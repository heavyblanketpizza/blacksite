"""Verify the OpenAI-compatible tool-calling API required by Holmes.

Run with ``poetry run python scripts/check_vllm.py --help``.
Only the fixed local probe below is executed; model output never executes code.
"""

import argparse
import json
import os
import secrets
import sys
from typing import Any, Iterator, Optional

import requests


PROBE_ID = "holmes-vllm-smoke"
PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "get_backend_probe",
        "description": "Get the verification code for a backend connectivity probe.",
        "parameters": {
            "type": "object",
            "properties": {"probe_id": {"type": "string"}},
            "required": ["probe_id"],
            "additionalProperties": False,
        },
    },
}


class ProbeError(Exception):
    """A backend failed a required part of the tool-calling contract."""


def _request(
    session: requests.Session, method: str, url: str, timeout: float, **kwargs: Any
) -> requests.Response:
    try:
        response = session.request(method, url, timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        raise ProbeError(
            "Cannot reach the backend. Check --base-url, server readiness, and --timeout."
        ) from exc
    if not response.ok:
        status = response.status_code
        response.close()
        if status in (401, 403):
            hint = "Check VLLM_API_KEY matches the server's API key."
        elif status == 404:
            hint = "Check --base-url includes /v1 and the model is served."
        else:
            hint = "Check server logs, the model's chat template, and tool-call parser."
        raise ProbeError(f"Backend returned HTTP {status}. {hint}")
    return response


def _json_object(value: Any, description: str) -> dict[str, Any]:
    try:
        result = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ProbeError(f"Invalid JSON in {description}.") from exc
    if not isinstance(result, dict):
        raise ProbeError(f"Expected a JSON object in {description}.")
    if result.get("error") is not None:
        raise ProbeError(
            f"Backend reported an API error in {description}; check server logs."
        )
    return result


def _sse_data(response: requests.Response) -> Iterator[str]:
    """Read SSE data fields, including multiline events and keepalive comments."""
    response.encoding = "utf-8"
    data = []
    for line in response.iter_lines(decode_unicode=True):
        if not line:
            if data:
                yield "\n".join(data)
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    if data:
        yield "\n".join(data)


def _choice(payload: dict[str, Any]) -> dict[str, Any]:
    choices = payload.get("choices")
    if (
        not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
    ):
        raise ProbeError("Expected exactly one completion choice from the backend.")
    return choices[0]


def _append_text(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        if not isinstance(value, str):
            raise ProbeError(f"Invalid streamed {key}; expected text.")
        target[key] += value


def _read_stream(response: requests.Response) -> tuple[dict[str, Any], str]:
    message: dict[str, Any] = {"role": "assistant", "content": ""}
    calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    done = False
    for data in _sse_data(response):
        if data == "[DONE]":
            done = True
            break
        payload = _json_object(data, "streaming response")
        # vLLM may emit usage after the finish-reason chunk and before [DONE].
        if payload.get("choices") == [] and "usage" in payload:
            continue
        choice = _choice(payload)
        if finish_reason is not None:
            raise ProbeError("Received completion data after the stream finished.")
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            raise ProbeError("Missing delta object in streaming response.")
        _append_text(message, "content", delta.get("content"))
        tool_deltas = delta.get("tool_calls") or []
        if not isinstance(tool_deltas, list):
            raise ProbeError("Invalid streamed tool_calls; expected a list.")
        for tool_delta in tool_deltas:
            if (
                not isinstance(tool_delta, dict)
                or type(tool_delta.get("index")) is not int
            ):
                raise ProbeError("Streamed tool call is missing its integer index.")
            index = tool_delta["index"]
            if index < 0:
                raise ProbeError("Streamed tool call has an invalid index.")
            call = calls.setdefault(
                index,
                {"id": "", "type": "", "function": {"name": "", "arguments": ""}},
            )
            _append_text(call, "id", tool_delta.get("id"))
            if tool_delta.get("type") is not None:
                call["type"] = tool_delta["type"]
            function = tool_delta.get("function") or {}
            if not isinstance(function, dict):
                raise ProbeError("Invalid function object in streamed tool call.")
            for field in ("name", "arguments"):
                _append_text(call["function"], field, function.get(field))
        finish_reason = choice.get("finish_reason")
    if not done or finish_reason is None:
        raise ProbeError(
            "Incomplete stream: missing [DONE] or finish_reason; "
            "check server/proxy timeouts."
        )
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return message, finish_reason


def _completion(
    session: requests.Session,
    base_url: str,
    model: str,
    messages: list[dict[str, Any]],
    stream: bool,
    timeout: float,
) -> dict[str, Any]:
    payload = {
        "model": model,
        "messages": messages,
        "tools": [PROBE_TOOL],
        "tool_choice": "auto",
        "max_tokens": 2048,
        "stream": stream,
    }
    try:
        with _request(
            session,
            "POST",
            f"{base_url}/chat/completions",
            timeout,
            json=payload,
            stream=stream,
        ) as response:
            if stream:
                message, finish_reason = _read_stream(response)
            else:
                choice = _choice(_json_object(response.text, "completion response"))
                message = choice.get("message")
                finish_reason = choice.get("finish_reason")
    except requests.RequestException as exc:
        raise ProbeError(
            "Response interrupted; check server/proxy timeouts and --timeout."
        ) from exc
    if finish_reason not in ("stop", "tool_calls"):
        raise ProbeError(
            f"Completion did not finish normally ({finish_reason!r}); "
            "check output limits and server logs."
        )
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ProbeError("Completion is missing an assistant message.")
    if finish_reason == "tool_calls" and not message.get("tool_calls"):
        raise ProbeError("Completion finished with tool_calls but omitted the calls.")
    return message


def _round_trip(
    session: requests.Session, base_url: str, model: str, stream: bool, timeout: float
) -> None:
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"Call get_backend_probe with probe_id '{PROBE_ID}' exactly once. "
                "Then return the verification_code from its result verbatim. "
                "The code is only available from the tool; do not invent one."
            ),
        }
    ]
    assistant = _completion(session, base_url, model, messages, stream, timeout)
    calls = assistant.get("tool_calls")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
        raise ProbeError(
            "Expected one automatic tool call. Enable --enable-auto-tool-choice "
            "and the model's tool-call parser."
        )
    call = calls[0]
    function = call.get("function")
    if (
        call.get("type") != "function"
        or not isinstance(call.get("id"), str)
        or not call["id"].strip()
        or not isinstance(function, dict)
        or function.get("name") != "get_backend_probe"
    ):
        raise ProbeError(
            "Invalid get_backend_probe tool call or missing call ID; "
            "check the chat template/parser."
        )
    arguments = _json_object(function.get("arguments"), "tool arguments")
    if arguments != {"probe_id": PROBE_ID}:
        raise ProbeError(
            "Tool arguments did not match the requested probe_id; "
            "check the model and parser."
        )

    # Created only after the first model response, so a successful final answer
    # demonstrates the model actually consumed the tool result.
    code = secrets.token_hex(16)
    messages.extend(
        [
            assistant,
            {
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps({"probe_id": PROBE_ID, "verification_code": code}),
            },
        ]
    )
    final = _completion(session, base_url, model, messages, stream, timeout)
    if final.get("tool_calls"):
        raise ProbeError("Model called tools again instead of returning the probe result.")
    content = final.get("content")
    if not isinstance(content, str) or code not in content:
        raise ProbeError(
            "Final answer did not include the tool's verification code; "
            "check tool-result handling."
        )


def check_backend(base_url: str, model: str, api_key: str, timeout: float = 120) -> None:
    base_url = base_url.rstrip("/")
    with requests.Session() as session:
        session.headers.update({"Authorization": f"Bearer {api_key}"})
        with _request(session, "GET", f"{base_url}/models", timeout) as response:
            models = _json_object(response.text, "model list").get("data")
        if not isinstance(models, list) or not any(
            isinstance(entry, dict) and entry.get("id") == model for entry in models
        ):
            raise ProbeError(
                f"Model {model!r} is not served. Match --model to --served-model-name."
            )
        for stream in (False, True):
            try:
                _round_trip(session, base_url, model, stream, timeout)
            except ProbeError as exc:
                mode = "Streaming" if stream else "Nonstreaming"
                raise ProbeError(f"{mode} tool check failed: {exc}") from exc


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("VLLM_API_BASE") or "http://localhost:8000/v1",
        help="OpenAI-compatible API URL (default: VLLM_API_BASE or http://localhost:8000/v1)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("VLLM_SERVED_MODEL") or "holmes-local",
        help="Served model alias (default: VLLM_SERVED_MODEL or holmes-local)",
    )
    parser.add_argument(
        "--timeout", type=float, default=120,
        help="HTTP timeout in seconds (default: 120)",
    )
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        check_backend(
            args.base_url,
            args.model,
            os.environ.get("VLLM_API_KEY") or "local-vllm",
            args.timeout,
        )
    except ProbeError as exc:
        print(f"vLLM check failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"vLLM check passed for {args.model}: automatic tool calls and tool results "
        "verified in nonstreaming and streaming modes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
