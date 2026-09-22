"""Exercise the shipped vLLM configuration through Holmes and LiteLLM's HTTP adapter."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import httpx
import litellm
import pytest
import respx

from holmes.config import Config
from holmes.core.llm import DefaultLLM, LLMModelRegistry


MODEL_LIST = Path(__file__).parents[2] / "examples/vllm/model_list.yaml"
BASE_URL = "http://vllm.test:8000/v1"
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_pod_status",
            "description": "Get the status of a Kubernetes pod.",
            "parameters": {
                "type": "object",
                "properties": {"pod": {"type": "string"}},
                "required": ["pod"],
            },
        },
    }
]


@pytest.fixture
def vllm_backend(monkeypatch: pytest.MonkeyPatch) -> DefaultLLM:
    monkeypatch.setenv("VLLM_API_BASE", BASE_URL)
    monkeypatch.setenv("VLLM_API_KEY", "test-vllm-key")
    parser = LLMModelRegistry.__new__(LLMModelRegistry)
    entry = parser._parse_models_file(str(MODEL_LIST))["vllm"]
    registry = Mock(spec=LLMModelRegistry)
    registry.get_model_params.return_value = entry
    config = Config(model="vllm")
    config._llm_model_registry = registry
    return config._get_llm("vllm")


def completion_response(
    message: dict[str, Any], finish_reason: str, stream: bool
) -> httpx.Response:
    common = {"id": "chatcmpl-vllm-test", "created": 1, "model": "holmes-local"}
    if stream:
        delta = dict(message)
        if "tool_calls" in delta:
            delta["tool_calls"] = [
                {"index": index, **call}
                for index, call in enumerate(delta["tool_calls"])
            ]
        chunks = [
            {"index": 0, "delta": delta, "finish_reason": None},
            {"index": 0, "delta": {}, "finish_reason": finish_reason},
        ]
        body = "".join(
            "data: "
            + json.dumps(
                {**common, "object": "chat.completion.chunk", "choices": [chunk]}
            )
            + "\n\n"
            for chunk in chunks
        )
        return httpx.Response(
            200,
            text=body + "data: [DONE]\n\n",
            headers={"Content-Type": "text/event-stream"},
        )
    return httpx.Response(
        200,
        json={
            **common,
            "object": "chat.completion",
            "choices": [
                {"index": 0, "message": message, "finish_reason": finish_reason}
            ],
            "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40},
        },
    )


@pytest.mark.parametrize("stream", [False, True])
def test_vllm_configuration_and_tool_round_trip(
    vllm_backend: DefaultLLM, stream: bool
) -> None:
    assert vllm_backend.get_context_window_size() == 32768
    assert vllm_backend.get_maximum_output_token() == 4096
    tool_message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_pod_status",
                "type": "function",
                "function": {
                    "name": "get_pod_status",
                    "arguments": '{"pod":"checkout"}',
                },
            }
        ],
    }
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": "Check the checkout pod", "token_count": 5}
    ]

    with respx.mock as transport:
        route = transport.post(f"{BASE_URL}/chat/completions").mock(
            side_effect=[
                completion_response(tool_message, "tool_calls", stream),
                completion_response(
                    {"role": "assistant", "content": "The checkout pod is Running."},
                    "stop",
                    stream,
                ),
            ]
        )
        first = vllm_backend.completion(
            messages=messages, tools=TOOLS, tool_choice="auto", stream=stream
        )
        if stream:
            first = litellm.stream_chunk_builder(list(first))
        call = first.choices[0].message.tool_calls[0]
        assert call.id == "call_pod_status"
        assert call.function.name == "get_pod_status"
        assert json.loads(call.function.arguments) == {"pod": "checkout"}

        messages.extend(
            [
                tool_message,
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": '{"status":"Running"}',
                },
            ]
        )
        final = vllm_backend.completion(
            messages=messages, tools=TOOLS, tool_choice="auto", stream=stream
        )
        if stream:
            final = litellm.stream_chunk_builder(list(final))
        assert final.choices[0].message.content == "The checkout pod is Running."
        assert final.choices[0].finish_reason == "stop"
        assert route.call_count == 2
        for request, _ in route.calls:
            payload = json.loads(request.content)
            assert request.headers["authorization"] == "Bearer test-vllm-key"
            assert payload["model"] == "holmes-local"
            assert payload["max_tokens"] == 4096
            assert payload["tool_choice"] == "auto"
            assert payload["tools"] == TOOLS
            assert payload.get("stream", False) is stream
            assert "custom_args" not in payload
            assert "token_count" not in payload["messages"][0]
        last_payload = json.loads(route.calls.last.request.content)
        assert last_payload["messages"][-1]["tool_call_id"] == "call_pod_status"
