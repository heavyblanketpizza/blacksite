import json

import pytest
import requests
import responses as responses_module

from scripts import check_vllm


BASE = "http://vllm.test:8000/v1"
MODEL = "holmes-local"


def _tool_message(arguments=None):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": "call_probe",
            "type": "function",
            "function": {
                "name": "get_backend_probe",
                "arguments": arguments if arguments is not None else json.dumps({"probe_id": check_vllm.PROBE_ID}),
            },
        }],
    }


def _response(message, reason="stop"):
    return {"choices": [{"index": 0, "message": message, "finish_reason": reason}]}


def _chunk(delta, reason=None):
    return {"choices": [{"index": 0, "delta": delta, "finish_reason": reason}]}


def _sse(chunks, done=True):
    body = ": keepalive\n\n" + "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
    return body + ("data: [DONE]\n\n" if done else "")


def _streamed_call():
    return _sse([
        _chunk({"role": "assistant"}),
        _chunk({"tool_calls": [{
            "index": 0, "id": "call_", "type": "function",
            "function": {"name": "get_backend_", "arguments": '{"probe_'},
        }]}),
        _chunk({"tool_calls": [{
            "index": 0, "id": "probe",
            "function": {"name": "probe", "arguments": 'id": "holmes-'},
        }]}),
        _chunk({"tool_calls": [{
            "index": 0, "function": {"arguments": 'vllm-smoke"}'},
        }]}),
        _chunk({}, "tool_calls"),
        {"choices": [], "usage": {"total_tokens": 32}},
    ])


def _successful_completion(request):
    payload = json.loads(request.body)
    messages = payload["messages"]
    if messages[-1]["role"] != "tool":
        body = _streamed_call() if payload["stream"] else json.dumps(_response(_tool_message(), "tool_calls"))
    else:
        tool = messages[-1]
        code = json.loads(tool["content"])["verification_code"]
        assert code not in json.dumps(messages[:-1])
        assert tool["tool_call_id"] == "call_probe"
        assert messages[-2]["tool_calls"] == _tool_message()["tool_calls"]
        body = (
            _sse([_chunk({"content": code[:16]}), _chunk({"content": code[16:]}, "stop"), {"choices": [], "usage": {}}])
            if payload["stream"]
            else json.dumps(_response({"role": "assistant", "content": code}))
        )
    content_type = "text/event-stream" if payload["stream"] else "application/json"
    return 200, {"Content-Type": content_type}, body


@pytest.fixture
def backend():
    with responses_module.RequestsMock() as mocked:
        mocked.get(f"{BASE}/models", json={"data": [{"id": MODEL}]})
        yield mocked


def test_full_check_verifies_nonstreaming_and_fragmented_streaming_round_trips(backend):
    backend.add_callback("POST", f"{BASE}/chat/completions", callback=_successful_completion)

    check_vllm.check_backend(f"{BASE}/", MODEL, "test-secret", timeout=5)

    assert len(backend.calls) == 5
    completions = [json.loads(call.request.body) for call in backend.calls[1:]]
    assert [payload["stream"] for payload in completions] == [False, False, True, True]
    for call in backend.calls:
        assert call.request.headers["Authorization"] == "Bearer test-secret"
    for payload in completions:
        assert payload["model"] == MODEL
        assert payload["tool_choice"] == "auto"
        assert payload["tools"] == [check_vllm.PROBE_TOOL]
        assert payload["max_tokens"] == 2048


def test_unknown_model_fails_before_completion(backend):
    with pytest.raises(check_vllm.ProbeError, match="--served-model-name"):
        check_vllm.check_backend(BASE, "missing-alias", "key")
    assert len(backend.calls) == 1


@pytest.mark.parametrize("arguments, error", [
    ("{broken", "Invalid JSON"),
    ("[]", "JSON object"),
    ('{"probe_id": "wrong-probe"}', "requested probe_id"),
    ('{"probe_id": "holmes-vllm-smoke", "command": "echo unsafe"}', "requested probe_id"),
])
def test_invalid_arguments_are_not_executed(backend, arguments, error):
    backend.post(f"{BASE}/chat/completions", json=_response(_tool_message(arguments), "tool_calls"))
    with pytest.raises(check_vllm.ProbeError, match=error):
        check_vllm.check_backend(BASE, MODEL, "key")
    assert len(backend.calls) == 2


@pytest.mark.parametrize("change, error", [
    ("missing", "Expected one automatic tool call"),
    ("name", "Invalid get_backend_probe"),
    ("id", "missing call ID"),
    ("type", "Invalid get_backend_probe"),
])
def test_missing_or_invalid_tool_calls_fail(backend, change, error):
    message = _tool_message()
    if change == "missing":
        message.pop("tool_calls")
        message["content"] = "The backend is healthy."
    elif change == "name":
        message["tool_calls"][0]["function"]["name"] = "run_shell"
    else:
        message["tool_calls"][0].pop(change)
    backend.post(f"{BASE}/chat/completions", json=_response(message))
    with pytest.raises(check_vllm.ProbeError, match=error):
        check_vllm.check_backend(BASE, MODEL, "key")


@pytest.mark.parametrize("message, error", [
    ({"role": "assistant", "content": "invented-code"}, "verification code"),
    (_tool_message(), "called tools again"),
])
def test_final_answer_must_consume_the_tool_result(backend, message, error):
    backend.post(f"{BASE}/chat/completions", json=_response(_tool_message(), "tool_calls"))
    backend.post(f"{BASE}/chat/completions", json=_response(message))
    with pytest.raises(check_vllm.ProbeError, match=error):
        check_vllm.check_backend(BASE, MODEL, "key")


@pytest.mark.parametrize("stream", [False, True])
def test_output_truncation_is_rejected(stream):
    body = _sse([_chunk({"content": "partial"}, "length")]) if stream else json.dumps(_response(_tool_message(), "length"))
    # Exercise the completion reader directly so both protocol paths receive
    # the failure instead of stopping after the first nonstreaming check.
    with responses_module.RequestsMock() as mocked:
        mocked.post(f"{BASE}/chat/completions", body=body)
        with requests.Session() as session, pytest.raises(check_vllm.ProbeError, match="length"):
            check_vllm._completion(session, BASE, MODEL, [], stream, 5)


@pytest.mark.parametrize("body, error", [
    (_sse([_chunk({"content": "partial"}, "stop")], done=False), "Incomplete stream"),
    (_sse([_chunk({"content": "partial"})]), "Incomplete stream"),
    (_sse([{"error": {"message": "engine failed"}}]), "API error"),
    ("data: {bad json}\n\ndata: [DONE]\n\n", "Invalid JSON"),
    (_sse([_chunk({"tool_calls": [{"function": {"arguments": "{}"}}]})]), "integer index"),
])
def test_stream_failures_are_actionable(body, error):
    with responses_module.RequestsMock() as mocked:
        mocked.post(f"{BASE}/chat/completions", body=body, content_type="text/event-stream")
        with requests.Session() as session, pytest.raises(check_vllm.ProbeError, match=error):
            check_vllm._completion(session, BASE, MODEL, [], True, 5)


def test_dropped_stream_is_reported_without_traceback():
    body = _sse([_chunk({"content": "partial"})], done=False)
    with responses_module.RequestsMock() as mocked:
        # The advertised response is longer than the data received. urllib3
        # raises IncompleteRead, which requests wraps as ChunkedEncodingError.
        mocked.post(
            f"{BASE}/chat/completions",
            body=body,
            headers={"Content-Length": str(len(body) + 100)},
            content_type="text/event-stream",
        )
        with requests.Session() as session, pytest.raises(check_vllm.ProbeError, match="Response interrupted"):
            check_vllm._completion(session, BASE, MODEL, [], True, 5)


@pytest.mark.parametrize("status, error", [(401, "VLLM_API_KEY"), (403, "VLLM_API_KEY"), (404, "/v1"), (500, "server logs")])
def test_http_failures_are_actionable(status, error):
    with responses_module.RequestsMock() as mocked:
        mocked.get(f"{BASE}/models", status=status)
        with pytest.raises(check_vllm.ProbeError, match=error):
            check_vllm.check_backend(BASE, MODEL, "key")


def test_network_timeout_is_actionable():
    with responses_module.RequestsMock() as mocked:
        mocked.get(f"{BASE}/models", body=requests.exceptions.Timeout())
        with pytest.raises(check_vllm.ProbeError, match="Cannot reach the backend"):
            check_vllm.check_backend(BASE, MODEL, "key", timeout=1)


def test_cli_uses_env_and_prints_success(backend, monkeypatch, capsys):
    monkeypatch.setenv("VLLM_API_BASE", BASE)
    monkeypatch.setenv("VLLM_SERVED_MODEL", MODEL)
    monkeypatch.setenv("VLLM_API_KEY", "env-key")
    monkeypatch.setenv("VLLM_MODEL", "weights-name-is-not-the-served-alias")
    backend.add_callback("POST", f"{BASE}/chat/completions", callback=_successful_completion)
    assert check_vllm.main([]) == 0
    assert "vLLM check passed" in capsys.readouterr().out
    assert backend.calls[0].request.headers["Authorization"] == "Bearer env-key"


def test_cli_failure_returns_nonzero_without_printing_secret(monkeypatch, capsys):
    monkeypatch.setenv("VLLM_API_KEY", "never-print-this-key")
    with responses_module.RequestsMock() as mocked:
        mocked.get(f"{BASE}/models", status=401)
        assert check_vllm.main(["--base-url", BASE]) == 1
    output = capsys.readouterr().err
    assert "VLLM_API_KEY" in output
    assert "never-print-this-key" not in output


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        check_vllm.main(["--help"])
    assert exc.value.code == 0
    assert "--base-url" in capsys.readouterr().out
