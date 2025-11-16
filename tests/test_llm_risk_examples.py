import pytest

from mcp_scanner import llm_risk_examples as examples


def test_build_prompt_sanitizes_code_fences() -> None:
    prompt = examples.build_prompt("```danger```\nrm -rf /tmp")
    assert "```" not in prompt
    assert "> " in prompt
    assert "danger" in prompt
    assert "rm -rf" in prompt


def test_sanitize_user_input_bounds_length() -> None:
    sanitized = examples._sanitize_user_input("x" * (examples.MAX_USER_INPUT_LENGTH + 5))
    assert len(sanitized) == examples.MAX_USER_INPUT_LENGTH
    assert "x" * (examples.MAX_USER_INPUT_LENGTH - 1) in sanitized


def test_sanitize_user_input_strips_control_characters() -> None:
    sanitized = examples._sanitize_user_input("line\x00one\nline\ttwo")
    assert "\x00" not in sanitized
    assert "\t" not in sanitized
    assert "lineone" in sanitized
    assert "linetwo" in sanitized


def test_build_prompt_handles_empty_input() -> None:
    prompt = examples.build_prompt("  \n")
    assert "[no user input provided]" in prompt


def test_execute_tool_response_validates_allowlist() -> None:
    with pytest.raises(ValueError):
        examples.execute_tool_response("rm -rf", allowed_commands={"echo": ["echo"]})


def test_execute_tool_response_runs_runner() -> None:
    captured: dict[str, list[str]] = {}

    def fake_runner(cmd: list[str]) -> int:
        captured["args"] = cmd
        return 0

    result = examples.execute_tool_response(
        "echo hello",
        runner=fake_runner,
        allowed_commands={"echo": ["echo"]},
    )
    assert result == 0
    assert captured["args"] == ["echo", "hello"]


def test_execute_tool_response_rejects_missing_allowlist() -> None:
    with pytest.raises(ValueError):
        examples.execute_tool_response("echo hello")


def test_dispatch_with_os_system_enforces_allowlist() -> None:
    with pytest.raises(ValueError):
        examples.dispatch_with_os_system("python tool.py", allowed_binaries=["bash"])


def test_dispatch_with_os_system_runs_runner() -> None:
    captured: dict[str, list[str]] = {}

    def fake_runner(cmd: list[str]) -> int:
        captured["args"] = cmd
        return 0

    assert (
        examples.dispatch_with_os_system(
            "bash /tmp/script.sh",
            runner=fake_runner,
            allowed_binaries=["bash"],
        )
        == 0
    )
    assert captured["args"] == ["bash", "/tmp/script.sh"]


def test_dispatch_with_os_system_requires_allowlist_entries() -> None:
    with pytest.raises(ValueError):
        examples.dispatch_with_os_system("bash /tmp/script.sh", allowed_binaries=[])


class DummyResponse:
    text = "ok"

    def raise_for_status(self) -> None:
        return None


class DummySession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def post(self, url: str, **kwargs) -> DummyResponse:
        self.calls.append((url, kwargs))
        return DummyResponse()


def test_invoke_insecure_model_enforces_https() -> None:
    with pytest.raises(ValueError):
        examples.invoke_insecure_model("prompt", model_url="http://example.com/api")


def test_invoke_insecure_model_uses_session() -> None:
    session = DummySession()
    result = examples.invoke_insecure_model(
        "prompt", model_url="https://example.com/api", session=session
    )
    assert result == "ok"
    assert session.calls[0][0] == "https://example.com/api"
    assert session.calls[0][1]["verify"] is True
