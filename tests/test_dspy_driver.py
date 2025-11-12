import json
from pathlib import Path
import sys

SRC_PATH = Path(__file__).resolve().parents[1] / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from remediation.dspy_driver import DSPyRemediationDriver
from mcp_scanner.dspy_programs import DSPyResponse
from mcp_scanner.models import VulnerabilityContext
from mcp_scanner.remediation import RemediationSuggester


class DummyProgram:
    def forward(self, context: VulnerabilityContext) -> DSPyResponse:
        return DSPyResponse(
            patches=[
                {
                    "file_path": "src/app.py",
                    "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@\n-raise Exception()\n+raise ValueError('invalid input')",
                    "rationale": "Ensure we do not leak stack traces to users.",
                    "confidence": 0.4,
                }
            ],
            raw_output=json.dumps(
                {
                    "patches": [
                        {
                            "file_path": "src/app.py",
                            "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@\n-raise Exception()\n+raise ValueError('invalid input')",
                            "rationale": "Ensure we do not leak stack traces to users.",
                            "confidence": 0.4,
                        }
                    ]
                }
            ),
        )


def make_semgrep_payload() -> dict:
    return {
        "results": [
            {
                "check_id": "python.flask.security.dangerous-debug",
                "path": "src/app.py",
                "start": {"line": 10, "col": 5},
                "end": {"line": 12, "col": 1},
                "extra": {
                    "message": "Debug mode exposes stack traces to end users.",
                    "severity": "HIGH",
                    "metadata": {"cwe": "CWE-489"},
                    "lines": "app.run(debug=True)",
                },
            }
        ]
    }


def make_rag_payload() -> dict:
    return {
        "graph": {
            "node-1": {
                "file_path": "src/app.py",
                "function": "create_app",
            }
        },
        "node_context": {
            "node-1": {
                "summary": "Application factory enabling debug mode.",
                "code_snippets": ["def create_app():\n    app.run(debug=True)"],
            }
        },
    }


def test_driver_generates_markdown_with_manual_review(tmp_path: Path) -> None:
    semgrep_path = tmp_path / "semgrep.json"
    rag_path = tmp_path / "rag.json"
    output_path = tmp_path / "out.md"
    json.dump(make_semgrep_payload(), semgrep_path.open("w"))
    json.dump(make_rag_payload(), rag_path.open("w"))

    suggester = RemediationSuggester(program=DummyProgram(), output_dir=tmp_path / "artifacts")
    driver = DSPyRemediationDriver(
        suggester=suggester,
        manual_review_threshold=0.9,
        output_markdown=output_path,
    )

    proposals = driver.run(semgrep_path=semgrep_path, rag_context_path=rag_path)

    assert len(proposals) == 1
    content = output_path.read_text()
    assert "python.flask.security.dangerous-debug" in content
    assert "node-1" in content
    assert "Manual Review Required: Yes" in content
    assert "```diff" in content


def test_driver_handles_no_findings(tmp_path: Path) -> None:
    semgrep_path = tmp_path / "semgrep.json"
    rag_path = tmp_path / "rag.json"
    output_path = tmp_path / "out.md"
    json.dump({"results": []}, semgrep_path.open("w"))
    json.dump(make_rag_payload(), rag_path.open("w"))

    driver = DSPyRemediationDriver(
        suggester=RemediationSuggester(program=DummyProgram(), output_dir=tmp_path / "artifacts"),
        output_markdown=output_path,
    )

    proposals = driver.run(semgrep_path=semgrep_path, rag_context_path=rag_path)

    assert proposals == []
    content = output_path.read_text()
    assert "No remediation suggestions were generated." in content
