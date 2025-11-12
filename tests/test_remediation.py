import json

from mcp_scanner.dspy_programs import DSPyResponse
from mcp_scanner.models import ValidationResult, VulnerabilityContext
from mcp_scanner.remediation import RemediationSuggester


class DummyProgram:
    def forward(self, context: VulnerabilityContext) -> DSPyResponse:
        return DSPyResponse(
            patches=[
                {
                    "file_path": "src/app.py",
                    "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@\n-print('hello')\n+print('hello world')",
                    "rationale": "Ensure greeting is descriptive",
                    "confidence": 0.9,
                }
            ],
            raw_output=json.dumps({
                "patches": [
                    {
                        "file_path": "src/app.py",
                        "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@\n-print('hello')\n+print('hello world')",
                        "rationale": "Ensure greeting is descriptive",
                        "confidence": 0.9,
                    }
                ]
            }),
        )


def make_context() -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="VULN-1234",
        metadata={"cwe": "CWE-79", "severity": "high"},
        graph_context={"callers": ["render_homepage"], "sinks": ["response.write"]},
        code_snippets=["print('hello')"],
    )


def test_suggest_persists_proposals(tmp_path):
    suggester = RemediationSuggester(program=DummyProgram(), output_dir=tmp_path)
    proposals = suggester.suggest([make_context()])

    assert len(proposals) == 1

    output_file = tmp_path / "VULN-1234.json"
    assert output_file.exists()

    payload = json.loads(output_file.read_text())
    assert payload["vulnerability_id"] == "VULN-1234"
    assert payload["proposals"][0]["file_path"] == "src/app.py"


def test_attach_validation_results_updates_disk(tmp_path):
    suggester = RemediationSuggester(program=DummyProgram(), output_dir=tmp_path)
    proposals = suggester.suggest([make_context()])
    proposal = proposals[0]

    validation = ValidationResult(
        command="pytest",
        succeeded=True,
        stdout="All tests passed",
        stderr="",
    )

    suggester.attach_validation_results(proposal=proposal, results=[validation])

    payload = json.loads((tmp_path / "VULN-1234.json").read_text())
    assert payload["proposals"][0]["validator_results"][0]["command"] == "pytest"
