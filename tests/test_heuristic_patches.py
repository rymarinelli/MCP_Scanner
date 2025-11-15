from pathlib import Path

from mcp_scanner.dspy_programs import PatchSuggestionProgram
from mcp_scanner.models import VulnerabilityContext
from remediation.heuristic_patches import HeuristicPatchGenerator


def make_context() -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="python.flask.security.audit.debug-enabled::app",
        metadata={
            "rule_id": "python.flask.security.audit.debug-enabled",
            "path": "app.py",
            "severity": "WARNING",
        },
        graph_context={},
        code_snippets=["app.run(debug=True)"],
    )


def test_generator_disables_flask_debug(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        """
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)
""".strip()
    )

    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    patches = generator.generate(make_context())

    assert len(patches) == 1
    patch = patches[0]
    assert patch["file_path"] == "app.py"
    assert "-    app.run(debug=True)" in patch["diff"]
    assert "+    app.run(debug=False)" in patch["diff"]


def test_patch_program_uses_heuristics(tmp_path: Path) -> None:
    context = make_context()
    (tmp_path / "app.py").write_text(
        "if __name__ == '__main__':\n    app.run(debug=True)\n",
        encoding="utf-8",
    )

    program = PatchSuggestionProgram(repo_root=tmp_path)
    response = program.forward(context)

    assert response.patches
    assert response.patches[0]["file_path"] == "app.py"
