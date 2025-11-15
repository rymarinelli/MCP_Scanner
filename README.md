# MCP Scanner

Foundational scaffolding for the MCP Scanner project. The repository currently
contains shared configuration, logging helpers, and abstract interfaces for
graph, LLM, and scanning components.

## Prerequisites

- Python 3.10+
- `pip`

## Getting started

1. **Create a virtual environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\\Scripts\\activate
   ```

2. **Install the project in editable mode**

   ```bash
   pip install --upgrade pip
   pip install -e .[dev]
   ```

   The remediation workflow shells out to Git and Semgrep. Install them with
   your platform package manager if they are not already available:

   ```bash
   # macOS (Homebrew)
   brew install git semgrep

   # Debian/Ubuntu
   sudo apt-get update && sudo apt-get install -y git curl
   curl -sL https://semgrep.dev/install.sh | sudo bash
   ```

3. **Provide configuration (optional)**

   Copy `.env.example` to `.env` and adjust any values as needed.

   ```bash
   cp .env.example .env
   ```

   Environment variables are prefixed with `MCP_` and can be nested using
   double underscores. For example, `MCP_LLM__API_KEY` sets the LLM provider
   API key.

## Project layout

```text
src/
├── common/        # Shared helpers (config, logging, etc.)
├── graph/         # Graph provider abstractions
├── llm/           # LLM provider abstractions
└── scanners/      # Repository scanner interfaces
```

## Automated scan pipeline

The HTTP service drives a multi-stage remediation workflow designed to mirror
the process you described:

1. **Enumerate the repository architecture.** The `enumeration` package walks
   the target repository, builds a property graph, and materializes both a JSON
   context file and an interactive HTML visualization. These artifacts are
   emitted in the scan response under `enumeration.artifacts`.
2. **Correlate Semgrep findings with the graph RAG.** Semgrep runs with the
   bundled ruleset and its JSON results are enriched using
   `graph.enrichers.correlate_semgrep_findings`, which injects the surrounding
   node metadata, code snippets, and relationship information from the RAG.
3. **Generate DSPy remediation scripts.** The enriched findings feed the DSPy
   remediation driver. The driver writes a Markdown playbook summarizing the
   proposed patches and persists per-vulnerability JSON payloads containing the
   DSPy outputs. The scan response surfaces durable paths to these files under
   `remediation.artifacts` (for example, `dspy_summary.md` and the
   `dspy_cases/` directory).
4. **Apply fixes and create commits.** Patch proposals are grouped by
   vulnerability and applied one commit at a time. Each successful commit uses a
   descriptive message (`fix(<vulnerability_id>): ...`). If a GitHub token is
   configured the service pushes the remediation branch and opens a pull
   request that links to every commit.

Every stage leaves behind stabilized artifacts in the response payload so that
you can review the RAG graph, Semgrep JSON, DSPy script, and remediation branch
after the scan completes.

## Loading configuration

Pydantic settings are used to centralize runtime configuration:

```python
from common.config import get_settings

settings = get_settings()
print(settings.llm.model)
```

The loader reads from `.env` by default and falls back to environment
variables.

## Using the bundled Hugging Face coding model

The remediation pipeline can run entirely on CPU by enabling the local
Hugging Face integration. Set the following environment variables to make the
service load the `ise-uiuc/Magicoder-S-DS-6.7B` model (or another compatible
coding model) via the Transformers library:

```bash
export MCP_LLM__PROVIDER=huggingface
export MCP_LLM__MODEL=ise-uiuc/Magicoder-S-DS-6.7B
```

When these settings are active, the remediation suggester streams prompts to
the locally hosted model instead of relying on a remote API. You can substitute
`MCP_LLM__MODEL` for a smaller CPU-friendly model (for example,
`deepseek-ai/deepseek-coder-1.3b-instruct`) if memory is constrained. The first
run will download the model weights to the local Hugging Face cache.

## Running the HTTP service via Docker

The repository now includes a lightweight HTTP service that exposes the
scanner workflow. Build and run the container as shown below:

```bash
docker build -t mcp-scanner .
docker run --rm -p 8000:8000 mcp-scanner
```

Trigger a scan by sending a `POST` request to the `/scan` endpoint. Provide
the Git URL (and optional branch) in the request body. You can also toggle
pipeline behaviors—such as disabling remediation commits or pull requests—by
supplying the optional boolean switches shown below:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
        "repo_url": "https://github.com/example/repo.git",
        "branch": "main",
        "quick": false,
        "apply_commits": true,
        "push": true,
        "create_pr": true,
        "base_branch": "main",
        "pr_labels": ["automated", "security"]
      }' \
  http://localhost:8000/scan
```

The response contains the Semgrep findings and proposed remediation patches
generated by the MCP pipeline.

When remediation succeeds you will find a `pull_request` object in the JSON
response whose `status` is `success` and whose `url` links to the created PR.
If the field is absent or the status is `skipped`, check the accompanying
`reason`—for example, missing `GITHUB_TOKEN` credentials or the absence of
Semgrep findings will prevent a pull request from being opened.

## Running a GitHub remediation scan

The workflow that powers the MCP Scanner assumes Git and GitHub credentials are
available so it can commit fixes and open pull requests. Before triggering a
scan set the following environment variables:

```bash
export GIT_USER="Your Name"
export GIT_EMAIL="you@example.com"
export GITHUB_TOKEN="ghp_your_personal_access_token"
```

The GitHub token needs the ``repo`` scope so the scanner can push remediation
branches and create pull requests on your behalf.

Once configured, start the HTTP service (either directly or inside Docker):

```bash
python -m service.http_server  # binds to 0.0.0.0:8000 by default
```

Trigger a full remediation run against a GitHub repository by POSTing directly
to the `/scan` endpoint. As long as ``GITHUB_TOKEN`` is exported in the
environment where the service is running the scanner will pick it up
automatically—no need to embed the credential in the request payload:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
        "repo_url": "https://github.com/rymarinelli/vulnerable_flask_SQL",
        "branch": "main",
        "quick": false,
        "apply_commits": true,
        "push": true,
        "create_pr": true,
        "pr_labels": ["automated", "security"]
      }' \
  http://localhost:8000/scan
```

The response bundles enumeration artifacts, Semgrep findings, applied commits,
and (when enabled) the remediation pull request metadata. To dry run a scan
without committing or opening a PR, set ``"apply_commits": false`` (and
optionally ``"quick": true``) in the request payload.

## Exposing the service with mytunnel (localtunnel)

When you need to share your local MCP Scanner instance with remote clients,
use the bundled test deployment helper. The script launches the HTTP server,
ensures the [`mytunnel`](https://www.npmjs.com/package/localtunnel) CLI is
available, and prints the public URL emitted by the tunnel:

```bash
python -m mcp_scanner.scripts.deploy_test_tunnel --install-lt --subdomain busy-papers-melt
```

Key flags:

- `--install-lt` installs the `lt` CLI with `npm` if it is not already
  available. Omit it when running in environments where global installs are not
  desired.
- `--subdomain` requests a stable localtunnel subdomain.
- `--host` and `--port` control the embedded MCP server binding (default:
  `0.0.0.0:8000`).

The command keeps running until interrupted with `Ctrl+C`, shutting down both
the server and tunnel cleanly when you exit. Once the script prints the
`🌐 Public MCP URL`, you can invoke the `/scan` endpoint from any machine and
drive a full remediation (including Git commits, pushes, and pull requests) via
`curl`:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
        "repo_url": "https://github.com/rymarinelli/vulnerable_flask_SQL",
        "apply_commits": true,
        "push": true,
        "create_pr": true
      }' \
  https://busy-papers-melt.loca.lt/scan
```

As long as ``GITHUB_TOKEN`` is exported in the environment where the tunnel
script is running, the scanner authenticates to GitHub, pushes the remediation
branch, and opens a
pull request. Keep `GIT_USER` and `GIT_EMAIL` configured to control the commit
authorship information applied to generated fixes.
