# MCP Scanner

This repository contains utilities for generating remediation suggestions for
vulnerabilities by combining metadata, graph context, and DSPy programs.

## Features

- **DSPy-driven remediation** – `PatchSuggestionProgram` defines a DSPy module
  that consumes vulnerability metadata, property graph context, and relevant
  code snippets to produce structured patch suggestions.
- **Persistence layer** – `RemediationSuggester` converts the DSPy output into
  typed `PatchProposal` objects and persists them as JSON documents under
  `reports/remediations/`.
- **Validation executor** – `PatchValidationExecutor` can run local validation
  commands (tests, linters) and annotate the stored remediation artifacts with
  the resulting logs.

## Running tests

```bash
pytest
```
