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

## Loading configuration

Pydantic settings are used to centralize runtime configuration:

```python
from common.config import get_settings

settings = get_settings()
print(settings.llm.model)
```

The loader reads from `.env` by default and falls back to environment
variables.
