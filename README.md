# MCP Vanguard

A lightweight tool runner that exposes a small registry of utilities both over HTTP
and via a Python command line interface. This repository contains the source code
for the command line entry point and helper utilities that back the MCP Vanguard
service.

## Command line interface

The CLI mirrors the JSON responses returned by the HTTP service. Any successful
invocation prints a JSON document with `status` set to `"success"` while errors
produce a JSON document with `status` set to `"error"` and a non-zero exit code.

Run the CLI with Python's module runner:

```bash
python -m mcp_vanguard run-tool <tool-name> [--key value ...]
```

Parameters are supplied as `--key value` pairs. Each value is decoded as JSON when
possible, allowing you to pass primitive types such as numbers, booleans, or
simple objects. Values that are not valid JSON are forwarded as strings.

### Examples

Execute the built-in `echo` tool:

```bash
python -m mcp_vanguard run-tool echo --message "Hello" --count 3
```

The CLI prints a JSON response identical to the HTTP API:

```json
{"status": "success", "tool": "echo", "result": {"received": {"message": "Hello", "count": 3}}}
```

Error responses are surfaced the same way:

```bash
python -m mcp_vanguard run-tool unknown-tool
```

```json
{"status": "error", "error": {"type": "ToolNotFound", "message": "Unknown tool: unknown-tool"}}
```

## Adding new tools

Tools are registered in `mcp_vanguard.registry`. Use the `@register_tool`
decorator to expose new functionality. Each tool receives keyword arguments based
on the CLI/HTTP payload and should return any JSON-serialisable object.

```python
from mcp_vanguard.registry import register_tool


@register_tool("reverse")
def reverse_tool(text: str) -> dict[str, str]:
    return {"text": text[::-1]}
```

Once registered, the tool becomes available to both the HTTP service and the CLI:

```bash
python -m mcp_vanguard run-tool reverse --text "Hello"
```
