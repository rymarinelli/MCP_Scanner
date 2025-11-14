FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl git-lfs \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY semgrep_runner.py /app/
COPY semgrep_rules /app/semgrep_rules

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip install --no-cache-dir semgrep

EXPOSE 8000

ENV MCP_SERVER_HOST=0.0.0.0 \
    MCP_SERVER_PORT=8000 \
    MCP_LLM__PROVIDER=huggingface \
    MCP_LLM__MODEL=ise-uiuc/Magicoder-S-DS-6.7B

CMD ["python", "-m", "service.http_server"]
