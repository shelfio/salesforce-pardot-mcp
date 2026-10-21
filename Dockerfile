FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock uv.toml ./
RUN uv sync --locked --no-dev --no-cache
ENV PATH="/app/.venv/bin:$PATH"

COPY . .

# Security: run as non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser \
    && mkdir -p /app/data && chown -R appuser:appgroup /app/data
USER appuser

EXPOSE 8000

CMD ["python", "server.py"]
