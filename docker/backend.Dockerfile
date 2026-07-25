# syntax=docker/dockerfile:1
# Build context is the repo root (see docker-compose.yml) so this image can
# preserve the same backend/ + sigma_rules/ + yara_rules/ + datasets/ layout
# that app/config.py expects to find relative to itself in local dev.
FROM python:3.12-slim

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip pip install -r backend/requirements.txt

COPY backend/ backend/
COPY sigma_rules/ sigma_rules/
COPY yara_rules/ yara_rules/
COPY datasets/ datasets/

WORKDIR /app/backend
RUN mkdir -p data

EXPOSE 8000

# ${PORT:-8000} so this still works unchanged under docker-compose (no PORT
# set, falls back to 8000) while respecting Render/Railway/etc., which assign
# a dynamic PORT env var the container must bind to.
CMD ["sh", "-c", "python -m app.seed --with-data && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
