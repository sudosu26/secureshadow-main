# ── Stage 1: Build React frontend ──────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./frontend/
WORKDIR /app/frontend
RUN npm ci

# Copy frontend source and build (vite outputs to ../secureshadow/static)
COPY frontend/ ./
RUN mkdir -p /app/secureshadow/static
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# System dependencies for psycopg2 and health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python package
COPY pyproject.toml README.md ./
COPY secureshadow/ ./secureshadow/
RUN pip install --no-cache-dir -e . \
    && pip install --no-cache-dir alembic psycopg2-binary "psycopg[binary]" "uvicorn[standard]"

# Copy built frontend assets from stage 1
COPY --from=frontend-build /app/secureshadow/static ./secureshadow/static/

# Copy Alembic migration config
COPY alembic.ini ./
COPY alembic/ ./alembic/

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run migrations then start the server
CMD ["sh", "-c", "python -m alembic upgrade head && uvicorn secureshadow.api.app:app --host 0.0.0.0 --port 8000"]
