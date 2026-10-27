FROM mirror.gcr.io/library/python:3.12-slim AS build
RUN pip install --no-cache-dir uv
WORKDIR /app
RUN python -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies with uv for fast Dockpack / Manufact Cloud builds
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/uv uv pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

FROM mirror.gcr.io/library/python:3.12-slim AS runtime
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOST="0.0.0.0"
ENV PORT="8000"

RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -m -d /app -s /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=build --chown=appuser:appgroup /app /app

EXPOSE 8000

USER appuser

CMD ["python", "server.py"]
