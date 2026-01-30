# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

# Install tini for signal handling, plus curl for healthcheck debug
RUN apt-get update && apt-get install -y --no-install-recommends \
      tini curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user & working directory
ENV APP_DIR=/app \
    REPORTS_DIR=/reports \
    PYTHONUNBUFFERED=1
RUN useradd -m -u 10001 appuser && mkdir -p $APP_DIR $REPORTS_DIR && chown -R appuser:appuser $APP_DIR $REPORTS_DIR

WORKDIR $APP_DIR

# Install runtime deps: Docker SDK to control sibling containers
RUN pip install --no-cache-dir docker

# Copy the control API
COPY --chown=appuser:appuser dast-control.py $APP_DIR/dast-control.py

# Default envs (override at run-time)
ENV API_PORT=8080 \
    NUCLEI_TEMPLATES=/root/nuclei-templates \
    NUCLEI_UPDATE_ON_START=true

# Healthcheck hits /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${API_PORT}/healthz || exit 1

# Run as non-root
USER appuser

EXPOSE 8080

# Use tini as entrypoint for clean signals; run the API
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python", "/app/dast-control.py"]

