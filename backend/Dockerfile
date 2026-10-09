# Backend Dockerfile for AgentHub
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install curl for healthcheck and debugging
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with retry and timeout settings
# Note: asyncpg and psycopg-binary are pure Python / pre-compiled, no system deps needed
#
# Mirror fallback loop: try Tsinghua -> Aliyun -> official PyPI. Each attempt uses a
# single mirror, so a congested/failing mirror cannot stall the build forever —
# pip moves on to the next one. Timeout/retries are deliberately lower than before
# (120s x 5 could hang ~10min per package on a stalled mirror).
RUN for mirror in \
        https://pypi.tuna.tsinghua.edu.cn/simple \
        https://mirrors.aliyun.com/pypi/simple \
        https://pypi.org/simple; do \
        echo "==> pip install from $mirror"; \
        pip install --no-cache-dir --retries 3 --timeout 30 -i "$mirror" -r requirements.txt && break; \
    done

# Copy application code
COPY . .

# Make entrypoint executable.
# Also strip CR chars: Windows git (core.autocrlf=true) checks out CRLF line endings,
# which breaks the shebang ("exec ./entrypoint.sh: no such file or directory").
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

# Expose port
EXPOSE 8080

# Run the application via entrypoint script
# Database initialization is handled separately — run:
#   python scripts/init_database.py
# against a running PostgreSQL instance before starting the app.
ENTRYPOINT ["./entrypoint.sh"]
