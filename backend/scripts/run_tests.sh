#!/bin/bash
# Run the backend test suite.
#
# Usage (from the repository root):
#   docker exec -w /app agenthub-backend bash scripts/run_tests.sh
#   docker exec -w /app agenthub-backend bash scripts/run_tests.sh -k project -v
#
# pytest / pytest-asyncio are development dependencies and are NOT part of the
# production image (see requirements-dev.txt). This script installs them on
# demand into the running container; rebuilding the backend container removes
# them again — just re-run the script, it reinstalls.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! python -c "import pytest" 2>/dev/null; then
    echo "==> Installing test dependencies (pytest, pytest-asyncio)"
    for mirror in \
        https://pypi.tuna.tsinghua.edu.cn/simple \
        https://mirrors.aliyun.com/pypi/simple \
        https://pypi.org/simple; do
        echo "--> $mirror"
        pip install -q -i "$mirror" -r requirements-dev.txt && break
    done
fi

exec python -m pytest "$@"
