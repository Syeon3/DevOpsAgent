"""Shared pytest fixtures for the AgentHub backend test suite.

Two ideas make the ops tests hermetic (no Docker, no DB, no network):

1. ``configure_ops`` — replaces ``get_settings()`` inside the ops module with a
   hand-built settings object, so each test decides the allow-list, the Docker
   socket path and the configured health endpoints.
2. ``http_port`` / ``fake_docker_socket`` — real aiohttp servers, one on a
   loopback TCP port and one on a Unix socket, standing in for the services the
   tools probe. The tools speak real HTTP to them, so the tests exercise the
   actual code path.
"""

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web

# Make `import app.*` work when pytest is launched from backend/.
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.agents.tools import ops as ops_module  # noqa: E402


# ── Settings stub ───────────────────────────────────────────────────────────


def _fake_settings(
    *,
    roots=(),
    endpoints=None,
    allowed=(),
    socket="/nonexistent/docker.sock",
    max_chars=4000,
):
    """Build an object shaped like the parts of Settings the ops tools use."""
    return SimpleNamespace(
        OPS_MAX_OUTPUT_CHARS=max_chars,
        OPS_DOCKER_SOCKET=socket,
        ops_project_roots_list=[str(r) for r in roots],
        ops_health_endpoints_map=dict(endpoints or {}),
        ops_allowed_hosts_list=list(allowed),
    )


@pytest.fixture
def configure_ops(monkeypatch):
    """Return a ``configure_ops(**overrides)`` helper for the ops module.

    Defaults are the most restrictive ones: no allowed root, no allowed host,
    no configured endpoint, and a Docker socket that does not exist.
    """

    def _configure(**overrides):
        settings = _fake_settings(**overrides)
        monkeypatch.setattr(ops_module, "get_settings", lambda: settings)
        return settings

    _configure()
    return _configure


# ── Real HTTP server on loopback ────────────────────────────────────────────


@pytest_asyncio.fixture
async def http_port():
    """Start a tiny HTTP server on 127.0.0.1:<random port> and yield the port.

    Routes:
        /health  -> 200 {"status": "ok"}
        /error   -> 500
        /slow    -> sleeps 2s, then 200   (for timeout tests)
        /leaky   -> 200, body contains a fake secret (for redaction tests)
    """

    async def health(request):
        return web.json_response({"status": "ok", "service": "demo"})

    async def error(request):
        return web.json_response({"error": "boom"}, status=500)

    async def slow(request):
        await asyncio.sleep(2)
        return web.json_response({"status": "ok"})

    async def leaky(request):
        return web.json_response({"status": "ok", "api_key": "sk-do-not-leak-me"})

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_get("/error", error)
    app.router.add_get("/slow", slow)
    app.router.add_get("/leaky", leaky)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield port
    finally:
        await runner.cleanup()


# ── Fake Docker Engine API on a Unix socket ─────────────────────────────────

FAKE_DOCKER_VERSION = {
    "Version": "27.3.1",
    "ApiVersion": "1.47",
    "Os": "linux",
    "Arch": "amd64",
}

FAKE_CONTAINERS = [
    {
        "Id": "1111111111111111",
        "Names": ["/agenthub-backend"],
        "Image": "agenthub-backend",
        "State": "running",
        "Status": "Up 3 hours (healthy)",
        "Ports": [],
    },
    {
        "Id": "2222222222222222",
        "Names": ["/agenthub-db"],
        "Image": "pgvector/pgvector:0.8.2-pg18-trixie",
        "State": "running",
        "Status": "Up 3 hours (healthy)",
        "Ports": [],
    },
    {
        "Id": "3333333333333333",
        "Names": ["/legacy-worker"],
        "Image": "legacy-worker",
        "State": "exited",
        "Status": "Exited (1) 2 hours ago",
        "Ports": [],
    },
]


@pytest_asyncio.fixture
async def fake_docker_socket(tmp_path):
    """Serve a fake Docker Engine API (``/version``, ``/containers/json``)."""
    socket_path = tmp_path / "docker.sock"

    async def version(request):
        return web.json_response(FAKE_DOCKER_VERSION)

    async def containers(request):
        assert request.query.get("all") == "1"  # the tool must ask for stopped ones too
        return web.json_response(FAKE_CONTAINERS)

    app = web.Application()
    app.router.add_get("/version", version)
    app.router.add_get("/containers/json", containers)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.UnixSite(runner, str(socket_path))
    await site.start()
    try:
        yield str(socket_path)
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def empty_docker_socket(tmp_path):
    """A Docker socket whose daemon reports zero containers."""

    async def version(request):
        return web.json_response(FAKE_DOCKER_VERSION)

    async def containers(request):
        return web.json_response([])

    app = web.Application()
    app.router.add_get("/version", version)
    app.router.add_get("/containers/json", containers)

    runner = web.AppRunner(app)
    await runner.setup()
    socket_path = tmp_path / "empty-docker.sock"
    site = web.UnixSite(runner, str(socket_path))
    await site.start()
    try:
        yield str(socket_path)
    finally:
        await runner.cleanup()


# ── Helpers ─────────────────────────────────────────────────────────────────
# (project-directory helpers live in test_ops_tools.py next to their usage)
