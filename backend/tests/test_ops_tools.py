"""Tests for the ops health-check tools (app/agents/tools/ops.py).

Coverage map (what the brief asked for → test):

    normal checks            test_check_project_healthy_python, test_check_docker_ok,
                             test_check_service_*_healthy
    missing directory        test_check_project_directory_not_found
    Docker unavailable       test_check_docker_socket_missing, test_check_docker_socket_invalid
    HTTP ok / fail / timeout test_check_service_http_healthy / _http_error / _timeout
    illegal input            test_check_project_*_rejected, test_check_service_rejected_*,
                             test_check_service_rejects_*, test_check_service_timeout_is_clamped
    agent tool calling       test_ops_tools_are_registered_on_agent,
                             test_agent_runs_check_project_tool_end_to_end

Run with:  python -m pytest            (from the backend/ directory)
"""

import pytest

from app.agents.tools import OPS_TOOLS, check_docker, check_project, check_service


def make_project(root, name, files):
    """Create ``root/name`` containing empty files named in ``files``."""
    project = root / name
    project.mkdir(parents=True, exist_ok=True)
    for file_name in files:
        (project / file_name).write_text("x", encoding="utf-8")
    return project


# ══════════════════════════════════════════════════════════════════════════
# 1. check_project
# ══════════════════════════════════════════════════════════════════════════


def test_check_project_healthy_python(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = make_project(tmp_path, "api", ["pyproject.toml", "README.md", ".gitignore"])

    report = check_project.invoke({"path": str(project)})

    assert "总体状态：正常" in report
    assert "Python 项目" in report
    assert "✓ pyproject.toml" in report
    assert "已拒绝" not in report


def test_check_project_reports_missing_key_file(configure_ops, tmp_path):
    """A lock file without its manifest is exactly the broken state we want caught."""
    configure_ops(roots=[tmp_path])
    project = make_project(tmp_path, "web", ["package-lock.json"])

    report = check_project.invoke({"path": str(project)})

    assert "总体状态：异常" in report
    assert "Node.js 项目" in report
    assert "✗ 缺失：package.json" in report


def test_check_project_go_checks_gomod_not_requirements(configure_ops, tmp_path):
    """Type detection must not demand files from other ecosystems."""
    configure_ops(roots=[tmp_path])
    project = make_project(tmp_path, "svc", ["go.mod", "go.sum", "README.md", ".gitignore"])

    report = check_project.invoke({"path": str(project)})

    assert "Go 项目" in report
    assert "requirements.txt" not in report
    assert "总体状态：正常" in report


def test_check_project_lists_subprojects(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    root = make_project(tmp_path, "mono", ["docker-compose.yml", "README.md"])
    make_project(root, "backend", ["requirements.txt"])
    make_project(root, "frontend", ["package.json"])

    report = check_project.invoke({"path": str(root)})

    assert "Docker Compose 项目" in report
    assert "子项目" in report
    assert "backend/ → Python 项目" in report
    assert "frontend/ → Node.js 项目" in report


def test_check_project_directory_not_found(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    make_project(tmp_path, "api", ["requirements.txt"])

    report = check_project.invoke({"path": str(tmp_path / "nope")})

    assert "总体状态：异常" in report
    assert "目录不存在" in report
    # Helpful hint: list what actually exists next to the requested path.
    assert "api" in report


def test_check_project_rejects_path_outside_roots(configure_ops, tmp_path):
    allowed = tmp_path / "allowed"
    outside = make_project(tmp_path, "secret", ["requirements.txt"])
    configure_ops(roots=[allowed])

    report = check_project.invoke({"path": str(outside)})

    assert "总体状态：已拒绝" in report
    assert "不在允许检查的范围内" in report
    assert "OPS_PROJECT_ROOTS" in report  # tells the user how to allow it


def test_check_project_rejects_traversal(configure_ops, tmp_path):
    allowed = make_project(tmp_path, "allowed", [])
    configure_ops(roots=[allowed])

    report = check_project.invoke({"path": str(allowed / ".." / ".." / "etc")})

    assert "总体状态：已拒绝" in report


def test_check_project_rejects_everything_when_no_roots(configure_ops, tmp_path):
    configure_ops(roots=[])
    project = make_project(tmp_path, "api", ["requirements.txt"])

    report = check_project.invoke({"path": str(project)})

    assert "总体状态：已拒绝" in report
    assert "OPS_PROJECT_ROOTS" in report


def test_check_project_rejects_file_path(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = make_project(tmp_path, "api", ["requirements.txt"])

    report = check_project.invoke({"path": str(project / "requirements.txt")})

    assert "不是目录" in report


def test_check_project_empty_path_lists_roots(configure_ops, tmp_path):
    make_project(tmp_path, "api", ["requirements.txt"])
    make_project(tmp_path, "web", ["package.json"])
    configure_ops(roots=[tmp_path])

    report = check_project.invoke({"path": ""})

    assert "允许检查的根目录" in report
    assert "- api/" in report
    assert "- web/" in report


def test_check_project_empty_path_without_roots(configure_ops):
    configure_ops(roots=[])

    report = check_project.invoke({"path": ""})

    assert "未配置任何允许检查的目录" in report


# ══════════════════════════════════════════════════════════════════════════
# 2. check_docker
# ══════════════════════════════════════════════════════════════════════════


async def test_check_docker_ok(configure_ops, fake_docker_socket):
    configure_ops(socket=fake_docker_socket)

    report = await check_docker.ainvoke({})

    assert "总体状态：可用" in report
    assert "Docker 27.3.1" in report
    assert "容器统计：共 3 个，运行中 2 个，非运行 1 个" in report
    assert "agenthub-backend [running]，健康检查=healthy" in report
    assert "legacy-worker [exited]" in report


async def test_check_docker_specific_containers(configure_ops, fake_docker_socket):
    configure_ops(socket=fake_docker_socket)

    report = await check_docker.ainvoke({"containers": "agenthub-db, agenthub-backend"})

    assert "指定容器" in report
    assert "agenthub-db [running]" in report
    assert "未找到该容器" not in report


async def test_check_docker_container_not_found(configure_ops, fake_docker_socket):
    configure_ops(socket=fake_docker_socket)

    report = await check_docker.ainvoke({"containers": "does-not-exist"})

    assert "✗ does-not-exist（未找到该容器）" in report
    assert "可能原因" in report


async def test_check_docker_no_containers(configure_ops, empty_docker_socket):
    configure_ops(socket=empty_docker_socket)

    report = await check_docker.ainvoke({})

    assert "容器统计：共 0 个" in report
    assert "当前没有任何容器" in report


async def test_check_docker_socket_missing(configure_ops, tmp_path):
    configure_ops(socket=str(tmp_path / "absent.sock"))

    report = await check_docker.ainvoke({})

    assert "总体状态：不可用" in report
    assert "不存在 Docker socket" in report
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in report  # actionable advice


async def test_check_docker_socket_invalid(configure_ops, tmp_path):
    """A file that exists but is not a listening daemon must not raise."""
    bogus = tmp_path / "docker.sock"
    bogus.write_text("not a socket", encoding="utf-8")
    configure_ops(socket=str(bogus))

    report = await check_docker.ainvoke({"timeout": 1})

    assert "总体状态：不可用" in report
    assert "查询失败" in report


async def test_check_docker_prefix_match(configure_ops, fake_docker_socket):
    """Docker allows prefix matching — an unambiguous prefix should resolve."""
    configure_ops(socket=fake_docker_socket)

    report = await check_docker.ainvoke({"containers": "agenthub-d"})

    assert "agenthub-db [running]" in report
    assert "未找到该容器" not in report


async def test_check_docker_ambiguous_prefix(configure_ops, fake_docker_socket):
    """An ambiguous prefix must be reported, not silently guessed."""
    configure_ops(socket=fake_docker_socket)

    report = await check_docker.ainvoke({"containers": "agenthub"})

    assert "匹配到多个" in report


# ══════════════════════════════════════════════════════════════════════════
# 3. check_service — configured targets
# ══════════════════════════════════════════════════════════════════════════


async def test_check_service_http_healthy(configure_ops, http_port):
    configure_ops(endpoints={"web": f"http://127.0.0.1:{http_port}/health"})

    report = await check_service.ainvoke({"target": "web"})

    assert "总体状态：健康" in report
    assert "HTTP 200" in report
    assert "已配置目标：web" in report


async def test_check_service_http_error_status(configure_ops, http_port):
    configure_ops(endpoints={"web": f"http://127.0.0.1:{http_port}/error"})

    report = await check_service.ainvoke({"target": "web"})

    assert "总体状态：异常" in report
    assert "HTTP 500" in report
    assert "处理建议" in report


async def test_check_service_timeout(configure_ops, http_port):
    configure_ops(endpoints={"slow": f"http://127.0.0.1:{http_port}/slow"})

    report = await check_service.ainvoke({"target": "slow", "timeout": 0.5})

    assert "总体状态：异常" in report
    assert "请求超时" in report
    assert "超时设置：0.5s" in report


async def test_check_service_connection_refused(configure_ops):
    """Nothing is listening on port 1 — must be reported, not raised."""
    configure_ops(endpoints={"dead": "http://127.0.0.1:1/health"})

    report = await check_service.ainvoke({"target": "dead"})

    assert "总体状态：异常" in report
    assert "连接失败" in report or "连接被拒绝" in report


async def test_check_service_tcp_healthy(configure_ops, http_port):
    configure_ops(endpoints={"db": f"tcp://127.0.0.1:{http_port}"})

    report = await check_service.ainvoke({"target": "db"})

    assert "总体状态：健康" in report
    assert "TCP 端口可连接" in report


async def test_check_service_tcp_refused(configure_ops):
    configure_ops(endpoints={"db": "tcp://127.0.0.1:1"})

    report = await check_service.ainvoke({"target": "db"})

    assert "总体状态：异常" in report


async def test_check_service_lists_configured_targets(configure_ops):
    configure_ops(endpoints={"web": "http://web:80/health", "db": "tcp://db:5432"})

    report = await check_service.ainvoke({"target": ""})

    assert "web → http://web:80/health" in report
    assert "db → tcp://db:5432" in report


# ══════════════════════════════════════════════════════════════════════════
# 4. check_service — ad-hoc targets and SSRF guards
# ══════════════════════════════════════════════════════════════════════════


async def test_check_service_rejected_when_allowlist_empty(configure_ops, http_port):
    configure_ops(allowed=[], endpoints={})

    report = await check_service.ainvoke({"target": f"http://127.0.0.1:{http_port}/health"})

    assert "总体状态：已拒绝" in report
    assert "OPS_ALLOWED_HOSTS" in report


async def test_check_service_rejects_unlisted_host(configure_ops):
    configure_ops(allowed=["10.0.0.5"])

    report = await check_service.ainvoke({"target": "http://example.com/health"})

    assert "总体状态：已拒绝" in report
    assert "不在允许清单" in report


async def test_check_service_allows_listed_host(configure_ops, http_port):
    configure_ops(allowed=["127.0.0.1"])

    report = await check_service.ainvoke({"target": f"http://127.0.0.1:{http_port}/health"})

    assert "总体状态：健康" in report
    assert "临时目标" in report


async def test_check_service_allows_cidr_entry(configure_ops, http_port):
    configure_ops(allowed=["127.0.0.0/8"])

    report = await check_service.ainvoke({"target": f"http://127.0.0.1:{http_port}/health"})

    assert "总体状态：健康" in report


@pytest.mark.parametrize(
    "metadata_target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ],
)
async def test_check_service_blocks_metadata_endpoints(configure_ops, metadata_target):
    """Even a permissive allow-list must not open the cloud metadata service."""
    configure_ops(allowed=["0.0.0.0/0", "169.254.169.254", "metadata.google.internal"])

    report = await check_service.ainvoke({"target": metadata_target})

    assert "总体状态：已拒绝" in report
    assert "元数据地址" in report


async def test_check_service_rejects_unknown_scheme(configure_ops):
    configure_ops(endpoints={"bad": "ftp://example.com/file"})

    report = await check_service.ainvoke({"target": "bad"})

    assert "已拒绝" in report
    assert "不支持的协议" in report


async def test_check_service_rejects_credentials_in_url(configure_ops):
    configure_ops(endpoints={"bad": "http://user:pass@example.com/"})

    report = await check_service.ainvoke({"target": "bad"})

    assert "不允许携带用户名/密码" in report


async def test_check_service_rejects_bad_port(configure_ops):
    configure_ops(endpoints={"bad": "http://example.com:99999/"})

    report = await check_service.ainvoke({"target": "bad"})

    assert "已拒绝" in report


async def test_check_service_timeout_is_clamped(configure_ops, http_port):
    configure_ops(endpoints={"web": f"http://127.0.0.1:{http_port}/health"})

    report = await check_service.ainvoke({"target": "web", "timeout": 999})

    assert "超时设置：15.0s" in report  # clamped to _MAX_TIMEOUT


async def test_check_service_redacts_secrets(configure_ops, http_port):
    """Neither the response body nor the query string may leak into the report."""
    configure_ops(
        endpoints={
            "leaky": f"http://127.0.0.1:{http_port}/leaky?token=super-secret-value"
        }
    )

    report = await check_service.ainvoke({"target": "leaky"})

    assert "sk-do-not-leak-me" not in report
    assert "super-secret-value" not in report
    assert "***" in report  # the key was masked, the fact was kept


# ══════════════════════════════════════════════════════════════════════════
# 5. Agent integration
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "tool_obj,expected_args",
    [
        (check_project, {"path"}),
        (check_docker, {"containers", "timeout"}),
        (check_service, {"target", "timeout"}),
    ],
)
def test_ops_tool_schemas_expose_only_user_facing_args(tool_obj, expected_args):
    """Hidden parameters (runtime/store) must never be visible to the model."""
    schema = tool_obj.args_schema.model_json_schema()
    assert set(schema["properties"]) == expected_args


def _stub_llm():
    """A real (offline) chat model — SummarizationMiddleware needs `_llm_type`."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    return GenericFakeChatModel(messages=iter([AIMessage(content="ok")]))


async def test_ops_tools_are_registered_on_agent(monkeypatch):
    """init_agent() must hand the three ops tools to create_agent()."""
    from app.agents import supervisor
    from app.infra import config as config_module

    captured: dict = {}

    def fake_create_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(supervisor, "create_agent", fake_create_agent)
    monkeypatch.setattr(supervisor, "_agent_instance", None)
    monkeypatch.setattr("app.infra.llm.get_system_llm", _stub_llm)
    monkeypatch.setattr(
        config_module,
        "get_settings",
        lambda: type("S", (), {"OPS_ENABLED": True})(),
    )

    await supervisor.init_agent(checkpointer=None, store=None)

    names = {t.name for t in captured["tools"]}
    assert {"check_project", "check_docker", "check_service"} <= names
    assert captured["context_schema"].__name__ == "AgentRuntimeContext"


async def test_ops_tools_can_be_disabled(monkeypatch):
    """OPS_ENABLED=false must remove them from the agent."""
    from app.agents import supervisor
    from app.infra import config as config_module

    captured: dict = {}
    monkeypatch.setattr(
        supervisor, "create_agent", lambda **kw: captured.update(kw) or object()
    )
    monkeypatch.setattr(supervisor, "_agent_instance", None)
    monkeypatch.setattr("app.infra.llm.get_system_llm", _stub_llm)
    monkeypatch.setattr(
        config_module,
        "get_settings",
        lambda: type("S", (), {"OPS_ENABLED": False})(),
    )

    await supervisor.init_agent(checkpointer=None, store=None)

    names = {t.name for t in captured["tools"]}
    assert not ({"check_project", "check_docker", "check_service"} & names)


async def test_agent_runs_check_project_tool_end_to_end(configure_ops, tmp_path):
    """Drive a real agent graph: model asks for the tool → tool runs → answer.

    This exercises the genuine LangGraph tool-calling loop (model node → tool
    node → model node) with our tools wired in, no network and no database.
    """
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage, HumanMessage
    from langgraph.checkpoint.memory import InMemorySaver
    from langchain.agents import create_agent

    configure_ops(roots=[tmp_path])
    project = make_project(tmp_path, "api", ["requirements.txt", "README.md", ".gitignore"])

    class ScriptedModel(GenericFakeChatModel):
        """GenericFakeChatModel can't bind tools; the agent always binds."""

        def bind_tools(self, tools, **kwargs):
            return self

    model = ScriptedModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "check_project",
                            "args": {"path": str(project)},
                            "id": "call_1",
                        }
                    ],
                ),
                AIMessage(content="检查完成，服务正常。"),
            ]
        )
    )

    agent = create_agent(
        model=model,
        tools=list(OPS_TOOLS),
        checkpointer=InMemorySaver(),
    )
    result = await agent.ainvoke(
        {"messages": [HumanMessage(content="检查一下 api 项目健康吗")]},
        config={"configurable": {"thread_id": "test-thread"}},
    )

    contents = [m.content for m in result["messages"]]
    tool_outputs = [
        m.content
        for m in result["messages"]
        if type(m).__name__ == "ToolMessage"
    ]
    assert tool_outputs, f"the tool never ran; messages={contents}"
    assert "总体状态：正常" in tool_outputs[0]
    assert "Python 项目" in tool_outputs[0]
    assert result["messages"][-1].content == "检查完成，服务正常。"
