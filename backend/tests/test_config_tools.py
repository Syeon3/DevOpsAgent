"""Tests for the config / startup diagnosis tools.

覆盖三块：

1. ``app/agents/tools/config_check.py`` 的纯函数（解析 + 比对），直接喂字符串，
   不需要文件系统；
2. ``check_config`` 工具（临时目录 + 真实文件 I/O + 路径白名单）；
3. ``diagnose_startup`` 工具（假的 Docker Engine API，见 conftest 的 docker_api）。

Coverage map（需求 → 测试）：

    正常配置            test_audit_clean_project_has_no_findings,
                        test_check_config_healthy_project,
                        test_check_startup_all_running_has_no_findings
    配置缺失            test_audit_reports_keys_missing_from_env,
                        test_audit_reports_missing_actual_env_file,
                        test_audit_reports_missing_env_file_of_compose,
                        test_check_startup_reports_service_without_container
    格式错误            test_parse_dotenv_*, test_parse_compose_invalid_yaml_*,
                        test_audit_reports_bad_port_format
    敏感信息脱敏        test_safe_items_masks_secret_values,
                        test_audit_flags_real_secret_in_template,
                        test_audit_never_puts_secret_values_in_findings,
                        test_check_config_report_never_contains_secret_values
    路径安全            test_check_config_rejects_path_outside_roots,
                        test_check_config_rejects_traversal,
                        test_diagnose_startup_rejects_path_outside_roots
    异常处理            test_check_config_missing_directory,
                        test_check_config_path_is_a_file,
                        test_check_config_skips_oversized_file,
                        test_check_config_notes_non_utf8_file,
                        test_diagnose_startup_without_docker_socket,
                        test_diagnose_startup_handles_docker_unavailable
    启动问题分析        test_check_startup_reports_exited_container_with_code,
                        test_check_startup_reports_restart_loop,
                        test_check_startup_reports_dependency_not_running,
                        test_check_startup_reports_port_taken_by_other_container
    工具注册            test_config_tools_are_registered_in_ops_tools,
                        test_config_tools_are_registered_on_agent

Run with:  python -m pytest            (from the backend/ directory)
"""

from pathlib import Path

import pytest

from app.agents.tools import OPS_TOOLS, check_config, diagnose_startup
from app.agents.tools import config_check as cc

# ══════════════════════════════════════════════════════════════════════════
# 测试素材
# ══════════════════════════════════════════════════════════════════════════

# 一个"看起来是真的"的密钥，用来验证它绝不会出现在报告里。
REAL_SECRET = "sk-liveABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

HEALTHY_ENV = "MODE=dev\nPOSTGRES_HOST=db\nPOSTGRES_PORT=5432\nLOG_LEVEL=INFO\n"
HEALTHY_EXAMPLE = "MODE=dev\nPOSTGRES_HOST=localhost\nPOSTGRES_PORT=5432\nLOG_LEVEL=INFO\n"
HEALTHY_GITIGNORE = ".env\n.env.local\n"

HEALTHY_COMPOSE = """\
services:
  backend:
    image: agenthub-backend
    build:
      context: ./backend
    container_name: agenthub-backend
    env_file:
      - ./backend/.env
    ports:
      - "8080:8080"
  db:
    image: postgres:18
    container_name: agenthub-db
    ports:
      - "5432:5432"
"""


def write_configs(root: Path, files: dict[str, str]) -> Path:
    """把 ``{相对路径: 内容}`` 写进 root，返回 root。"""
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def healthy_project(root: Path) -> Path:
    """一个配置完全自洽的项目：模板与 .env 键一致、compose 引用都存在。"""
    return write_configs(
        root,
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "docker-compose.yml": HEALTHY_COMPOSE,
            "backend/.env": HEALTHY_ENV,
            "backend/.env.example": HEALTHY_EXAMPLE,
            "backend/Dockerfile": "FROM python:3.12\n",
        },
    )


def run_audit(*, dotenv_files=None, compose_files=None, **kwargs):
    """``audit`` 的薄包装：测试只关心其中一类文件时，另一类直接当"没有"。"""
    return cc.audit(
        dotenv_files=dict(dotenv_files or {}),
        compose_files=dict(compose_files or {}),
        **kwargs,
    )


def findings_of(findings, name):
    return [f for f in findings if f.name == name]


def all_text(findings) -> str:
    """把结论里所有会展示给用户的文本拼起来，用于"有没有泄露"这类断言。"""
    chunks = []
    for f in findings:
        chunks.extend([f.category, f.hint, f.advice, *f.evidence])
    return "\n".join(chunks)


# ══════════════════════════════════════════════════════════════════════════
# 1. parse_dotenv —— 语法解析
# ══════════════════════════════════════════════════════════════════════════


def test_parse_dotenv_reads_plain_pairs():
    parsed = cc.parse_dotenv("# 注释\n\nMODE=dev\nLOG_LEVEL=INFO\n")

    assert parsed.values == {"MODE": "dev", "LOG_LEVEL": "INFO"}
    assert parsed.order == ("MODE", "LOG_LEVEL")
    assert parsed.problems == ()


def test_parse_dotenv_strips_matching_quotes():
    parsed = cc.parse_dotenv('A="hello world"\nB=\'single\'\n')

    assert parsed.values == {"A": "hello world", "B": "single"}
    assert parsed.problems == ()


def test_parse_dotenv_accepts_export_prefix():
    parsed = cc.parse_dotenv("export MODE=prod\n")

    assert parsed.values == {"MODE": "prod"}
    assert parsed.problems == ()


def test_parse_dotenv_strips_inline_comment_on_unquoted_value():
    parsed = cc.parse_dotenv("LOG_LEVEL=INFO  # 日志级别\n")

    assert parsed.values == {"LOG_LEVEL": "INFO"}


def test_parse_dotenv_keeps_hash_inside_quotes():
    parsed = cc.parse_dotenv('PASSWORD="a#b"\n')

    assert parsed.values == {"PASSWORD": "a#b"}


def test_parse_dotenv_key_with_spaces_around_equals():
    parsed = cc.parse_dotenv("MODE = dev\n")

    assert parsed.values == {"MODE": "dev"}


def test_parse_dotenv_duplicate_key_keeps_last_value():
    parsed = cc.parse_dotenv("MODE=dev\nMODE=prod\n")

    assert parsed.values == {"MODE": "prod"}
    assert parsed.duplicates == ("MODE",)
    assert parsed.order == ("MODE",)  # 只记一次，报告里不会出现两行


def test_parse_dotenv_line_without_equals_is_a_problem():
    parsed = cc.parse_dotenv("MODE=dev\nTHIS LINE HAS NO EQUALS\n")

    assert len(parsed.problems) == 1
    assert "第 2 行" in parsed.problems[0]
    assert "KEY=VALUE" in parsed.problems[0]
    assert parsed.values == {"MODE": "dev"}


def test_parse_dotenv_illegal_key_name_is_a_problem():
    parsed = cc.parse_dotenv("MY-KEY=1\n")

    assert len(parsed.problems) == 1
    assert "键名不合法" in parsed.problems[0]


def test_parse_dotenv_unclosed_quote_is_a_problem():
    parsed = cc.parse_dotenv('A="unterminated\n')

    assert len(parsed.problems) == 1
    assert "引号没有闭合" in parsed.problems[0]


def test_parse_dotenv_line_starting_with_equals_has_no_key():
    parsed = cc.parse_dotenv("=value\n")

    assert "缺少键名" in parsed.problems[0]


def test_parse_dotenv_empty_keys_are_reported():
    parsed = cc.parse_dotenv("A=\nB=   \nC=1\n")

    assert parsed.empty_keys() == ["A", "B"]


# ══════════════════════════════════════════════════════════════════════════
# 2. 密钥识别与脱敏
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "key",
    [
        "JWT_SECRET_KEY",
        "POSTGRES_PASSWORD",
        "TAVILY_API_KEY",
        "SYSTEM_DEFAULT_LLM_API_KEY",
        "API_KEY_ENCRYPTION_KEY",
        "AMAP_KEY",
        "LANGCHAIN_API_KEY",
        "DATABASE_DSN",
        "SMTP_PASSWD",
        "access_token",
        "AWS_CREDENTIALS",
    ],
)
def test_is_sensitive_key_matches_secret_like_names(key):
    assert cc.is_sensitive_key(key) is True


@pytest.mark.parametrize(
    "key",
    [
        "MODE",
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "LOG_LEVEL",
        "OPS_PROJECT_ROOTS",
        "MONKEY_COUNT",  # 分段匹配的意义：不能被 "KEY" 子串误伤
        "KEYSTONE_URL",
    ],
)
def test_is_sensitive_key_does_not_over_match(key):
    assert cc.is_sensitive_key(key) is False


def test_safe_items_masks_secret_values_but_keeps_plain_ones():
    parsed = cc.parse_dotenv("MODE=dev\nJWT_SECRET_KEY=super-secret-value\n")

    safe = dict(parsed.safe_items())

    assert safe["MODE"] == "dev"  # 非密钥照常显示，排障时有用
    assert safe["JWT_SECRET_KEY"] == "***"
    assert "super-secret-value" not in str(safe)


def test_safe_items_keeps_empty_secret_empty():
    """空值显示成空，不会被伪装成 "***"（那会让人以为它配过了）。"""
    parsed = cc.parse_dotenv("JWT_SECRET_KEY=\n")

    assert dict(parsed.safe_items())["JWT_SECRET_KEY"] == ""


def test_sensitive_keys_with_real_value_skips_placeholders():
    parsed = cc.parse_dotenv(
        "A_KEY=your-api-key-here\n"
        "B_KEY=changeme\n"
        f"C_KEY={REAL_SECRET}\n"
        "D_KEY=\n"
        "MODE=dev\n"
    )

    assert [k for k, _ in parsed.sensitive_keys_with_real_value()] == ["C_KEY"]


# ══════════════════════════════════════════════════════════════════════════
# 3. parse_compose
# ══════════════════════════════════════════════════════════════════════════


def test_parse_compose_reads_services_and_fields():
    parsed = cc.parse_compose(HEALTHY_COMPOSE)

    assert parsed.problems == ()
    assert sorted(parsed.services) == ["backend", "db"]
    backend = parsed.services["backend"]
    assert backend.image == "agenthub-backend"
    assert backend.build_context == "./backend"
    assert backend.container_name == "agenthub-backend"
    assert backend.env_file == ("./backend/.env",)
    assert backend.host_ports == (8080,)


def test_parse_compose_accepts_build_as_plain_string():
    parsed = cc.parse_compose("services:\n  a:\n    build: ./svc\n")

    assert parsed.services["a"].build_context == "./svc"
    assert parsed.services["a"].has_build_or_image()


def test_parse_compose_handles_env_file_dict_form():
    """Compose 2.24+ 的长格式 ``env_file: [{path: ...}]`` 也要认。"""
    parsed = cc.parse_compose(
        "services:\n  a:\n    image: x\n    env_file:\n      - path: .env\n        required: false\n"
    )

    assert parsed.services["a"].env_file == (".env",)


def test_parse_compose_accepts_environment_list_and_mapping():
    parsed = cc.parse_compose(
        "services:\n"
        "  a:\n"
        "    image: x\n"
        "    environment:\n"
        "      - FOO=1\n"
        "      - BAR=2\n"
        "  b:\n"
        "    image: y\n"
        "    environment:\n"
        "      BAZ: \"3\"\n"
        "      PASSED:\n"
    )

    assert parsed.services["a"].environment == {"FOO": "1", "BAR": "2"}
    assert parsed.services["b"].environment == {"BAZ": "3", "PASSED": ""}


def test_parse_compose_invalid_yaml_reports_line_number():
    parsed = cc.parse_compose("services:\n  a:\n   - [unclosed\n")

    assert parsed.services == {}
    assert len(parsed.problems) == 1
    assert "YAML 解析失败" in parsed.problems[0]
    assert "行" in parsed.problems[0]


def test_parse_compose_empty_document_is_a_problem():
    parsed = cc.parse_compose("")

    assert "空" in parsed.problems[0]


def test_parse_compose_top_level_not_a_mapping():
    parsed = cc.parse_compose("- just\n- a list\n")

    assert "顶层结构不是键值映射" in parsed.problems[0]


def test_parse_compose_missing_services_section():
    parsed = cc.parse_compose("version: '3'\nnetworks:\n  n: {}\n")

    assert "没有 services 段" in parsed.problems[0]


def test_parse_compose_service_value_not_a_mapping():
    parsed = cc.parse_compose("services:\n  a: just-a-string\n")

    assert "不是键值映射" in parsed.problems[0]
    assert parsed.services == {}


def test_parse_compose_flags_deprecated_version_key():
    parsed = cc.parse_compose("version: '3.8'\nservices:\n  a:\n    image: x\n")

    assert parsed.deprecated_version_key is True


def test_parse_compose_does_not_construct_arbitrary_objects():
    """必须用 safe_load：恶意 compose 不能借 YAML 标签构造 Python 对象。"""
    parsed = cc.parse_compose("services: !!python/object/apply:os.system ['echo hi']\n")

    assert parsed.services == {}
    assert parsed.problems  # 报错，而不是执行


# ── 端口与插值 ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("8080:8080", 8080),
        ("127.0.0.1:8080:8080", 8080),
        ("8080", None),  # 只写容器端口 → 宿主机端口随机
        ("${BACKEND_PORT:-8080}:8080", None),  # 运行期才知道，不猜
    ],
)
def test_parse_port_entry(entry, expected):
    port, problem = cc._parse_port_entry(entry)

    assert port == expected
    assert problem == ""


@pytest.mark.parametrize("entry", ["abc:8080", "8080:8080:8080:1", "70000:80"])
def test_parse_port_entry_rejects_malformed(entry):
    _port, problem = cc._parse_port_entry(entry)

    assert problem != ""


def test_find_interpolations_distinguishes_default():
    found = cc.find_interpolations(
        "image: app:${TAG:-latest}\nports: ['${PORT}:80']\nvol: ${DATA_DIR}\n"
    )

    assert found == {"TAG": True, "PORT": False, "DATA_DIR": False}


def test_find_interpolations_handles_bare_dollar_form():
    assert cc.find_interpolations("image: app:$TAG\n") == {"TAG": False}


# ══════════════════════════════════════════════════════════════════════════
# 4. audit —— .env 与 .env.example
# ══════════════════════════════════════════════════════════════════════════


def test_audit_clean_project_has_no_findings():
    findings = run_audit(
        dotenv_files={"backend/.env": HEALTHY_ENV, "backend/.env.example": HEALTHY_EXAMPLE},
        compose_files={"docker-compose.yml": HEALTHY_COMPOSE},
        present_files={"backend/.env", "backend/.env.example", "backend/Dockerfile"},
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings == []


def test_audit_reports_keys_missing_from_env():
    findings = run_audit(
        dotenv_files={
            "backend/.env": "MODE=dev\n",
            "backend/.env.example": "MODE=dev\nJWT_SECRET_KEY=\nPOSTGRES_HOST=localhost\n",
        },
        gitignore=HEALTHY_GITIGNORE,
    )

    missing = findings_of(findings, "env_missing_key")
    assert len(missing) == 1
    assert missing[0].severity == "严重"
    assert "JWT_SECRET_KEY" in missing[0].evidence[0]
    assert "POSTGRES_HOST" in missing[0].evidence[0]


def test_audit_reports_empty_value_declared_in_template():
    findings = run_audit(
        dotenv_files={
            "backend/.env": "MODE=dev\nPOSTGRES_HOST=\n",
            "backend/.env.example": "MODE=dev\nPOSTGRES_HOST=localhost\n",
        },
        gitignore=HEALTHY_GITIGNORE,
    )

    # 空值只报一次（env_empty_key），不会被同时算成"缺失"
    assert findings_of(findings, "env_missing_key") == []
    empty = findings_of(findings, "env_empty_key")
    assert len(empty) == 1
    assert "POSTGRES_HOST" in empty[0].evidence[0]


def test_audit_reports_keys_missing_from_template():
    findings = run_audit(
        dotenv_files={
            "backend/.env": "MODE=dev\nDEBUG_LOCAL=1\n",
            "backend/.env.example": "MODE=dev\n",
        },
        gitignore=HEALTHY_GITIGNORE,
    )

    extra = findings_of(findings, "env_extra_key")
    assert len(extra) == 1
    assert extra[0].severity == "提示"
    assert "DEBUG_LOCAL" in extra[0].evidence[0]


def test_audit_reports_missing_actual_env_file():
    findings = run_audit(
        dotenv_files={"backend/.env.example": HEALTHY_EXAMPLE},
        gitignore=".env\n",
    )

    missing = findings_of(findings, "env_actual_missing")
    assert len(missing) == 1
    assert missing[0].severity == "严重"
    assert "cp .env.example .env" in missing[0].advice


def test_audit_reports_dotenv_syntax_problem():
    findings = run_audit(
        dotenv_files={"backend/.env": "MODE=dev\nNO EQUALS HERE\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    syntax = findings_of(findings, "dotenv_syntax")
    assert len(syntax) == 1
    assert syntax[0].severity == "严重"


def test_audit_reports_duplicate_key():
    findings = run_audit(
        dotenv_files={"backend/.env": "MODE=dev\nMODE=prod\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    dup = findings_of(findings, "dotenv_duplicate_key")
    assert len(dup) == 1
    assert dup[0].severity == "警告"


def test_audit_reports_required_key_missing():
    findings = run_audit(
        dotenv_files={"backend/.env": "MODE=dev\n"},
        required_keys=["POSTGRES_HOST", "MODE"],
        gitignore=HEALTHY_GITIGNORE,
    )

    required = findings_of(findings, "required_key_missing")
    assert len(required) == 1
    assert "POSTGRES_HOST" in required[0].evidence[1]
    assert "MODE" not in required[0].evidence[1].split("都没有找到：")[-1]


def test_audit_required_key_accepts_definition_in_any_env_file():
    """必需项写在 frontend/.env 还是 backend/.env 都算配了，不能误报。"""
    findings = run_audit(
        dotenv_files={"frontend/.env": "API_BASE=http://x\n"},
        required_keys=["API_BASE"],
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings_of(findings, "required_key_missing") == []


def test_audit_ignores_required_keys_when_none_declared():
    findings = run_audit(
        dotenv_files={"backend/.env": "MODE=dev\n"},
        required_keys=[],
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings_of(findings, "required_key_missing") == []


# ══════════════════════════════════════════════════════════════════════════
# 5. audit —— 密钥泄露检查
# ══════════════════════════════════════════════════════════════════════════


def test_audit_flags_real_secret_in_template():
    findings = run_audit(
        dotenv_files={"backend/.env.example": f"LLM_API_KEY={REAL_SECRET}\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    flagged = findings_of(findings, "template_real_secret")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"
    assert "LLM_API_KEY" in flagged[0].evidence[0]


def test_audit_flags_concrete_secret_value_in_template():
    # 这里刻意用一个"编造的"具体值：既不能是占位符（那样就不该报），
    # 也不能抄真实部署里的密钥 —— 测试用例会进版本库，抄真值等于二次泄露。
    findings = run_audit(
        dotenv_files={"backend/.env.example": "API_KEY_ENCRYPTION_KEY=LocalDevOnlyKey2026Xyz\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    flagged = findings_of(findings, "template_concrete_secret")
    assert len(flagged) == 1
    assert flagged[0].severity == "警告"


@pytest.mark.parametrize(
    "value",
    [
        "your-secret-key-please-replace",
        "changeme",
        "<your-api-key>",
        "sk-abcdefghijklmnop***********",
        "TODO",
        "",
    ],
)
def test_audit_does_not_flag_placeholder_secrets(value):
    findings = run_audit(
        dotenv_files={"backend/.env.example": f"JWT_SECRET_KEY={value}\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings_of(findings, "template_real_secret") == []
    assert findings_of(findings, "template_concrete_secret") == []


def test_audit_does_not_flag_secrets_in_real_env_file():
    """``.env`` 本来就要放真密钥 —— 只在模板文件里报，避免天天误报。"""
    findings = run_audit(
        dotenv_files={"backend/.env": f"LLM_API_KEY={REAL_SECRET}\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings_of(findings, "template_real_secret") == []
    assert findings_of(findings, "template_concrete_secret") == []


def test_audit_never_puts_secret_values_in_findings():
    """最重要的一条：结论里的任何字段都不能出现密钥的值。"""
    findings = run_audit(
        dotenv_files={
            "backend/.env.example": f"LLM_API_KEY={REAL_SECRET}\nJWT_SECRET_KEY={REAL_SECRET}\n",
        },
        gitignore=HEALTHY_GITIGNORE,
    )

    text = all_text(findings)
    assert findings  # 先确认真的报了问题，否则这个断言是空的
    assert REAL_SECRET not in text
    assert REAL_SECRET[:20] not in text  # 连前 20 位都不给


def test_audit_flags_env_not_covered_by_gitignore():
    findings = run_audit(
        dotenv_files={"backend/.env": HEALTHY_ENV},
        gitignore="__pycache__/\nnode_modules/\n",
    )

    flagged = findings_of(findings, "env_not_gitignored")
    assert len(flagged) == 1
    assert "backend/.env" in flagged[0].evidence[0]


@pytest.mark.parametrize("pattern", [".env", ".env*", "*.env", "/.env", "backend/.env"])
def test_audit_accepts_gitignore_patterns_covering_env(pattern):
    findings = run_audit(
        dotenv_files={"backend/.env": HEALTHY_ENV},
        gitignore=f"{pattern}\n",
    )

    assert findings_of(findings, "env_not_gitignored") == []


def test_audit_skips_gitignore_check_when_file_absent():
    """没有 .gitignore 就不判断 —— 也许项目根本不用 git。"""
    findings = run_audit(
        dotenv_files={"backend/.env": HEALTHY_ENV},
        gitignore="",
    )

    assert findings_of(findings, "env_not_gitignored") == []


# ══════════════════════════════════════════════════════════════════════════
# 6. audit —— compose
# ══════════════════════════════════════════════════════════════════════════


def test_audit_reports_missing_env_file_of_compose():
    findings = run_audit(
        compose_files={"docker-compose.yml": HEALTHY_COMPOSE},
        present_files={"docker-compose.yml", "backend/Dockerfile"},  # 少了 backend/.env
    )

    flagged = findings_of(findings, "compose_env_file_missing")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"
    assert "backend → ./backend/.env" in flagged[0].evidence[0]


def test_audit_reports_unknown_depends_on():
    findings = run_audit(
        compose_files={
            "docker-compose.yml": "services:\n  a:\n    image: x\n    depends_on:\n      - ghost\n"
        },
    )

    flagged = findings_of(findings, "compose_depends_on_unknown")
    assert len(flagged) == 1
    assert "a → ghost" in flagged[0].evidence[0]


def test_audit_reports_service_without_image_or_build():
    findings = run_audit(compose_files={"docker-compose.yml": "services:\n  a:\n    restart: always\n"})

    flagged = findings_of(findings, "compose_service_without_image")
    assert len(flagged) == 1
    assert "a" in flagged[0].evidence[0]


def test_audit_reports_port_conflict_between_services():
    findings = run_audit(
        compose_files={
            "docker-compose.yml": (
                "services:\n"
                "  a:\n    image: x\n    ports: ['8080:80']\n"
                "  b:\n    image: y\n    ports: ['8080:8080']\n"
            )
        },
    )

    flagged = findings_of(findings, "compose_port_conflict")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"
    assert "8080" in flagged[0].evidence[0]


def test_audit_does_not_report_port_conflict_within_one_service():
    """同一个服务里因为变量展开写成两遍，是冗余写法，不是冲突。"""
    findings = run_audit(
        compose_files={
            "docker-compose.yml": "services:\n  a:\n    image: x\n    ports: ['8080:80', '8080:80']\n"
        },
    )

    assert findings_of(findings, "compose_port_conflict") == []


def test_audit_reports_bad_port_format():
    findings = run_audit(
        compose_files={"docker-compose.yml": "services:\n  a:\n    image: x\n    ports: ['oops:80']\n"}
    )

    flagged = findings_of(findings, "compose_bad_port")
    assert len(flagged) == 1
    assert flagged[0].severity == "警告"


def test_audit_reports_undefined_interpolation():
    findings = run_audit(
        compose_files={
            "docker-compose.yml": "services:\n  a:\n    image: app:${TAG}\n"
        },
    )

    flagged = findings_of(findings, "compose_interpolation_undefined")
    assert len(flagged) == 1
    assert "TAG" in flagged[0].evidence[0]
    # 这个坑值得写进建议里：env_file 不参与插值
    assert "env_file" in flagged[0].hint


def test_audit_does_not_report_interpolation_with_default():
    findings = run_audit(
        compose_files={"docker-compose.yml": "services:\n  a:\n    image: app:${TAG:-latest}\n"},
    )

    assert findings_of(findings, "compose_interpolation_undefined") == []


def test_audit_does_not_report_interpolation_defined_in_sibling_env():
    findings = run_audit(
        compose_files={"docker-compose.yml": "services:\n  a:\n    image: app:${TAG}\n"},
        dotenv_files={".env": "TAG=v1\n"},
        gitignore=HEALTHY_GITIGNORE,
    )

    assert findings_of(findings, "compose_interpolation_undefined") == []


def test_audit_reports_missing_build_context():
    findings = run_audit(
        compose_files={"docker-compose.yml": HEALTHY_COMPOSE},
        present_files={"docker-compose.yml"},  # 连 backend 目录都没有
    )

    flagged = findings_of(findings, "compose_build_context_missing")
    assert len(flagged) == 1
    assert "backend → ./backend" in flagged[0].evidence[0]


def test_audit_reports_unparsable_compose():
    findings = run_audit(compose_files={"docker-compose.yml": "services:\n  a:\n   - [oops\n"})

    flagged = findings_of(findings, "compose_unparsable")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"


def test_audit_reports_deprecated_compose_version():
    findings = run_audit(
        compose_files={"docker-compose.yml": "version: '3.8'\nservices:\n  a:\n    image: x\n"}
    )

    flagged = findings_of(findings, "compose_deprecated_version")
    assert len(flagged) == 1
    assert flagged[0].severity == "提示"


def test_audit_sorts_severe_findings_first():
    findings = run_audit(
        dotenv_files={"backend/.env": "A=1\nBAD LINE\n"},
        compose_files={"docker-compose.yml": "services:\n  a:\n    ports: ['8080:80']\n  b:\n    image: y\n    ports: ['8080:80']\n"},
        gitignore=".env\n",
    )

    assert findings[0].severity == "严重"
    ranks = [cc._SEVERITY_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks)


# ══════════════════════════════════════════════════════════════════════════
# 7. check_startup —— compose 声明 vs 容器实际状态
# ══════════════════════════════════════════════════════════════════════════

RUNNING_BACKEND = {
    "Id": "aaaa",
    "Names": ["/agenthub-backend"],
    "State": "running",
    "Status": "Up 3 hours (healthy)",
    "Labels": {"com.docker.compose.service": "backend"},
    "Ports": [],
}
RUNNING_DB = {
    "Id": "bbbb",
    "Names": ["/agenthub-db"],
    "State": "running",
    "Status": "Up 3 hours (healthy)",
    "Labels": {"com.docker.compose.service": "db"},
    "Ports": [{"PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}],
}


def compose_of(text: str) -> cc.ComposeFile:
    return cc.parse_compose(text)


def test_check_startup_all_running_has_no_findings():
    compose = compose_of(HEALTHY_COMPOSE)

    findings = cc.check_startup(compose, [RUNNING_BACKEND, RUNNING_DB])

    assert findings == []


def test_check_startup_reports_service_without_container():
    compose = compose_of(HEALTHY_COMPOSE)

    findings = cc.check_startup(compose, [RUNNING_DB])

    flagged = findings_of(findings, "startup_container_missing")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"
    assert "backend" in flagged[0].evidence[0]
    # 只报了缺失的那个，没把在跑的 db 也算进去
    assert "db" not in flagged[0].evidence[0].split("：")[-1]


def test_check_startup_reports_exited_container_with_code():
    compose = compose_of("services:\n  worker:\n    image: w\n    container_name: legacy-worker\n")
    exited = {
        "Id": "cccc",
        "Names": ["/legacy-worker"],
        "State": "exited",
        "Status": "Exited (1) 2 hours ago",
        "Ports": [],
    }
    inspect = {
        "legacy-worker": {
            "State": {"Status": "exited", "ExitCode": 137, "OOMKilled": True},
            "RestartCount": 3,
        }
    }

    findings = cc.check_startup(compose, [exited], inspect=inspect)

    flagged = findings_of(findings, "startup_exited")
    assert len(flagged) == 1
    assert "legacy-worker" in flagged[0].evidence[0]
    assert "137" in flagged[0].evidence[0]
    # inspect 里的退出码优先于 Status 文本里的
    assert any("SIGKILL" in e for e in flagged[0].evidence)


def test_check_startup_falls_back_to_status_text_exit_code():
    compose = compose_of("services:\n  worker:\n    image: w\n    container_name: legacy-worker\n")
    exited = {
        "Id": "cccc",
        "Names": ["/legacy-worker"],
        "State": "exited",
        "Status": "Exited (2) 2 hours ago",
        "Ports": [],
    }

    findings = cc.check_startup(compose, [exited])

    assert "退出码 2" in findings_of(findings, "startup_exited")[0].evidence[0]


def test_check_startup_reports_restart_loop():
    compose = compose_of("services:\n  backend:\n    image: x\n    container_name: agenthub-backend\n")
    restarting = {
        "Id": "dddd",
        "Names": ["/agenthub-backend"],
        "State": "restarting",
        "Status": "Restarting (1) 5 seconds ago",
        "Ports": [],
    }

    findings = cc.check_startup(compose, [restarting])

    flagged = findings_of(findings, "startup_restart_loop")
    assert len(flagged) == 1
    assert flagged[0].severity == "严重"


def test_check_startup_reports_container_not_running_without_exit_code():
    compose = compose_of("services:\n  backend:\n    image: x\n    container_name: agenthub-backend\n")
    created = {
        "Id": "eeee",
        "Names": ["/agenthub-backend"],
        "State": "created",
        "Status": "Created",
        "Ports": [],
    }

    findings = cc.check_startup(compose, [created])

    assert len(findings_of(findings, "startup_container_not_running")) == 1


def test_check_startup_reports_dependency_not_running():
    compose = compose_of(
        "services:\n"
        "  backend:\n    image: x\n    container_name: agenthub-backend\n"
        "    depends_on:\n      - db\n"
        "  db:\n    image: y\n    container_name: agenthub-db\n"
    )
    stopped_db = dict(RUNNING_DB, State="exited", Status="Exited (0) 1 hour ago")

    findings = cc.check_startup(compose, [RUNNING_BACKEND, stopped_db])

    flagged = findings_of(findings, "startup_dependency_unavailable")
    assert len(flagged) == 1
    assert "backend 依赖 db" in flagged[0].evidence[0]


def test_check_startup_reports_unhealthy_dependency():
    compose = compose_of(
        "services:\n"
        "  backend:\n    image: x\n    container_name: agenthub-backend\n"
        "    depends_on:\n      - db\n"
        "  db:\n    image: y\n    container_name: agenthub-db\n"
    )
    sick_db = dict(RUNNING_DB, Status="Up 2 minutes (unhealthy)")

    findings = cc.check_startup(compose, [RUNNING_BACKEND, sick_db])

    flagged = findings_of(findings, "startup_dependency_unavailable")
    assert len(flagged) == 1
    assert "unhealthy" in flagged[0].evidence[0]


def test_check_startup_reports_port_taken_by_other_container():
    compose = compose_of(
        "services:\n  backend:\n    image: x\n    container_name: agenthub-backend\n"
        "    ports: ['8080:8080']\n"
    )
    squatter = {
        "Id": "ffff",
        "Names": ["/old-api"],
        "State": "running",
        "Status": "Up 5 hours",
        "Ports": [{"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
    }

    findings = cc.check_startup(compose, [RUNNING_BACKEND, squatter])

    flagged = findings_of(findings, "startup_port_taken")
    assert len(flagged) == 1
    assert "8080" in flagged[0].evidence[0]
    assert "old-api" in flagged[0].evidence[0]


def test_check_startup_ignores_port_held_by_the_service_itself():
    """服务自己占着自己的端口是正常的，不能报冲突。"""
    compose = compose_of(
        "services:\n  db:\n    image: y\n    container_name: agenthub-db\n    ports: ['5432:5432']\n"
    )

    findings = cc.check_startup(compose, [RUNNING_DB])

    assert findings_of(findings, "startup_port_taken") == []


def test_check_startup_returns_nothing_when_compose_unparsable():
    compose = compose_of("services:\n  a:\n   - [oops\n")

    assert cc.check_startup(compose, [RUNNING_BACKEND]) == []


@pytest.mark.parametrize(
    ("code", "keyword"),
    [(137, "SIGKILL"), (143, "SIGTERM"), (139, "段错误"), (1, "错误码 1"), (0, "正常退出")],
)
def test_exit_code_hint_covers_common_codes(code, keyword):
    assert keyword in cc._exit_code_hint(code)


def test_exit_code_hint_falls_back_for_unknown_code():
    assert "退出码 42" in cc._exit_code_hint(42)


# ── 容器匹配 ──────────────────────────────────────────────────────────────


def test_match_container_prefers_explicit_container_name():
    service = cc.ComposeService(name="backend", container_name="agenthub-backend")
    containers = [
        {"Id": "1", "Names": ["/other"], "Labels": {"com.docker.compose.service": "backend"}},
        {"Id": "2", "Names": ["/agenthub-backend"]},
    ]

    assert cc.match_container(service, containers)["Id"] == "2"


def test_match_container_falls_back_to_compose_label():
    service = cc.ComposeService(name="backend")
    containers = [{"Id": "1", "Names": ["/whatever-1"], "Labels": {"com.docker.compose.service": "backend"}}]

    assert cc.match_container(service, containers)["Id"] == "1"


@pytest.mark.parametrize("name", ["backend", "agenthub-backend-1", "agenthub_backend_1", "backend_1"])
def test_match_container_falls_back_to_generated_name(name):
    service = cc.ComposeService(name="backend")
    containers = [{"Id": "1", "Names": [f"/{name}"]}]

    assert cc.match_container(service, containers)["Id"] == "1"


def test_match_container_does_not_confuse_similar_names():
    service = cc.ComposeService(name="backend")
    containers = [{"Id": "1", "Names": ["/backend-worker-1"]}]

    assert cc.match_container(service, containers) is None


def test_container_name_of_strips_leading_slash():
    assert cc.container_name_of({"Names": ["/api"]}) == "api"
    # 没有 Names 时退回用短 ID（12 位），不能把整串 ID 塞进报告
    assert cc.container_name_of({"Id": "0123456789abcdef"}) == "0123456789ab"


# ══════════════════════════════════════════════════════════════════════════
# 8. check_config 工具
# ══════════════════════════════════════════════════════════════════════════


def test_check_config_healthy_project(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = healthy_project(tmp_path / "app")

    report = check_config.invoke({"path": str(project)})

    assert "【配置检查】" in report
    assert "总体状态：正常" in report
    assert "backend/.env" in report
    assert "docker-compose.yml" in report
    assert "已拒绝" not in report


def test_check_config_reports_missing_key(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "MODE=dev\n",
            "backend/.env.example": "MODE=dev\nPOSTGRES_HOST=localhost\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "总体状态：异常" in report
    assert "必需配置缺失" in report
    assert "POSTGRES_HOST" in report


def test_check_config_marks_facts_and_guesses(configure_ops, tmp_path):
    """报告里必须把"查到的"和"猜的"分开写。"""
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "MODE=dev\n",
            "backend/.env.example": "MODE=dev\nPOSTGRES_HOST=localhost\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "【已证实】证据：" in report
    assert "【推测】可能原因：" in report
    assert "处理建议：" in report


def test_check_config_report_never_contains_secret_values(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": f"LLM_API_KEY={REAL_SECRET}\nMODE=dev\n",
            "backend/.env.example": f"LLM_API_KEY={REAL_SECRET}\nMODE=dev\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert REAL_SECRET not in report
    assert REAL_SECRET[:20] not in report
    # 但要让人知道"这里有个密钥，已经藏起来了"
    assert "LLM_API_KEY" in report


def test_check_config_lists_hidden_secret_count(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "MODE=dev\nJWT_SECRET_KEY=abc\nPOSTGRES_PASSWORD=def\n",
            "backend/.env.example": "MODE=dev\nJWT_SECRET_KEY=\nPOSTGRES_PASSWORD=\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "2 个密钥类变量的值已隐藏" in report


def test_check_config_previews_non_secret_values(configure_ops, tmp_path):
    """非密钥的值要显示 —— POSTGRES_HOST=localhost 这种错误只看键名发现不了。"""
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "MODE=dev\nPOSTGRES_HOST=localhost\n",
            "backend/.env.example": "MODE=dev\nPOSTGRES_HOST=localhost\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "POSTGRES_HOST=localhost" in report


def test_check_config_rejects_path_outside_roots(configure_ops, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    configure_ops(roots=[allowed])

    report = check_config.invoke({"path": str(tmp_path / "elsewhere")})

    assert "已拒绝" in report
    assert "OPS_PROJECT_ROOTS" in report


def test_check_config_rejects_traversal(configure_ops, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    configure_ops(roots=[allowed])

    report = check_config.invoke({"path": str(allowed / ".." / ".." / "etc")})

    assert "已拒绝" in report


def test_check_config_refuses_when_no_roots_configured(configure_ops, tmp_path):
    configure_ops(roots=[])

    report = check_config.invoke({"path": str(tmp_path)})

    assert "已拒绝" in report
    assert "OPS_PROJECT_ROOTS 为空" in report


def test_check_config_rejects_control_characters_in_path(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])

    report = check_config.invoke({"path": f"{tmp_path}\x00/etc"})

    assert "已拒绝" in report


def test_check_config_missing_directory(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])

    report = check_config.invoke({"path": str(tmp_path / "nope")})

    assert "总体状态：异常" in report
    assert "目录不存在" in report


def test_check_config_path_is_a_file(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    target = tmp_path / "somefile.txt"
    target.write_text("x", encoding="utf-8")

    report = check_config.invoke({"path": str(target)})

    assert "不是目录" in report


def test_check_config_reports_project_without_config_files(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = write_configs(tmp_path / "app", {"README.md": "# hi\n"})

    report = check_config.invoke({"path": str(project)})

    assert "未找到 .env / docker-compose.yml" in report


def test_check_config_scans_nested_directories(configure_ops, tmp_path):
    """AgentHub 把 .env 放在 backend/ 和 frontend/，必须往下扫一层。"""
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "MODE=dev\n",
            "backend/.env.example": "MODE=dev\n",
            "frontend/.env": "VITE_API=x\n",
            "frontend/.env.example": "VITE_API=x\n",
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "backend/.env" in report
    assert "frontend/.env" in report


def test_check_config_reports_compose_env_file_missing(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = write_configs(
        tmp_path / "app",
        {".gitignore": HEALTHY_GITIGNORE, "docker-compose.yml": HEALTHY_COMPOSE,
         "backend/Dockerfile": "FROM x\n"},
    )

    report = check_config.invoke({"path": str(project)})

    assert "Compose 引用的配置文件不存在" in report
    assert "backend/.env" in report


def test_check_config_skips_oversized_file(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path], config_max_file_kb=8)
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "backend/.env": "A=1\n" + "# padding\n" * 2000,
        },
    )

    report = check_config.invoke({"path": str(project)})

    assert "超过" in report
    assert "读取上限" in report


def test_check_config_notes_non_utf8_file(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path])
    project = tmp_path / "app"
    (project / "backend").mkdir(parents=True)
    (project / ".gitignore").write_text(HEALTHY_GITIGNORE, encoding="utf-8")
    (project / "backend" / ".env").write_bytes("MODE=开发\n".encode("gbk"))

    report = check_config.invoke({"path": str(project)})

    assert "不是合法的 UTF-8 编码" in report


def test_check_config_survives_audit_exception(configure_ops, tmp_path, monkeypatch):
    """分析器内部炸了也要返回可读报告，不能把异常抛给模型。"""
    configure_ops(roots=[tmp_path])
    project = healthy_project(tmp_path / "app")

    def boom(**kwargs):
        raise RuntimeError("模拟内部错误")

    monkeypatch.setattr("app.agents.tools.ops.audit", boom)

    report = check_config.invoke({"path": str(project)})

    assert "总体状态：检查失败" in report
    assert "模拟内部错误" in report


def test_check_config_output_is_truncated(configure_ops, tmp_path):
    """结论多到超过字符预算时必须截断，并明确告诉调用方截断了。"""
    configure_ops(roots=[tmp_path], config_max_chars=1000)
    files = {".gitignore": HEALTHY_GITIGNORE}
    for i in range(12):
        # 每个子目录一个格式坏掉的 .env → 12 条独立结论，报告必然超预算
        files[f"svc{i}/.env"] = "NOT A VALID LINE\n"
    project = write_configs(tmp_path / "app", files)

    report = check_config.invoke({"path": str(project)})

    assert "输出已截断" in report


# ══════════════════════════════════════════════════════════════════════════
# 9. diagnose_startup 工具
# ══════════════════════════════════════════════════════════════════════════


def compose_project(root: Path, compose_text: str = HEALTHY_COMPOSE) -> Path:
    return write_configs(
        root,
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "docker-compose.yml": compose_text,
            "backend/.env": HEALTHY_ENV,
            "backend/.env.example": HEALTHY_EXAMPLE,
            "backend/Dockerfile": "FROM python:3.12\n",
        },
    )


async def test_diagnose_startup_ok_when_services_running(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = compose_project(tmp_path / "app")

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "【启动问题分析】" in report
    assert "总体状态：正常" in report
    assert "✓ backend → agenthub-backend" in report
    assert "✓ db → agenthub-db" in report


async def test_diagnose_startup_flags_service_without_container(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = compose_project(
        tmp_path / "app",
        "services:\n  ghost:\n    image: x\n    container_name: not-there\n",
    )

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "总体状态：异常" in report
    assert "服务未启动" in report
    assert "ghost" in report
    assert "✗ ghost → 没有对应容器" in report


async def test_diagnose_startup_reports_exit_code_from_inspect(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = compose_project(
        tmp_path / "app",
        "services:\n  worker:\n    image: w\n    container_name: legacy-worker\n",
    )

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "容器已退出" in report
    assert "退出码 1" in report  # 来自假 inspect 路由
    assert "legacy-worker" in report
    # 指向下一步：看日志
    assert "check_container_logs" in report


async def test_diagnose_startup_reports_port_taken(configure_ops, tmp_path, docker_api):
    socket, state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    state["containers"] = [
        RUNNING_BACKEND,
        RUNNING_DB,
        {
            "Id": "ffff",
            "Names": ["/old-api"],
            "State": "running",
            "Status": "Up 5 hours",
            "Ports": [{"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
        },
    ]
    project = compose_project(tmp_path / "app")

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "宿主机端口已被占用" in report
    assert "old-api" in report


DEPENDS_COMPOSE = """\
services:
  backend:
    image: agenthub-backend
    container_name: agenthub-backend
    depends_on:
      - db
  db:
    image: postgres:18
    container_name: agenthub-db
"""


async def test_diagnose_startup_reports_dependency_down(configure_ops, tmp_path, docker_api):
    socket, state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    state["containers"] = [
        RUNNING_BACKEND,
        dict(RUNNING_DB, State="exited", Status="Exited (0) 1 hour ago"),
    ]
    project = compose_project(tmp_path / "app", DEPENDS_COMPOSE)

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "依赖服务不可用" in report
    assert "backend 依赖 db" in report


async def test_diagnose_startup_includes_config_findings(configure_ops, tmp_path, docker_api):
    """配置层面的问题也要出现在启动分析里。"""
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "docker-compose.yml": HEALTHY_COMPOSE,
            "backend/.env": "MODE=dev\n",  # 少了一堆键
            "backend/.env.example": HEALTHY_EXAMPLE,
            "backend/Dockerfile": "FROM x\n",
        },
    )

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "总体状态：异常" in report
    assert "必需配置缺失" in report
    assert "POSTGRES_HOST" in report


async def test_diagnose_startup_explains_where_each_finding_came_from(
    configure_ops, tmp_path, docker_api
):
    """同时有"容器状态"和"配置"两类结论时，要说明哪几条是哪来的。"""
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            # ghost 在 Docker 里没有容器 → 1 条启动类结论
            # .env 缺键            → 1 条配置类结论
            "docker-compose.yml": "services:\n  ghost:\n    image: x\n    container_name: gone\n",
            "backend/.env": "MODE=dev\n",
            "backend/.env.example": HEALTHY_EXAMPLE,
        },
    )

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "服务未启动" in report
    assert "必需配置缺失" in report
    assert "前 1 条来自容器实际状态" in report
    assert "后 1 条来自配置文件的静态检查" in report


async def test_diagnose_startup_without_docker_socket(configure_ops, tmp_path):
    configure_ops(roots=[tmp_path], socket="/nonexistent/docker.sock")
    project = compose_project(tmp_path / "app")

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "无法分析容器状态" in report
    assert "只来自配置文件" in report
    assert "docker.sock" in report


async def test_diagnose_startup_handles_docker_unavailable(configure_ops, tmp_path):
    """socket 文件存在但没人应答 —— 要区分于"socket 不存在"。"""
    bogus = tmp_path / "dead.sock"
    bogus.write_text("", encoding="utf-8")
    configure_ops(roots=[tmp_path], socket=str(bogus))
    project = compose_project(tmp_path / "app")

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "无法分析容器状态" in report


async def test_diagnose_startup_without_compose_file(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = write_configs(tmp_path / "app", {"README.md": "# hi\n"})

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "没有 docker-compose.yml" in report
    assert "check_docker" in report


async def test_diagnose_startup_rejects_path_outside_roots(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    configure_ops(roots=[allowed], socket=socket)

    report = await diagnose_startup.ainvoke({"path": str(tmp_path / "elsewhere")})

    assert "已拒绝" in report


async def test_diagnose_startup_rejects_missing_directory(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)

    report = await diagnose_startup.ainvoke({"path": str(tmp_path / "nope")})

    assert "已拒绝" in report
    assert "目录不存在" in report


async def test_diagnose_startup_defaults_to_first_allowed_root(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    compose_project(tmp_path)

    report = await diagnose_startup.ainvoke({})

    assert "【启动问题分析】" in report
    assert "总体状态" in report


async def test_diagnose_startup_without_roots_lists_them(configure_ops):
    configure_ops(roots=[])

    report = await diagnose_startup.ainvoke({})

    assert "OPS_PROJECT_ROOTS" in report


async def test_diagnose_startup_never_leaks_secrets(configure_ops, tmp_path, docker_api):
    socket, _state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    project = write_configs(
        tmp_path / "app",
        {
            ".gitignore": HEALTHY_GITIGNORE,
            "docker-compose.yml": HEALTHY_COMPOSE,
            "backend/.env": f"LLM_API_KEY={REAL_SECRET}\nMODE=dev\n",
            "backend/.env.example": f"LLM_API_KEY={REAL_SECRET}\nMODE=dev\n",
            "backend/Dockerfile": "FROM x\n",
        },
    )

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert REAL_SECRET not in report
    assert REAL_SECRET[:20] not in report


async def test_diagnose_startup_notes_inspect_limit(configure_ops, tmp_path, docker_api):
    """停了很多容器时，只 inspect 前几个，并且**说明**这一点。"""
    socket, state = docker_api
    configure_ops(roots=[tmp_path], socket=socket)
    state["containers"] = [
        {"Id": f"dead{i}", "Names": [f"/dead-{i}"], "State": "exited",
         "Status": "Exited (1) 1 hour ago", "Ports": []}
        for i in range(9)
    ]
    project = compose_project(tmp_path / "app")

    report = await diagnose_startup.ainvoke({"path": str(project)})

    assert "只额外查询了前 6 个" in report


# ══════════════════════════════════════════════════════════════════════════
# 9.5 验收回归 —— 代码审查确认的缺陷，逐条钉住
# ══════════════════════════════════════════════════════════════════════════


def test_parse_compose_survives_deeply_nested_yaml():
    """500 层嵌套会让 PyYAML 抛 ``RecursionError``，**不是** ``yaml.YAMLError``。

    实测约 1KB 就能触发，远低于 ``OPS_CONFIG_MAX_FILE_KB`` 上限 ——
    不单独接住的话，一份畸形 compose 就能让整个工具以原始异常结束。
    """
    nested = "a: " + "[" * 500 + "]" * 500

    parsed = cc.parse_compose(nested, label="docker-compose.yml")

    assert parsed.problems
    assert "嵌套层级过深" in parsed.problems[0]
    assert parsed.services == {}


def test_parse_dotenv_never_echoes_non_keyvalue_line():
    """没有 ``=`` 的行无法判断是不是密钥，所以只报行号和长度、不回显内容。"""
    parsed = cc.parse_dotenv("my-secret-token: abc123\n", label="backend/.env")

    assert len(parsed.problems) == 1
    problem = parsed.problems[0]
    assert "第 1 行" in problem
    assert "长度" in problem
    assert "my-secret-token" not in problem
    assert "abc123" not in problem


def test_parse_dotenv_never_echoes_private_key_body():
    """PEM 私钥上下两行没有 ``=``，会被当成"格式错误行"，绝不能原文回显。"""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    parsed = cc.parse_dotenv(pem, label="backend/.env")
    joined = "\n".join(parsed.problems)

    assert len(parsed.problems) == 2
    assert "PRIVATE KEY" not in joined
    assert "-----" not in joined


def test_parse_dotenv_never_echoes_invalid_key_name():
    """键名不合法时同样不回显 —— base64 正文行会走到这个分支。"""
    parsed = cc.parse_dotenv("1BADKEY=whatever\n", label="backend/.env")

    assert parsed.problems
    assert "键名不合法" in parsed.problems[0]
    assert "1BADKEY" not in parsed.problems[0]
    assert "长度 7" in parsed.problems[0]


def test_find_interpolations_treats_error_operator_as_no_default():
    """``:?`` / ``?`` 是"未定义就报错"，不是兜底默认值 —— 正是最该报的那类。"""
    found = cc.find_interpolations(
        "a: ${MUST_HAVE:?缺少就报错}\nb: ${OK:-fallback}\nc: ${PLAIN}\n"
    )

    assert found["MUST_HAVE"] is False
    assert found["OK"] is True
    assert found["PLAIN"] is False


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("8080:80", 8080),
        ("127.0.0.1:8080:80", 8080),
        ("[::1]:8080:80", 8080),
        ("[::]:9000:80", 9000),
    ],
)
def test_parse_port_entry_accepts_ipv6_host(entry, expected):
    """IPv6 宿主机要写成 ``[::1]``，冒号在方括号里，不能按冒号硬切。"""
    port, problem = cc._parse_port_entry(entry)

    assert port == expected
    assert problem == ""


def test_parse_port_entry_rejects_unclosed_ipv6_bracket():
    port, problem = cc._parse_port_entry("[::1:8080:80")

    assert port is None
    assert "右方括号" in problem


@pytest.mark.parametrize(
    "pattern",
    ["prod.env", "config/prod.env", "*.env.example", ".env.*", "node_modules/"],
)
def test_gitignore_patterns_that_do_not_cover_env(pattern):
    """这些写法盖不住 ``.env``，不能算"已忽略" —— 漏报比误报危险。"""
    assert cc._gitignore_covers_env(f"{pattern}\n") is False


def test_check_config_skips_symlink_pointing_outside_root(configure_ops, tmp_path):
    """根目录里指向外部的软链接，不能把白名单之外的 .env 读进来。"""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".env").write_text("LEAKED_TOKEN=should-not-be-read\n", encoding="utf-8")

    link = root / "proj"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:  # pragma: no cover - 平台不允许建软链接
        pytest.skip("当前平台不允许创建目录软链接")

    configure_ops(roots=[root])

    report = check_config.invoke({"path": str(root)})

    assert "should-not-be-read" not in report
    # 软链接本身也要在报告里说明被跳过了，而不是静默消失
    assert "指向项目根目录之外" in report


# ══════════════════════════════════════════════════════════════════════════
# 10. 工具注册与 Agent 集成
# ══════════════════════════════════════════════════════════════════════════


def test_config_tools_are_registered_in_ops_tools():
    names = [t.name for t in OPS_TOOLS]

    assert "check_config" in names
    assert "diagnose_startup" in names
    assert names == [
        "check_project",
        "check_docker",
        "check_service",
        "check_container_logs",
        "check_config",
        "diagnose_startup",
    ]


def test_config_tools_are_importable_from_package():
    from app.agents.tools import __all__ as exported

    assert "check_config" in exported
    assert "diagnose_startup" in exported


def test_config_tools_have_chinese_descriptions():
    """描述会直接进提示词，必须是中文且提到"只读"。"""
    for tool in (check_config, diagnose_startup):
        assert "只读" in tool.description
        assert "path" in tool.args


async def test_config_tools_are_registered_on_agent(monkeypatch):
    """``init_agent()`` 必须把这两个工具真的交给 ``create_agent()``。"""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    from app.agents import supervisor
    from app.infra import config as config_module

    captured: dict = {}

    monkeypatch.setattr(
        supervisor, "create_agent", lambda **kw: captured.update(kw) or object()
    )
    monkeypatch.setattr(supervisor, "_agent_instance", None)
    monkeypatch.setattr(
        "app.infra.llm.get_system_llm",
        lambda: GenericFakeChatModel(messages=iter([AIMessage(content="ok")])),
    )
    monkeypatch.setattr(
        config_module, "get_settings", lambda: type("S", (), {"OPS_ENABLED": True})()
    )

    await supervisor.init_agent(checkpointer=None, store=None)

    names = {t.name for t in captured["tools"]}
    assert {"check_config", "diagnose_startup"} <= names
