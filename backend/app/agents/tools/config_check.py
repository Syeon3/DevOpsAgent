"""配置文件检查引擎 —— 纯函数，不做任何 I/O。

和 ``log_analysis.py`` 一样，把"纯逻辑"从 ``ops.py`` 里拆出来：

- 本模块只接收**已经读进来的文本**（``.env``、``docker-compose.yml``、
  ``.gitignore``）和 Docker 返回的 JSON，返回结构化结论；
- ``ops.py`` 负责 I/O（读文件、限制路径、调 Docker API）和脱敏。

好处是这些解析和判定逻辑可以脱离文件系统单独做单元测试。

三件事：

1. ``parse_dotenv`` —— 解析 ``.env`` / ``.env.example``，同时把"格式可疑"的行挑出来。
2. ``parse_compose`` —— 解析 compose 文件，抽出启动分析需要的字段
   （服务、镜像 / 构建、端口、依赖、env_file、健康检查）。
3. ``audit`` / ``check_startup`` —— 交叉比对，产出中文问题清单。

贯穿全模块的一条硬规则
----------------------
**密钥的值绝不进入返回值。** 凡是名字像密钥的键
（``*_KEY`` / ``*_SECRET`` / ``*_TOKEN`` / ``*_PASSWORD`` …），返回值里只保留
"已设置 / 未设置 / 为空"和值的**长度**，值本身一律丢弃。这不是靠渲染层
"记得别打印"，而是从数据源头就不给出可泄露的东西 —— 见 ``DotenvFile.safe_items``。
"""

import posixpath
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - PyYAML 是 langchain-core 的传递依赖，正常环境一定在
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# PyYAML 是否可用。不可用时 compose 相关的检查会降级成一条明确提示，
# 而不是让整个工具抛异常。
YAML_AVAILABLE = yaml is not None


# ── 数量 / 长度上限（防止一份畸形配置把报告撑爆）────────────────────────────

_MAX_EVIDENCE_ITEMS = 12  # 一条结论最多列几个具体项（键名 / 文件 / 服务）
_EVIDENCE_MAX_LEN = 160  # 每条证据最多显示多少字符

# 排序用的严重程度权重，数字越小越靠前。与 log_analysis 保持一致。
_SEVERITY_RANK = {"严重": 0, "警告": 1, "提示": 2}


def _clip(text: str, limit: int = _EVIDENCE_MAX_LEN) -> str:
    """截断过长的一行证据，并抹掉换行符（避免证据里夹带伪段落）。"""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else f"{text[:limit]}…"


def _head(items: Collection[str], limit: int = _MAX_EVIDENCE_ITEMS) -> str:
    """把若干项拼成一行证据，超出上限时写明省略了多少项。"""
    ordered = sorted(items)
    shown = ordered[:limit]
    text = "、".join(_clip(x) for x in shown)
    if len(ordered) > limit:
        text += f" …（另有 {len(ordered) - limit} 项）"
    return text


# ── 1. 哪些键算"密钥" ───────────────────────────────────────────────────────

# 判断方式：把键名按 ``_`` / ``-`` / ``.`` 切开，任一段命中下面这张表就算密钥。
# 用"分段"而不是子串匹配，是为了避免 ``MONKEY_COUNT`` 这类误判。
_SENSITIVE_WORDS = frozenset(
    {
        "AUTH",
        "AUTHORIZATION",
        "BEARER",
        "CREDENTIAL",
        "CREDENTIALS",
        "DSN",
        "KEY",
        "KEYS",
        "PASSWD",
        "PASSWORD",
        "PASSWORDS",
        "PRIVATE",
        "PWD",
        "SALT",
        "SECRET",
        "SECRETS",
        "TOKEN",
        "TOKENS",
    }
)

_KEY_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def is_sensitive_key(name: str) -> bool:
    """键名是否包含"像密钥"的单词。

    保守起见宁可多判：多藏一个普通变量只是少了一点信息，
    少藏一个密钥就是真的泄密。返回值只用于决定"要不要显示值"，
    不影响任何检查逻辑。
    """
    parts = {p.upper() for p in _KEY_SPLIT_RE.split(name or "") if p}
    return bool(parts & _SENSITIVE_WORDS)


# ── 2. .env 解析 ────────────────────────────────────────────────────────────

# 合法键名：字母或下划线开头，后面是字母 / 数字 / 下划线 / 点。
# 注意不能有 ``-``，那在 dotenv 里不是合法变量名。
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

# 值的占位符特征：命中任意一个就认为"这里本来就该由使用者替换"。
_PLACEHOLDER_HINTS = (
    "<",
    "***",
    "...",
    "change-this",
    "change_me",
    "change-me",
    "changeme",
    "change_this",
    "dummy",
    "example",
    "fake",
    "none",
    "null",
    "placeholder",
    "redacted",
    "replace-me",
    "replace_me",
    "sample",
    "sometoken",
    "todo",
    "your-",
    "your_",
    "yourkey",
)

# 真实密钥的常见前缀。命中说明这是**真的**凭证，不是占位符。
_REAL_SECRET_RE = re.compile(
    r"^(?:sk-[A-Za-z0-9_-]{16,}"
    r"|sk_live_[A-Za-z0-9]{16,}"
    r"|rk_live_[A-Za-z0-9]{16,}"
    r"|lsv2_[A-Za-z0-9_]{16,}"
    r"|tvly-[A-Za-z0-9-]{16,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)"
)

# 文件名：模板类（会进版本库，值不该是真凭证）。
_TEMPLATE_NAME_RE = re.compile(r"\.env\.(?:example|sample|template|dist|tmpl)$", re.I)
# 文件名：实际生效的配置。
_ACTUAL_NAME_RES = (
    re.compile(r"^\.env$"),
    re.compile(r"^\.env\.(?:local|dev|development|prod|production|test|staging)$", re.I),
)


def _looks_like_placeholder(value: str) -> bool:
    """值看起来是"等待使用者替换的占位符"吗？"""
    low = value.lower()
    return any(hint in low for hint in _PLACEHOLDER_HINTS)


def is_template_name(label: str) -> bool:
    """``.env.example`` 这类"提交进版本库的模板"文件。"""
    return bool(_TEMPLATE_NAME_RE.search(posixpath.basename(label)))


def is_actual_env_name(label: str) -> bool:
    """``.env`` / ``.env.local`` 这类"真正生效的配置"文件。"""
    base = posixpath.basename(label)
    return any(r.search(base) for r in _ACTUAL_NAME_RES)


@dataclass(frozen=True)
class DotenvFile:
    """一个 dotenv 文件的解析结果。"""

    label: str
    values: dict[str, str] = field(default_factory=dict)
    """键 -> 值。**包含密钥的真值**，仅供本模块内部判断"空 / 占位符"用。"""

    order: tuple[str, ...] = ()
    """键出现的先后顺序（报告里按这个顺序列，读起来更像原文件）。"""

    duplicates: tuple[str, ...] = ()
    """重复定义过的键（后面的定义会覆盖前面的）。"""

    problems: tuple[str, ...] = ()
    """格式问题，已经是可直接展示的中文句子。"""

    def safe_items(self) -> list[tuple[str, str]]:
        """只返回**可以安全展示**的 ``(键, 值)``。

        密钥类的键，值一律换成 ``"***"`` —— 这样即使调用方想打印，
        也打印不出真东西。渲染报告的地方必须走这个方法。
        """
        out: list[tuple[str, str]] = []
        for key in self.order:
            value = self.values.get(key, "")
            if is_sensitive_key(key):
                out.append((key, "***" if value else ""))
            else:
                out.append((key, value))
        return out

    def empty_keys(self) -> list[str]:
        """值为空的键（``KEY=`` 或者只有空白）。"""
        return [k for k in self.order if not self.values.get(k, "").strip()]

    def sensitive_keys_with_real_value(self) -> list[tuple[str, str]]:
        """敏感键中"值不像占位符"的那些，返回 ``(键, 值)``。

        调用方**只能**用键名和 ``len(值)``，不得把值写进报告。
        """
        out: list[tuple[str, str]] = []
        for key in self.order:
            value = self.values.get(key, "").strip()
            if not value or not is_sensitive_key(key):
                continue
            if _looks_like_placeholder(value):
                continue
            out.append((key, value))
        return out


def parse_dotenv(text: str, *, label: str = ".env") -> DotenvFile:
    """解析 dotenv 文本，顺带记录格式问题。

    支持 ``export KEY=value``、单/双引号、行内 ``#`` 注释和空行 / 注释行。
    写不出结论的地方**不猜**：例如引号不配对时只报告问题，值按原样保留。

    注意这里只做**语法**解析，不判断"这个键该不该有"——那是 ``audit`` 的事。
    """
    values: dict[str, str] = {}
    order: list[str] = []
    duplicates: list[str] = []
    problems: list[str] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # ``export FOO=bar`` —— shell 风格，dotenv 也认。
        if stripped.startswith("export ") or stripped.startswith("export\t"):
            stripped = stripped[len("export") :].lstrip()

        if "=" not in stripped:
            problems.append(f"第 {number} 行不是 KEY=VALUE 形式，这一行会被忽略：{_clip(stripped)}")
            continue

        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()

        if not key:
            problems.append(f"第 {number} 行缺少键名（= 左边是空的）。")
            continue
        if not _ENV_KEY_RE.match(key):
            problems.append(
                f"第 {number} 行的键名不合法：{_clip(key)}"
                "（只允许字母、数字、下划线、点，且不能以数字开头）。"
            )

        # 处理引号：成对的引号整体去掉，只留内容。
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            if value[:1] in ("'", '"'):
                problems.append(
                    f"第 {number} 行 {key} 的值引号没有闭合，解析结果可能不是预期的。"
                )
            # 未加引号时才把 `` #`` 之后当注释（加了引号的 # 是值的一部分）。
            comment = value.find(" #")
            if comment != -1:
                value = value[:comment].rstrip()

        if key in values:
            if key not in duplicates:
                duplicates.append(key)
        else:
            order.append(key)
        values[key] = value

    return DotenvFile(
        label=label,
        values=values,
        order=tuple(order),
        duplicates=tuple(duplicates),
        problems=tuple(problems),
    )


# ── 3. compose 解析 ─────────────────────────────────────────────────────────

# ``${VAR}`` / ``${VAR:-默认}`` / ``${VAR:?错误}`` / ``$VAR``
_INTERP_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?([-?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

# 端口写法里允许出现的东西：``8080``、``8080-8090``、以及变量占位。
_PORT_HOST_RE = re.compile(r"^(\d{1,5})(?:-\d{1,5})?$")


def find_interpolations(text: str) -> dict[str, bool]:
    """找出 compose 文本里的 ``${VAR}``，返回 ``变量名 -> 是否带默认值``。

    带 ``:-`` / ``-`` 默认值的变量，即使环境里没有也能启动；
    不带的会被 Compose 替换成空字符串 —— 这个区别是判断"配置缺失"的关键。
    """
    found: dict[str, bool] = {}
    for match in _INTERP_RE.finditer(text or ""):
        name = match.group(1) or match.group(4)
        if not name:
            continue
        has_default = bool(match.group(1)) and match.group(2) is not None
        # 同一个变量出现多次时，只要有一次带默认值就算"有兜底"。
        found[name] = found.get(name, False) or has_default
    return found


@dataclass(frozen=True)
class ComposeService:
    """compose 里一个服务的、与"能不能起来"有关的字段。"""

    name: str
    image: str = ""
    build_context: str = ""
    container_name: str = ""
    ports: tuple[str, ...] = ()
    host_ports: tuple[int, ...] = ()
    env_file: tuple[str, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    restart: str = ""
    has_healthcheck: bool = False

    def has_build_or_image(self) -> bool:
        return bool(self.image or self.build_context)


@dataclass(frozen=True)
class ComposeFile:
    """一个 compose 文件的解析结果。"""

    label: str
    services: dict[str, ComposeService] = field(default_factory=dict)
    problems: tuple[str, ...] = ()
    interpolations: dict[str, bool] = field(default_factory=dict)
    deprecated_version_key: bool = False

    def depends_on_healthy(self) -> list[tuple[str, str]]:
        """返回 ``(服务, 依赖的服务)``，条件是依赖写了 ``condition: service_healthy``。"""
        return [
            (svc.name, dep)
            for svc in self.services.values()
            for dep in svc.depends_on
        ]


def _as_str_list(value: Any) -> list[str]:
    """把 compose 里"可以是字符串也可以是列表"的字段统一成字符串列表。"""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(k) for k in value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _parse_port_entry(entry: str) -> tuple[int | None, str]:
    """从一条 ``ports`` 条目里取出**宿主机端口**。

    返回 ``(端口, 问题说明)``。取不到且确认是格式错误时，第二个元素非空。
    含 ``${...}`` 的条目是"运行时才知道"，不算错误，直接跳过（不猜）。
    """
    text = entry.strip()
    if not text:
        return None, "端口映射是空字符串。"
    if "${" in text or "$" in text:
        return None, ""  # 变量插值，运行期才能确定，不猜

    parts = text.split(":")
    if len(parts) == 1:  # "8080" —— 只写容器端口，宿主端口随机
        return None, ""
    if len(parts) > 3:
        return None, f"端口映射 {_clip(text)} 的格式无法识别（冒号太多）。"

    host = parts[-2].strip()
    # 长格式里的 protocol 有时会跟在后面，正常情况不会有。
    match = _PORT_HOST_RE.match(host)
    if not match:
        return None, f"端口映射 {_clip(text)} 的宿主机端口不是合法数字：{_clip(host)}"
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        return None, f"端口映射 {_clip(text)} 的宿主机端口超出 1~65535：{port}"
    return port, ""


def _service_from_mapping(name: str, raw: Mapping[str, Any]) -> ComposeService:
    """把一个服务的原始 mapping 转成 ``ComposeService``。"""
    image = str(raw.get("image") or "")
    build = raw.get("build")
    build_context = ""
    if isinstance(build, str):
        build_context = build
    elif isinstance(build, Mapping):
        build_context = str(build.get("context") or ".")

    ports = tuple(_as_str_list(raw.get("ports")))
    host_ports: list[int] = []
    for entry in ports:
        port, _problem = _parse_port_entry(entry)
        if port is not None:
            host_ports.append(port)

    # env_file 有三种写法：单个字符串、字符串列表，以及长格式
    # ``[{path: .env, required: false}]``（Compose 2.24+）。三种都要认，
    # 否则会漏报"env_file 指向的文件不存在"。
    env_file: list[str] = []
    env_raw_files = raw.get("env_file")
    if isinstance(env_raw_files, str):
        env_file.append(env_raw_files)
    elif isinstance(env_raw_files, (list, tuple)):
        for item in env_raw_files:
            if isinstance(item, Mapping):
                path = item.get("path")
                if path:
                    env_file.append(str(path))
            elif item is not None:
                env_file.append(str(item))

    environment: dict[str, str] = {}
    env_raw = raw.get("environment")
    if isinstance(env_raw, Mapping):
        for key, value in env_raw.items():
            # ``FOO:`` （值为 null）表示"从宿主机环境透传"，没有具体值。
            environment[str(key)] = "" if value is None else str(value)
    elif isinstance(env_raw, (list, tuple)):
        for item in env_raw:
            key, _, value = str(item).partition("=")
            environment[key.strip()] = value

    return ComposeService(
        name=name,
        image=image,
        build_context=build_context,
        container_name=str(raw.get("container_name") or ""),
        ports=ports,
        host_ports=tuple(host_ports),
        env_file=tuple(env_file),
        environment=environment,
        depends_on=tuple(_as_str_list(raw.get("depends_on"))),
        restart=str(raw.get("restart") or ""),
        has_healthcheck=bool(raw.get("healthcheck")),
    )


def parse_compose(text: str, *, label: str = "docker-compose.yml") -> ComposeFile:
    """解析 compose 文本，抽出服务定义和与启动有关的字段。

    只用 ``yaml.safe_load`` —— compose 文件是被检查的对象，可能是别人写的，
    绝不能用 ``yaml.load``（那会允许文件里构造任意 Python 对象）。

    解析失败不会抛异常：问题写进 ``problems``，``services`` 留空，
    上层据此给出"配置文件本身有问题"的结论。
    """
    interpolations = find_interpolations(text)
    problems: list[str] = []

    if not YAML_AVAILABLE:  # pragma: no cover - 正常环境不会走到
        return ComposeFile(
            label=label,
            problems=("服务端缺少 PyYAML，无法解析 compose 文件（请安装 pyyaml 后重启）。",),
            interpolations=interpolations,
        )

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"第 {mark.line + 1} 行第 {mark.column + 1} 列" if mark else "位置未知"
        detail = getattr(exc, "problem", None) or str(exc)
        return ComposeFile(
            label=label,
            problems=(f"YAML 解析失败（{where}）：{_clip(detail)}",),
            interpolations=interpolations,
        )

    if data is None:
        return ComposeFile(
            label=label,
            problems=("compose 文件是空的，没有任何服务定义。",),
            interpolations=interpolations,
        )
    if not isinstance(data, Mapping):
        return ComposeFile(
            label=label,
            problems=("compose 文件的顶层结构不是键值映射（mapping）。",),
            interpolations=interpolations,
        )

    deprecated = "version" in data
    raw_services = data.get("services")
    if raw_services is None:
        problems.append("compose 文件里没有 services 段，无法启动任何服务。")
        raw_services = {}
    elif not isinstance(raw_services, Mapping):
        problems.append("services 段的结构不是键值映射（mapping）。")
        raw_services = {}

    services: dict[str, ComposeService] = {}
    for name, raw in raw_services.items():
        name = str(name)
        if not isinstance(raw, Mapping):
            problems.append(f"服务 {name} 的定义不是键值映射，已跳过。")
            continue
        services[name] = _service_from_mapping(name, raw)

    return ComposeFile(
        label=label,
        services=services,
        problems=tuple(problems),
        interpolations=interpolations,
        deprecated_version_key=deprecated,
    )


# ── 4. 结论的数据结构 ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ConfigFinding:
    """一条配置 / 启动问题结论。"""

    name: str  # 英文标识（便于写测试和去重）
    category: str  # 展示给用户的中文分类
    severity: str  # 严重 / 警告 / 提示
    evidence: tuple[str, ...]  # 具体证据（必须来自真实解析结果）
    hint: str  # 可能原因
    advice: str  # 处理建议


def sort_findings(findings: Sequence[ConfigFinding]) -> list[ConfigFinding]:
    """按"严重程度 → 分类名"排序，保证报告顺序稳定、可复现。"""
    return sorted(findings, key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.category, f.name))


def _finding(
    name: str,
    category: str,
    severity: str,
    evidence: Sequence[str],
    hint: str,
    advice: str,
) -> ConfigFinding:
    return ConfigFinding(
        name=name,
        category=category,
        severity=severity,
        evidence=tuple(_clip(e) for e in evidence),
        hint=hint,
        advice=advice,
    )


# ── 5. 检查：单个 dotenv 文件 ───────────────────────────────────────────────


def _check_dotenv_syntax(parsed: DotenvFile) -> list[ConfigFinding]:
    """格式类问题：拆不开的行、非法键名、重复键、空值。"""
    out: list[ConfigFinding] = []

    if parsed.problems:
        out.append(
            _finding(
                "dotenv_syntax",
                "配置格式错误",
                "严重",
                [f"{parsed.label}：{p}" for p in parsed.problems[:6]],
                "这些行不符合 dotenv 语法，加载时会被忽略或用错误的方式解析，"
                "最终表现为「明明配了却读不到」。",
                "按 KEY=VALUE 的格式修正上述行；值里需要保留 # 或空格时用引号包起来。",
            )
        )

    if parsed.duplicates:
        out.append(
            _finding(
                "dotenv_duplicate_key",
                "配置重复定义",
                "警告",
                [f"{parsed.label} 中重复出现的键：{_head(parsed.duplicates)}"],
                "dotenv 后出现的定义会覆盖前面的，前一处多半是改配置时忘了删。",
                "删掉重复的那一行，只保留一个定义，避免「改了不生效」。",
            )
        )

    empty = parsed.empty_keys()
    if empty:
        out.append(
            _finding(
                "dotenv_empty_value",
                "环境变量为空",
                "提示",
                [f"{parsed.label} 中值为空的键：{_head(empty)}"],
                "写成 KEY= 意味着它的值是空字符串而不是「不存在」，"
                "下游多半会拿到空值而不是回退到默认值。",
                "确认这些键是否真的允许为空；如果是忘了填，补上正确值。",
            )
        )

    return out


# ── 6. 检查：模板里混进真实密钥 ─────────────────────────────────────────────


def _check_template_secrets(parsed: DotenvFile) -> list[ConfigFinding]:
    """模板文件（``.env.example``）里不该出现真实凭证 —— 它是要进版本库的。

    报告里**只写键名和值长度**，绝不写值本身，连前几位都不给。
    """
    if not is_template_name(parsed.label):
        return []

    risky = parsed.sensitive_keys_with_real_value()
    if not risky:
        return []

    confirmed = [(k, v) for k, v in risky if _REAL_SECRET_RE.match(v)]
    suspected = [(k, v) for k, v in risky if not _REAL_SECRET_RE.match(v)]

    out: list[ConfigFinding] = []
    if confirmed:
        out.append(
            _finding(
                "template_real_secret",
                "模板文件含真实密钥",
                "严重",
                [
                    f"{parsed.label}：{k} 的值符合真实凭证的格式（长度 {len(v)}，值已隐藏）"
                    for k, v in confirmed[:6]
                ],
                "这类前缀是云厂商 / 平台签发的真实密钥格式。模板文件通常会提交进版本库，"
                "等同把密钥公开。",
                "立刻在对应平台吊销并重新签发该密钥，把模板里的值换成占位符"
                "（例如 your-api-key-here），真实值只放在不提交的 .env 里。",
            )
        )
    if suspected:
        out.append(
            _finding(
                "template_concrete_secret",
                "模板文件写入具体密钥值",
                "警告",
                [
                    f"{parsed.label}：{k} 填的是具体值而不是占位符（长度 {len(v)}，值已隐藏）"
                    for k, v in suspected[:6]
                ],
                "模板文件里给出可直接使用的值，别人复制模板时会把同一个密钥带到自己的环境里。"
                "如果这个值在生产环境也在用，它就已经是公开的了。",
                "把模板里的值改成占位符（如 your-jwt-secret-key-change-this），"
                "并在文件开头注明「请勿把真实密钥写进本文件」。",
            )
        )
    return out


# ── 7. 检查：compose 文件 ───────────────────────────────────────────────────


def _check_compose_structure(
    compose: ComposeFile, *, present_files: Collection[str]
) -> list[ConfigFinding]:
    """compose 的静态问题：解析失败、服务定义不全、引用了不存在的文件。"""
    out: list[ConfigFinding] = []

    if compose.problems:
        out.append(
            _finding(
                "compose_unparsable",
                "Compose 配置错误",
                "严重",
                [f"{compose.label}：{p}" for p in compose.problems[:6]],
                "compose 文件本身读不出来，docker compose 会在启动前就报错退出，"
                "所有服务都起不来。",
                "按上面给出的位置修正 YAML 语法 / 补齐 services 段，然后 "
                "`docker compose config` 验证一遍。",
            )
        )
        # 解析都失败了，后面的结构性检查没有依据，直接返回。
        return out

    dirname = posixpath.dirname(compose.label)
    present = {p.replace("\\", "/") for p in present_files}
    present_basenames = {posixpath.basename(p) for p in present}

    def _same_dir_exists(relative: str) -> bool:
        """``env_file`` 里的相对路径是相对 compose 文件所在目录的。"""
        candidate = posixpath.normpath(posixpath.join(dirname, relative))
        return candidate in present or posixpath.basename(candidate) in present_basenames

    if compose.deprecated_version_key:
        out.append(
            _finding(
                "compose_deprecated_version",
                "Compose 配置已过时",
                "提示",
                [f"{compose.label} 顶层仍有 version 字段"],
                "Compose V2 已忽略 version 字段，启动时会打印一条 obsolete 警告。",
                "删掉顶层 version 字段即可，不影响行为。",
            )
        )

    no_image = [s.name for s in compose.services.values() if not s.has_build_or_image()]
    if no_image:
        out.append(
            _finding(
                "compose_service_without_image",
                "服务缺少镜像定义",
                "严重",
                [f"{compose.label} 中既没有 image 也没有 build 的服务：{_head(no_image)}"],
                "compose 不知道该拿什么镜像来跑这个服务，启动时会直接报错。",
                "给这些服务补上 image（用现成镜像）或 build（从 Dockerfile 构建）。",
            )
        )

    missing_env_files: list[str] = []
    for service in compose.services.values():
        for entry in service.env_file:
            if "${" in entry:
                continue  # 变量插值的路径不猜
            if not _same_dir_exists(entry):
                missing_env_files.append(f"{service.name} → {entry}")
    if missing_env_files:
        out.append(
            _finding(
                "compose_env_file_missing",
                "Compose 引用的配置文件不存在",
                "严重",
                [f"{compose.label}：{_head(missing_env_files)}"],
                "compose 在启动该服务时会去读 env_file，文件不存在会直接失败"
                "（报「env file … not found」），整个服务起不来。",
                "按下面步骤之一处理：① 从模板生成它（cp .env.example .env）；"
                "② 修正 env_file 的路径；③ 该服务确实不需要时删掉这一行。",
            )
        )

    unknown_deps: list[str] = []
    for service in compose.services.values():
        for dep in service.depends_on:
            if dep not in compose.services:
                unknown_deps.append(f"{service.name} → {dep}")
    if unknown_deps:
        out.append(
            _finding(
                "compose_depends_on_unknown",
                "依赖的服务不存在",
                "严重",
                [f"{compose.label}：{_head(unknown_deps)}"],
                "depends_on 指向的服务名在本文件里没有定义，compose 会拒绝启动。",
                "改成正确的服务名，或把被依赖的服务补进同一个 compose 文件。",
            )
        )

    return out


def _check_compose_ports(compose: ComposeFile) -> list[ConfigFinding]:
    """端口冲突与端口写法问题。"""
    out: list[ConfigFinding] = []

    if not compose.problems:
        # 同一条 ports 里写了两次同一个宿主机端口。
        bad_entries: list[str] = []
        conflicts: dict[int, list[str]] = {}
        for service in compose.services.values():
            for entry in service.ports:
                _port, problem = _parse_port_entry(entry)
                if problem:
                    bad_entries.append(f"{service.name} → {problem}")
            for port in service.host_ports:
                conflicts.setdefault(port, []).append(service.name)

        if bad_entries:
            out.append(
                _finding(
                    "compose_bad_port",
                    "端口映射格式异常",
                    "警告",
                    [f"{compose.label}：{_head(bad_entries)}"],
                    "端口写法不符合「宿主机:容器」或「IP:宿主机:容器」的格式，"
                    "compose 会在解析阶段报错。",
                    "改成「8080:8080」或「127.0.0.1:8080:8080」的写法。",
                )
            )

        # 只在**不同服务**之间算冲突：同一个服务里重复写端口是写法冗余，不是冲突。
        dupes = {
            port: sorted(set(names))
            for port, names in conflicts.items()
            if len(set(names)) > 1
        }
        if dupes:
            out.append(
                _finding(
                    "compose_port_conflict",
                    "宿主机端口冲突",
                    "严重",
                    [
                        f"{compose.label}：宿主机端口 {port} 同时被 "
                        f"{'、'.join(names)} 映射"
                        for port, names in sorted(dupes.items())[:6]
                    ],
                    "两个服务抢同一个宿主机端口，只有一个能绑上，"
                    "另一个会以「port is already allocated」启动失败。",
                    "把其中一个服务的宿主机端口改成别的（例如 8081:8080），"
                    "或删掉不需要对外暴露的那一条。",
                )
            )

    return out


def _check_compose_interpolation(
    compose: ComposeFile, *, defined_keys: Collection[str], sibling_env_keys: Collection[str]
) -> list[ConfigFinding]:
    """``${VAR}`` 引用了但没有默认值、也没人定义的变量。

    这里要说清一个容易踩的坑：compose 的变量插值只认**同级目录的 .env**
    和 shell 环境，**不认** 服务里 ``env_file`` 指向的文件。所以哪怕
    ``backend/.env`` 里写了 FOO，compose 里的 ``${FOO}`` 照样是空的。
    """
    if compose.problems:
        return []

    defined = {k.upper() for k in defined_keys} | {k.upper() for k in sibling_env_keys}
    undefined = sorted(
        name for name, has_default in compose.interpolations.items()
        if not has_default and name.upper() not in defined
    )
    if not undefined:
        return []

    return [
        _finding(
            "compose_interpolation_undefined",
            "Compose 变量未定义",
            "警告",
            [
                f"{compose.label} 中引用了 {{{{ {name} }}}}（无默认值），"
                "但同级目录的 .env 和环境变量里都没有定义"
                for name in undefined[:6]
            ],
            "compose 会把它替换成空字符串并继续启动，于是镜像名 / 端口 / 路径"
            "变成空值，报错位置和真正的原因离得很远。"
            "注意：服务里 env_file 指定的文件**不参与** compose 变量插值，只认同级 .env。",
            "在 compose 同级目录建一个 .env 写上这些变量，"
            "或者在写法上补默认值，例如 ${VAR:-默认值}。",
        )
    ]


def _check_compose_paths(
    compose: ComposeFile, *, present_files: Collection[str]
) -> list[ConfigFinding]:
    """build.context 和 bind mount 的源路径是否存在。"""
    if compose.problems:
        return []

    dirname = posixpath.dirname(compose.label)
    present = {p.replace("\\", "/") for p in present_files}
    present_basenames = {posixpath.basename(p) for p in present}
    present_dirs = {posixpath.dirname(p) for p in present}

    missing_build: list[str] = []
    for service in compose.services.values():
        context = service.build_context
        if not context or "${" in context:
            continue
        normalised = posixpath.normpath(posixpath.join(dirname, context))
        if normalised in present_dirs or posixpath.basename(normalised) in present_basenames:
            continue
        missing_build.append(f"{service.name} → {context}")

    if not missing_build:
        return []

    return [
        _finding(
            "compose_build_context_missing",
            "构建目录不存在",
            "警告",
            [f"{compose.label}：{_head(missing_build)}"],
            "build.context 指向的目录在这台机器上不存在，"
            "`docker compose build` 会失败；若本地已有镜像则可能侥幸启动。",
            "确认代码是否完整（子模块 / 目录没有同步过来），或把 context 改成正确路径。",
        )
    ]


# ── 8. 检查：.env 与 .env.example 的差异 ────────────────────────────────────


def _check_env_pair(template: DotenvFile, actual: DotenvFile) -> list[ConfigFinding]:
    """模板里声明了、实际配置里却没配的键 —— 需求里的「必需配置缺失」。"""
    out: list[ConfigFinding] = []

    missing = [k for k in template.order if k not in actual.values]
    empty = [
        k
        for k in template.order
        if k in actual.values and not actual.values.get(k, "").strip()
    ]
    extra = [k for k in actual.order if k not in template.values]

    if missing:
        out.append(
            _finding(
                "env_missing_key",
                "必需配置缺失",
                "严重",
                [
                    f"{template.label} 声明了、但 {actual.label} 里没有：{_head(missing)}",
                    f"共 {len(missing)} 个键",
                ],
                "这些键在模板里存在，说明项目预期它们是配置项。"
                "实际配置文件里没有它们，服务会拿到空值或直接启动失败"
                "（具体行为取决于代码里有没有默认值）。",
                f"对照 {template.label} 把这些键补进 {actual.label}，"
                "填上本机 / 本环境对应的值。",
            )
        )

    if empty:
        out.append(
            _finding(
                "env_empty_key",
                "必需配置为空",
                "警告",
                [f"{actual.label} 里这些键的值是空的：{_head(empty)}"],
                "键存在但值为空，和「完全没配」在多数框架里是同一个结果。",
                "确认是否有意留空；否则补上正确值。",
            )
        )

    if extra:
        out.append(
            _finding(
                "env_extra_key",
                "配置未在模板中记录",
                "提示",
                [
                    f"{actual.label} 里有、{template.label} 里没有的键：{_head(extra)}",
                ],
                "通常是本地调试加上去的，或者新配置项忘了同步到模板 —— "
                "后者会让别人部署时缺配置。",
                "确认这些键是否需要在模板里补一条（值用占位符），方便其他人部署。",
            )
        )

    return out


def _check_required_keys(
    parsed_envs: Mapping[str, DotenvFile], required: Collection[str]
) -> list[ConfigFinding]:
    """运维用 ``OPS_REQUIRED_ENV`` 显式声明的必需键，一个都没配到就报警。

    判定范围是整个项目里**所有** dotenv 文件的并集 ——
    一个键写在 backend/.env 还是 frontend/.env 都算配了，避免误报。
    """
    considered = [k for k in required if k.strip()]
    if not considered or not parsed_envs:
        return []

    configured: set[str] = set()
    for parsed in parsed_envs.values():
        configured.update(parsed.order)

    missing = sorted(k for k in considered if k not in configured)
    if not missing:
        return []

    return [
        _finding(
            "required_key_missing",
            "运维声明的必需变量缺失",
            "严重",
            [
                f"OPS_REQUIRED_ENV 要求配置：{_head(considered)}",
                f"在所有被检查的 .env 文件中都没有找到：{_head(missing)}",
            ],
            "这些键由运维人员在服务端显式声明为必需项，缺失说明部署配置不完整。",
            "在对应的 .env 里补上这些键；如果这个键确实不再需要，"
            "把它从 OPS_REQUIRED_ENV 里去掉。",
        )
    ]


# ── 9. 检查：.env 是否会被提交进版本库 ──────────────────────────────────────


def _gitignore_covers_env(text: str) -> bool:
    """``.gitignore`` 里是否有能盖住 ``.env`` 的规则。

    只认常见的几种写法，认不出来就当"没覆盖"——保守方向的误报是提醒，
    反向的漏报是事故。
    """
    patterns = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.add(line.lstrip("/").rstrip("/"))
    if not patterns:
        return False
    if ".env" in patterns or ".env*" in patterns or "*.env" in patterns:
        return True
    # ``*.env.*`` / ``.env.*`` 也能盖住 .env.local 之类的文件
    return any(p.startswith(".env") or p.endswith(".env") or ".env." in p for p in patterns)


def _check_env_not_ignored(
    parsed_envs: Mapping[str, DotenvFile], gitignore_text: str
) -> list[ConfigFinding]:
    """有 .env 但没有 .gitignore（或规则盖不住）时提醒一次。"""
    if not parsed_envs or not gitignore_text.strip():
        return []

    actual = [label for label in parsed_envs if is_actual_env_name(label)]
    if not actual or _gitignore_covers_env(gitignore_text):
        return []

    return [
        _finding(
            "env_not_gitignored",
            "实际配置未加入忽略列表",
            "警告",
            [f"{_head(actual)}：.gitignore 中没有能覆盖 .env 的规则"],
            "如果这些文件被 git add 进去，里面的密钥会永久留在提交历史里，"
            "即使之后删除也一样能翻出来。",
            "在 .gitignore 里加一行 .env（以及 .env.local 等变体），"
            "然后确认该文件当前没有被跟踪。",
        )
    ]


# ── 10. 总入口：配置检查 ────────────────────────────────────────────────────


def audit(
    *,
    dotenv_files: Mapping[str, str],
    compose_files: Mapping[str, str],
    present_files: Collection[str] = (),
    required_keys: Sequence[str] = (),
    gitignore: str = "",
) -> list[ConfigFinding]:
    """交叉比对已读入的配置文本，返回按严重程度排序的问题清单。

    入参全是**纯数据**（文件名 -> 原文），不做任何 I/O，所以可以直接用
    字符串在单元测试里构造各种畸形配置。

    Args:
        dotenv_files: ``相对路径 -> .env 文件原文``。
        compose_files: ``相对路径 -> compose 文件原文``。
        present_files: 项目目录下实际存在的相对路径（用于判断 env_file 等是否缺失）。
        required_keys: 运维声明的必需变量名。
        gitignore: ``.gitignore`` 原文；项目没有这个文件时传空字符串。

    Returns:
        问题清单；一切正常时返回空列表。
    """
    findings: list[ConfigFinding] = []

    parsed_envs = {
        label: parse_dotenv(text, label=label) for label, text in dotenv_files.items()
    }
    parsed_composes = {
        label: parse_compose(text, label=label) for label, text in compose_files.items()
    }

    # 每个 dotenv 文件自身的语法问题。
    for parsed in parsed_envs.values():
        findings.extend(_check_dotenv_syntax(parsed))
        findings.extend(_check_template_secrets(parsed))

    # 模板 vs 实际配置：只在**同一个目录**里配对比较，跨目录比没有意义。
    by_dir: dict[str, dict[str, DotenvFile]] = {}
    for label, parsed in parsed_envs.items():
        by_dir.setdefault(posixpath.dirname(label), {})[label] = parsed

    for dirname, files in sorted(by_dir.items()):
        templates = [p for label, p in files.items() if is_template_name(label)]
        actuals = [p for label, p in files.items() if is_actual_env_name(label)]
        if not templates:
            continue
        if not actuals:
            findings.append(
                _finding(
                    "env_actual_missing",
                    "缺少实际配置文件",
                    "严重",
                    [
                        f"{p.label} 附近没有对应的 .env"
                        for p in templates
                    ],
                    "项目只提供了模板，没有生成真正生效的配置文件。"
                    "多数框架读的是 .env，读不到就会用空值或直接启动失败。",
                    "在模板所在目录执行 cp "
                    f"{posixpath.basename(templates[0].label)} .env，然后按本机情况填写。",
                )
            )
            continue
        for template in templates:
            for actual in actuals:
                findings.extend(_check_env_pair(template, actual))

    # 所有 dotenv 里定义过的键（compose 插值判断要用）。
    all_env_keys: set[str] = set()
    for parsed in parsed_envs.values():
        all_env_keys.update(parsed.order)

    for compose in parsed_composes.values():
        findings.extend(
            _check_compose_structure(compose, present_files=present_files)
        )
        findings.extend(_check_compose_ports(compose))
        findings.extend(
            _check_compose_interpolation(
                compose,
                defined_keys=all_env_keys,
                sibling_env_keys={
                    k
                    for label, parsed in parsed_envs.items()
                    if posixpath.dirname(label) == posixpath.dirname(compose.label)
                    for k in parsed.order
                },
            )
        )
        findings.extend(_check_compose_paths(compose, present_files=present_files))

    findings.extend(_check_required_keys(parsed_envs, required_keys))
    findings.extend(_check_env_not_ignored(parsed_envs, gitignore))

    return sort_findings(findings)


# ── 11. 总入口：启动问题分析 ────────────────────────────────────────────────

# 退出码 -> 可能原因。内容是**推测**，报告里会标明。
_EXIT_CODE_HINTS = {
    137: "被 SIGKILL 强制杀死：最常见的原因是内存超限（OOM），也可能是 docker stop 超时后升级成强杀。",
    143: "收到 SIGTERM 后退出：属于正常停止流程（docker stop / compose down）。",
    139: "段错误（SIGSEGV）退出：进程访问了非法内存，通常是二进制依赖不兼容或原生扩展崩溃。",
    134: "收到 SIGABRT 后退出：进程主动 abort，常见于断言失败或 C 库检测到内存错误。",
    1: "应用自身以错误码 1 退出：通常是启动阶段的配置错误、依赖连不上，或代码抛了未捕获异常。",
    0: "进程正常退出（退出码 0）：对常驻服务来说意味着主进程干完活就结束了，"
    "常见于入口命令写成了短命令、或前台进程没有守护住。",
}


def _exit_code_hint(code: int) -> str:
    return _EXIT_CODE_HINTS.get(
        code, f"以退出码 {code} 结束：需要结合容器日志判断具体原因。"
    )


def container_name_of(container: Mapping[str, Any]) -> str:
    """从 ``/containers/json`` 的一条记录里取出容器名（去掉开头的 ``/``）。"""
    names = container.get("Names") or []
    if names:
        return str(names[0]).lstrip("/")
    return str(container.get("Id", "?"))[:12]


def _compose_service_label(container: Mapping[str, Any]) -> str:
    labels = container.get("Labels") or {}
    if isinstance(labels, Mapping):
        return str(labels.get("com.docker.compose.service") or "")
    return ""


def match_container(
    service: ComposeService, containers: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    """在容器列表里找出某个 compose 服务对应的容器。

    按可靠性从高到低尝试三种办法：

    1. ``container_name`` 完全一致（compose 里写死了名字，最准）；
    2. compose 打的标签 ``com.docker.compose.service``；
    3. 容器名等于服务名，或者形如 ``<项目>-<服务>-1`` / ``<项目>_<服务>_1``。

    找不到就返回 ``None`` —— 报告里会说"容器不存在"，
    但**不会**断言服务一定没启动（也许它根本没被这个 compose 管）。
    """
    if service.container_name:
        for container in containers:
            if container_name_of(container) == service.container_name:
                return container

    for container in containers:
        if _compose_service_label(container) == service.name:
            return container

    # compose 默认生成的容器名是 ``<项目>-<服务>-1``（连字符）或 ``<项目>_<服务>_1``
    # （下划线），项目名由目录名决定，这里不假设它叫什么。
    pattern = re.compile(rf"^(?:.*[-_])?{re.escape(service.name)}[-_]1$")
    for container in containers:
        name = container_name_of(container)
        if name == service.name or pattern.match(name):
            return container
    return None


def _parse_exited_code(status_text: str) -> int | None:
    """从 ``"Exited (137) 2 hours ago"`` 里取出 137。取不到返回 None。"""
    match = re.search(r"\bExited \((\d{1,3})\)", status_text or "")
    return int(match.group(1)) if match else None


def check_startup(
    compose: ComposeFile,
    containers: Sequence[Mapping[str, Any]],
    *,
    inspect: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[ConfigFinding]:
    """把 compose 声明的服务和 Docker 里**实际**的容器状态对起来。

    这是"启动问题分析"的核心：配置说应该跑什么，Docker 说实际在跑什么，
    两者的差集就是启动失败的地方。

    Args:
        compose: 已解析的 compose 文件。
        containers: ``GET /containers/json?all=1`` 的返回内容。
        inspect: ``容器名 -> GET /containers/{id}/json 的返回内容``，
                 用来拿退出码、OOM 标记和重启次数。没有也能分析，只是证据少一些。

    Returns:
        问题清单；所有服务都在正常运行且没有端口冲突时返回空列表。
    """
    inspect = inspect or {}
    findings: list[ConfigFinding] = []

    if compose.problems or not compose.services:
        return findings  # compose 本身就没解析出来，交给配置检查去报告

    # ── ① 服务与容器的对应关系 ──────────────────────────────────────────
    not_created: list[str] = []
    not_running: list[tuple[str, str]] = []
    restarting: list[tuple[str, str]] = []
    exited_abnormally: list[tuple[str, int, str]] = []

    for service in compose.services.values():
        container = match_container(service, containers)
        if container is None:
            not_created.append(service.name)
            continue

        name = container_name_of(container)
        state = str(container.get("State", "")).lower()
        status_text = str(container.get("Status", ""))

        if state == "restarting":
            restarting.append((service.name, name))
            continue
        if state != "running":
            code = _parse_exited_code(status_text)
            info = inspect.get(name) or {}
            state_info = info.get("State") if isinstance(info, Mapping) else None
            if isinstance(state_info, Mapping) and state_info.get("ExitCode") is not None:
                try:
                    code = int(state_info["ExitCode"])
                except (TypeError, ValueError):
                    pass
            if code is not None:
                exited_abnormally.append((service.name, code, name))
            else:
                not_running.append((service.name, name))

    if not_created:
        findings.append(
            _finding(
                "startup_container_missing",
                "服务未启动",
                "严重",
                [
                    f"{compose.label} 里声明的这些服务，在 Docker 里找不到对应容器："
                    f"{_head(not_created)}",
                    "判断依据：容器列表（含已停止的容器）中没有匹配的名字或 compose 标签",
                ],
                "容器根本不存在，说明这个服务没有被创建过 —— 可能是从来没启动过，"
                "也可能是被 `docker compose down` 删掉了。",
                "执行 `docker compose -f <compose 文件> up -d` 创建并启动这些服务；"
                "如果启动后立刻失败，再用 check_container_logs 看它的日志。",
            )
        )

    if restarting:
        findings.append(
            _finding(
                "startup_restart_loop",
                "容器反复重启",
                "严重",
                [f"{service}（容器 {name}）状态为 restarting" for service, name in restarting],
                "容器起来就挂、挂了又被 restart 策略拉起来，形成重启循环。"
                "这通常意味着启动过程中有硬错误（配置错误、依赖连不上），"
                "retry 解决不了。",
                "先看日志定位真正原因：check_container_logs（容器名见上）。"
                "如果只是想在排查期间止血，可以临时把 restart 策略改成 no。",
            )
        )

    if exited_abnormally:
        worst = [f"{service}（容器 {name}）退出码 {code}" for service, code, name in exited_abnormally]
        findings.append(
            _finding(
                "startup_exited",
                "容器已退出",
                "严重",
                worst
                + [
                    _exit_code_hint(code)
                    for _service, code, _name in exited_abnormally[:3]
                ],
                "容器已经停止，服务当前不可用。退出码只是线索，真正的原因在日志里 —— "
                "退出码只能告诉你「怎么死的」，不能告诉你「为什么死」。",
                "对每个退出的容器调用 check_container_logs 读取它最后阶段的日志；"
                "如果日志是空的，说明进程在打印任何东西之前就死了，"
                "这时要重点怀疑镜像 / 入口命令 / 挂载，而不是应用代码。",
            )
        )

    if not_running:
        findings.append(
            _finding(
                "startup_container_not_running",
                "容器未在运行",
                "严重",
                [f"{service}（容器 {name}）不在运行状态" for service, name in not_running],
                "容器存在但不是 running，通常是已停止（exited / created）。",
                "用 check_container_logs 看它上次运行的日志，"
                "再用 `docker compose up -d` 重启。",
            )
        )

    # ── ② depends_on 的依赖是否真的可用 ─────────────────────────────────
    by_service = {s.name: s for s in compose.services.values()}
    broken_deps: list[str] = []
    for service in compose.services.values():
        for dep in service.depends_on:
            dep_service = by_service.get(dep)
            if dep_service is None:
                continue  # 服务名写错的问题由配置检查报，这里不重复
            container = match_container(dep_service, containers)
            if container is None or str(container.get("State", "")).lower() != "running":
                broken_deps.append(f"{service.name} 依赖 {dep}，但 {dep} 当前不可用")
                continue
            health = re.search(r"\((unhealthy|starting)\)", str(container.get("Status", "")))
            if health and health.group(1) == "unhealthy":
                broken_deps.append(
                    f"{service.name} 依赖 {dep}，但 {dep} 的健康检查结果是 unhealthy"
                )
    if broken_deps:
        findings.append(
            _finding(
                "startup_dependency_unavailable",
                "依赖服务不可用",
                "严重",
                broken_deps[:6],
                "compose 的 depends_on 保证的是启动**顺序**，不保证对端真的能用。"
                "依赖方没起来时，被依赖的服务往往会在启动阶段连接失败然后退出。",
                "先把依赖服务拉起来并确认它健康（check_service / check_docker），"
                "再重启上层服务；如果依赖一时起不来，可考虑让上层服务带上重试逻辑。",
            )
        )

    # ── ③ 宿主机端口是否已被别的容器占用 ────────────────────────────────
    occupied: dict[int, str] = {}
    for container in containers:
        name = container_name_of(container)
        for entry in container.get("Ports") or []:
            if not isinstance(entry, Mapping):
                continue
            public = entry.get("PublicPort")
            if isinstance(public, int) and public > 0:
                occupied.setdefault(public, name)

    # 只报"被 compose 之外的东西占用"的端口；compose 内部的冲突由配置检查负责。
    # 判断"是不是自己人"要用服务**实际匹配到的容器名**，不能拿服务名去比 ——
    # 服务叫 db、容器叫 agenthub-db 的情况太常见了，用服务名比会天天误报。
    own_containers = {
        container_name_of(container)
        for service in compose.services.values()
        if (container := match_container(service, containers)) is not None
    }
    port_conflicts: list[str] = []
    for service in compose.services.values():
        for port in service.host_ports:
            holder = occupied.get(port)
            if holder and holder not in own_containers:
                port_conflicts.append(
                    f"{service.name} 想映射宿主机端口 {port}，但该端口已被容器 {holder} 占用"
                )
    if port_conflicts:
        findings.append(
            _finding(
                "startup_port_taken",
                "宿主机端口已被占用",
                "严重",
                port_conflicts[:6],
                "端口已经被别的容器绑定了。容器启动时会报"
                "「port is already allocated」（或在桥接网络下静默失败），"
                "表现出来就是服务怎么都起不来。",
                "停掉占用该端口的容器，或把当前服务映射到别的宿主机端口"
                "（例如改成 8081:8080）。注意别改容器端口 —— 服务监听的还是原来那个。",
            )
        )

    return sort_findings(findings)
