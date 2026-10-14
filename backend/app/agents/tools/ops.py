"""Ops tools — project layout, Docker daemon and service health checks.

First "intelligent ops diagnosis" capability. Three read-only tools give the
agent real evidence instead of guesses:

- ``check_project``  — is the directory there, what kind of project is it,
  are the key config files present?
- ``check_docker``   — is the Docker daemon reachable, which containers run,
  what is their state / health?
- ``check_service``  — HTTP / TCP probe of an *allow-listed* target.

Security model (read this before changing anything)
---------------------------------------------------
1. **No arbitrary paths.** ``check_project`` only accepts paths inside the
   directories listed in ``OPS_PROJECT_ROOTS``. The path is ``resolve()``d
   first, so ``../`` traversal and symlinks out of the root are rejected.
2. **No arbitrary URLs.** ``check_service`` only probes targets explicitly
   configured by the operator in ``OPS_HEALTH_ENDPOINTS``. An ad-hoc
   ``host:port`` is additionally checked against ``OPS_ALLOWED_HOSTS``
   (empty by default = ad-hoc checks disabled). Cloud metadata endpoints are
   refused even when an allow-list entry would match them.
3. **No secret leakage.** The tools never read file contents, and the URL /
   response body shown in the report has query strings and common secret keys
   redacted.
4. **No writes.** Every Docker call is a GET against the Docker Engine API
   over the Unix socket; nothing is created, started or removed.

All three tools are read-only and safe to expose to any authenticated user.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import aiohttp
from langchain_core.tools import tool

from app.infra.config import get_settings

logger = logging.getLogger(__name__)

# ── Limits (defensive bounds so a tool call can never hang or flood) ────────

_DEFAULT_TIMEOUT = 5.0
_MIN_TIMEOUT = 0.5
_MAX_TIMEOUT = 15.0
_MAX_CONTAINERS_SHOWN = 30
_MAX_BODY_PREVIEW = 200
_MAX_SUBPROJECTS = 15

# Directories that are never a project of their own — skipped when scanning
# one level of sub-directories for nested projects.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".github",
        ".idea",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "node_modules",
        "target",
        "venv",
    }
)

# Cloud metadata endpoints — refused even if an allow-list entry matches.
# SSRF to these hosts is how credentials get stolen in cloud environments.
_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure / OpenStack IMDS
        "100.100.100.200",  # Alibaba Cloud
        "metadata.google.internal",
        "metadata",
    }
)

# (name, patterns) → redacted when echoed back into the report.
_SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|authorization|access[_-]?key)"
    r"(\"?\s*[:=]\s*\"?)([^\s\"',}]{2,})"
)


# ── Project type table ──────────────────────────────────────────────────────
# For each known project type:
#   markers       — any of these at the project root means "this is that type"
#   required_any  — every group must have at least one file present
#   recommended   — nice to have; missing → a warning, not a failure
#
# The point of the table is exactly what a naive checker gets wrong: a Go
# project has no requirements.txt and a Maven project has no package.json, so
# "missing file" only means something *relative to the detected type*.


@dataclass(frozen=True)
class _ProjectType:
    name: str
    label: str
    markers: tuple[str, ...]
    required_any: tuple[tuple[str, ...], ...]
    recommended: tuple[str, ...]


_PROJECT_TYPES: tuple[_ProjectType, ...] = (
    # NOTE: `markers` are deliberately BROADER than `required_any`. A directory
    # is recognised by any marker (e.g. a lock file), but the *key* file may
    # still be missing (a package-lock.json without package.json = broken
    # checkout). That is exactly the kind of finding this checker exists for.
    _ProjectType(
        name="python",
        label="Python 项目",
        markers=(
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
            "Pipfile",
            "manage.py",
        ),
        required_any=(("pyproject.toml", "setup.py", "requirements.txt", "Pipfile"),),
        recommended=("README.md", ".gitignore", ".env.example", "Dockerfile"),
    ),
    _ProjectType(
        name="node",
        label="Node.js 项目",
        markers=(
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            ".nvmrc",
        ),
        required_any=(("package.json",),),
        recommended=("README.md", ".gitignore", ".env.example", "Dockerfile"),
    ),
    _ProjectType(
        name="go",
        label="Go 项目",
        markers=("go.mod", "go.sum"),
        required_any=(("go.mod",),),
        recommended=("README.md", ".gitignore", "go.sum", "Dockerfile"),
    ),
    _ProjectType(
        name="maven",
        label="Java (Maven) 项目",
        markers=("pom.xml", "mvnw"),
        required_any=(("pom.xml",),),
        recommended=("README.md", ".gitignore", "Dockerfile"),
    ),
    _ProjectType(
        name="gradle",
        label="Java (Gradle) 项目",
        markers=(
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradlew",
        ),
        required_any=(("build.gradle", "build.gradle.kts"),),
        recommended=("README.md", ".gitignore", "Dockerfile"),
    ),
    # Compose is listed before the plain "docker" type on purpose: a directory
    # that has both should be described as a Compose project.
    _ProjectType(
        name="docker-compose",
        label="Docker Compose 项目",
        markers=(
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ),
        required_any=(
            ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
        ),
        recommended=(".env.example", "README.md"),
    ),
    _ProjectType(
        name="docker",
        label="Docker 镜像项目",
        markers=("Dockerfile",),
        required_any=(("Dockerfile",),),
        recommended=(".dockerignore", "README.md"),
    ),
)

_GENERIC_TYPE = _ProjectType(
    name="generic",
    label="通用目录（未识别出具体技术栈）",
    markers=(),
    required_any=(),
    recommended=("README.md", ".gitignore"),
)


# ── Shared helpers ──────────────────────────────────────────────────────────


def _configured_roots() -> list[Path]:
    """Resolve the ``OPS_PROJECT_ROOTS`` allow-list into absolute paths."""
    roots: list[Path] = []
    for raw in get_settings().ops_project_roots_list:
        try:
            roots.append(Path(raw).resolve())
        except OSError:  # pragma: no cover - unreadable/odd path
            logger.warning("Skipping unusable OPS_PROJECT_ROOTS entry: %s", raw)
    return roots


def _normcase(path: Path) -> str:
    """Normalise case for path comparison (Windows is case-insensitive)."""
    return os.path.normcase(str(path))


def _is_within(child: Path, root: Path) -> bool:
    """True when ``child`` is ``root`` itself or lives below it."""
    c, r = _normcase(child), _normcase(root)
    return c == r or c.startswith(r.rstrip(os.sep) + os.sep)


def _resolve_allowed_path(raw_path: str) -> tuple[Path | None, str]:
    """Validate a user-supplied path against the configured roots.

    Returns ``(resolved_path, "")`` when allowed, else ``(None, error_message)``.

    The path is resolved *before* the containment check, so ``../../etc`` and
    symlinks pointing outside the root are both rejected.
    """
    raw_path = (raw_path or "").strip().strip('"').strip("'")
    if not raw_path:
        return None, "路径为空。"

    roots = _configured_roots()
    if not roots:
        return None, (
            "服务端未配置允许检查的目录（OPS_PROJECT_ROOTS 为空），"
            "出于安全考虑拒绝任何路径检查。"
        )

    try:
        candidate = Path(raw_path).expanduser().resolve()
    except (OSError, ValueError) as exc:
        return None, f"路径无法解析：{raw_path}（{exc}）"

    # Refuse NUL bytes / control characters outright.
    if any(ch in raw_path for ch in ("\x00", "\n", "\r")):
        return None, "路径包含非法字符。"

    if not any(_is_within(candidate, root) for root in roots):
        allowed = "、".join(str(r) for r in roots)
        return None, (
            f"路径不在允许检查的范围内，已拒绝：{candidate}\n"
            f"允许的根目录（OPS_PROJECT_ROOTS）：{allowed}"
        )

    return candidate, ""


def _detect_types(path: Path, names: set[str]) -> list[_ProjectType]:
    """Return every project type whose markers are present in ``names``."""
    found = [pt for pt in _PROJECT_TYPES if any(m in names for m in pt.markers)]
    return found or [_GENERIC_TYPE]


def _scan_subprojects(path: Path) -> list[tuple[str, _ProjectType]]:
    """Scan one level down for nested projects (e.g. backend/, frontend/)."""
    results: list[tuple[str, _ProjectType]] = []
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return results

    for entry in entries:
        if len(results) >= _MAX_SUBPROJECTS:
            break
        if not entry.is_dir() or entry.name in _SKIP_DIRS or entry.name.startswith("."):
            continue
        try:
            names = {p.name for p in entry.iterdir() if p.is_file()}
        except OSError:
            continue
        matched = [pt for pt in _PROJECT_TYPES if any(m in names for m in pt.markers)]
        if matched:
            results.append((entry.name, matched[0]))
    return results


def _redact(text: str) -> str:
    """Mask anything that looks like a credential before echoing it back."""
    return _SECRET_PATTERN.sub(r"\1\2***", text)


def _redact_url(url: str) -> str:
    """Drop query string / user-info (may carry tokens) from a URL."""
    try:
        parts = urlparse(url)
    except ValueError:
        return "<无法解析的地址>"
    netloc = parts.netloc.rsplit("@", 1)[-1]  # strip user:pass@
    return urlunparse((parts.scheme, netloc, parts.path, "", "", ""))


def _truncate(text: str) -> str:
    """Cap tool output — the model pays tokens for every character."""
    limit = get_settings().OPS_MAX_OUTPUT_CHARS
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n...（输出已截断，共 {len(text)} 字符）"


def _clamp_timeout(value: float | None) -> float:
    """Keep a caller-supplied timeout inside sane bounds."""
    try:
        timeout = float(value) if value is not None else _DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT
    if timeout != timeout:  # NaN
        return _DEFAULT_TIMEOUT
    return max(_MIN_TIMEOUT, min(timeout, _MAX_TIMEOUT))


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"  # pragma: no cover


# ── Tool 1: project check ───────────────────────────────────────────────────


def _render_project_report(path: Path) -> str:
    """Build the Chinese evidence report for one project directory."""
    try:
        names = {p.name for p in path.iterdir()}
    except OSError as exc:
        return (
            f"【项目检查】{path}\n"
            f"总体状态：异常\n"
            f"检查证据：目录存在但无法读取（{exc}）。\n"
            f"可能原因：权限不足，或挂载目录不可访问。\n"
            f"处理建议：确认容器对 {path} 有读取权限（docker-compose 中挂载为 :ro 即可）。"
        )

    types = _detect_types(path, names)
    lines = [f"【项目检查】{path}"]
    problems: list[str] = []
    warnings: list[str] = []

    lines.append("项目类型：" + "、".join(t.label for t in types))

    # Key files — evaluated per detected type, not as a global checklist.
    lines.append("关键文件：")
    for pt in types:
        if not pt.required_any:
            continue
        for group in pt.required_any:
            present = [f for f in group if f in names]
            if present:
                for f in present:
                    try:
                        size = _human_size((path / f).stat().st_size)
                    except OSError:
                        size = "大小未知"
                    lines.append(f"  ✓ {f}（存在，{size}）")
            else:
                missing = " 或 ".join(group)
                lines.append(f"  ✗ 缺失：{missing}")
                problems.append(f"{pt.label} 缺少 {missing}")

    # Recommended files — informational only.
    recommended_missing: list[str] = []
    for pt in types:
        for f in pt.recommended:
            if f not in names and f not in recommended_missing:
                recommended_missing.append(f)
    if recommended_missing:
        lines.append("建议文件（缺失不影响可用性）：")
        for f in recommended_missing:
            lines.append(f"  ! {f}（建议补充）")
        warnings.append(f"{len(recommended_missing)} 个建议文件未找到")

    # Nested projects (backend/, frontend/, …).
    subprojects = _scan_subprojects(path)
    if subprojects:
        lines.append("子项目：")
        for name, pt in subprojects:
            lines.append(f"  - {name}/ → {pt.label}")

    # Dockerfile / compose presence is useful ops context even when the type
    # table did not classify the directory as such.
    has_dockerfile = "Dockerfile" in names
    compose_files = [f for f in names if f in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}]
    lines.append(
        "容器化配置："
        + ("Dockerfile 存在" if has_dockerfile else "未发现 Dockerfile")
        + "；"
        + (f"Compose 文件：{compose_files[0]}" if compose_files else "未发现 compose 文件")
    )

    if problems:
        status = "异常"
    elif warnings:
        status = "正常（有提示）"
    else:
        status = "正常"

    lines.insert(1, f"总体状态：{status}")
    lines.append("")
    lines.append("检查证据说明：以上全部结论来自目录遍历，未读取任何文件内容（避免泄露 .env 中的密钥）。")
    if problems:
        lines.append("可能原因：" + "；".join(problems) + "。")
        lines.append(
            "处理建议：确认是否使用了不同的依赖管理方式（如 Poetry / uv / Pipenv），"
            "并补齐对应的关键文件；若项目确实不需要该文件，可以忽略此项。"
        )
    return _truncate("\n".join(lines))


def _list_roots() -> str:
    """Describe the configured roots (used for discovery / error messages)."""
    roots = _configured_roots()
    if not roots:
        return (
            "【项目检查】未配置任何允许检查的目录（OPS_PROJECT_ROOTS 为空）。\n"
            "处理建议：在 backend/.env 中设置 OPS_PROJECT_ROOTS，"
            "并在 docker-compose.yml 中把宿主机目录挂载到该路径（只读）。"
        )

    lines = ["【项目检查】未指定路径，以下是允许检查的根目录及其下一级内容："]
    for root in roots:
        exists = root.is_dir()
        lines.append(f"- {root}（{'存在' if exists else '不存在'}）")
        if not exists:
            continue
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            lines.append(f"    （无法列出：{exc}）")
            continue
        shown = 0
        for entry in entries:
            if entry.name.startswith(".") or entry.name in _SKIP_DIRS:
                continue
            if shown >= _MAX_SUBPROJECTS:
                lines.append("    ...（更多条目已省略）")
                break
            lines.append(f"    - {entry.name}{'/' if entry.is_dir() else ''}")
            shown += 1
    lines.append("")
    lines.append("提示：把上面某个目录传给 check_project 的 path 参数即可做详细检查。")
    return _truncate("\n".join(lines))


@tool
def check_project(path: str = "") -> str:
    """检查一个项目目录的结构是否正常（运维健康检查的第 1 步）。

    会做三件事：① 确认目录存在且可读；② 识别项目类型（Python / Node / Go /
    Maven / Gradle / Docker Compose）；③ 按该类型检查关键配置文件是否齐全。
    只读取文件名，不读取文件内容，因此不会泄露 .env 里的密钥。

    只能检查服务器预先允许的目录（由服务端 OPS_PROJECT_ROOTS 配置），
    传入其他路径会被拒绝——这是为了防止越权读取宿主机文件。

    Args:
        path: 要检查的项目目录的绝对路径，例如 "/ops/projects/backend"。
              留空则返回当前允许检查的全部根目录及其下一级内容（用于先看看有什么）。

    Returns:
        中文检查报告：总体状态 / 项目类型 / 关键文件 / 建议 / 证据说明。
    """
    if not path or path.strip().lower() in {"list", "ls", "."}:
        return _list_roots()

    resolved, error = _resolve_allowed_path(path)
    if resolved is None:
        return _truncate(f"【项目检查】{path}\n总体状态：已拒绝\n原因：{error}")

    if not resolved.exists():
        suggestion = ""
        parent = resolved.parent
        if parent.is_dir():
            try:
                siblings = sorted(
                    p.name for p in parent.iterdir() if p.is_dir()
                )[:10]
            except OSError:
                siblings = []
            if siblings:
                suggestion = "\n该路径的上一级目录下现有子目录：" + "、".join(siblings)
        return _truncate(
            f"【项目检查】{resolved}\n"
            f"总体状态：异常\n"
            f"检查证据：目录不存在。\n"
            f"可能原因：路径写错、项目未部署，或宿主机目录没有挂载进容器。\n"
            f"处理建议：核对路径；若项目在宿主机上，确认 docker-compose.yml 里"
            f"把该目录挂载到了容器内的这个位置。{suggestion}"
        )

    if not resolved.is_dir():
        return _truncate(
            f"【项目检查】{resolved}\n"
            f"总体状态：异常\n"
            f"检查证据：该路径存在但不是目录（可能是一个文件）。\n"
            f"处理建议：传入项目根目录而不是文件路径。"
        )

    return _render_project_report(resolved)


# ── Tool 2: docker check ────────────────────────────────────────────────────


async def _docker_api(
    socket_path: str, endpoint: str, timeout: float
) -> tuple[Any | None, str]:
    """GET a Docker Engine API endpoint over the Unix socket.

    Returns ``(parsed_json, "")`` on success or ``(None, error_message)``.
    Only GET is used — these tools never mutate the Docker state.
    """
    connector = aiohttp.UnixConnector(path=socket_path)
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            async with session.get(f"http://localhost{endpoint}") as resp:
                raw = await resp.text()
                if resp.status != 200:
                    return None, f"Docker 返回 HTTP {resp.status}：{raw[:200]}"
                return json.loads(raw), ""
    except FileNotFoundError:
        return None, f"找不到 Docker socket：{socket_path}"
    except PermissionError:
        return None, f"没有权限访问 Docker socket：{socket_path}"
    except asyncio.TimeoutError:
        return None, f"访问 Docker socket 超时（>{timeout}s）"
    except (aiohttp.ClientConnectorError, ConnectionRefusedError) as exc:
        return None, f"无法连接 Docker socket：{socket_path}（{exc}）"
    except json.JSONDecodeError:
        return None, "Docker 返回的内容不是合法 JSON。"
    except Exception as exc:  # noqa: BLE001 - report anything else as-is
        return None, f"访问 Docker 失败：{type(exc).__name__}: {exc}"


def _parse_health(status_text: str) -> str:
    """Extract ``healthy`` / ``unhealthy`` / ``starting`` from Status text."""
    match = re.search(r"\((healthy|unhealthy|starting)\)", status_text or "")
    return match.group(1) if match else ""


def _render_container(container: dict[str, Any]) -> str:
    names = container.get("Names") or []
    name = (names[0].lstrip("/") if names else container.get("Id", "?")[:12])
    state = container.get("State", "unknown")
    status_text = container.get("Status", "")
    image = container.get("Image", "?")
    health = _parse_health(status_text)
    mark = "✓" if state == "running" else "✗"
    health_text = f"，健康检查={health}" if health else ""
    return f"  {mark} {name} [{state}]{health_text}  {status_text}  镜像={image}"


@tool
async def check_docker(
    containers: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> str:
    """检查 Docker 是否可用，以及指定容器的运行状态（运维健康检查的第 2 步）。

    通过容器内的 Docker socket（/var/run/docker.sock）只读查询 Docker Engine API：
    先访问 /version 确认守护进程可用，再列出容器及其状态与健康检查结果。
    Docker 不可用（socket 未挂载 / 守护进程没启动 / 没有权限）时会返回明确原因，
    不会抛异常。

    Args:
        containers: 要重点检查的容器名，多个用逗号分隔，例如
                    "agenthub-backend,agenthub-db"。留空则汇总所有容器。
        timeout: 超时秒数，默认 5 秒（会被限制在 0.5~15 秒之间）。

    Returns:
        中文检查报告：守护进程信息 / 容器统计 / 每个容器的状态与健康检查结果。
    """
    timeout = _clamp_timeout(timeout)
    settings = get_settings()
    socket_path = settings.OPS_DOCKER_SOCKET

    lines = ["【Docker 检查】"]

    if not Path(socket_path).exists():
        lines.append("总体状态：不可用")
        lines.append(f"检查证据：容器内不存在 Docker socket（{socket_path}）。")
        lines.append(
            "可能原因：backend 容器没有挂载 /var/run/docker.sock，"
            "或 Docker Desktop / dockerd 没有运行。"
        )
        lines.append(
            "处理建议：在 docker-compose.yml 的 backend 服务下加入 "
            "`- /var/run/docker.sock:/var/run/docker.sock:ro`，然后重启 backend 容器。"
        )
        return _truncate("\n".join(lines))

    version, error = await _docker_api(socket_path, "/version", timeout)
    if version is None:
        lines.append("总体状态：不可用")
        lines.append(f"检查证据：Docker socket 存在（{socket_path}），但查询失败——{error}")
        lines.append(
            "可能原因：Docker 守护进程未运行、socket 权限不足"
            "（容器内用户不在 docker 组），或 Docker 版本过旧。"
        )
        lines.append("处理建议：在宿主机执行 `docker version` 确认守护进程正常；确认 socket 挂载为只读且容器有访问权限。")
        return _truncate("\n".join(lines))

    lines.append("总体状态：可用")
    lines.append(
        "守护进程：Docker {ver}（API {api}，{os}/{arch}），socket={path}".format(
            ver=version.get("Version", "?"),
            api=version.get("ApiVersion", "?"),
            os=version.get("Os", "?"),
            arch=version.get("Arch", "?"),
            path=socket_path,
        )
    )

    data, error = await _docker_api(socket_path, "/containers/json?all=1", timeout)
    if data is None:
        lines.append(f"检查证据：守护进程可用，但列出容器失败——{error}")
        return _truncate("\n".join(lines))

    all_containers: list[dict[str, Any]] = data
    by_name: dict[str, dict[str, Any]] = {}
    for item in all_containers:
        for raw_name in item.get("Names") or []:
            by_name[raw_name.lstrip("/")] = item

    running = sum(1 for c in all_containers if c.get("State") == "running")
    lines.append(
        f"容器统计：共 {len(all_containers)} 个，运行中 {running} 个，"
        f"非运行 {len(all_containers) - running} 个"
    )

    requested = [n.strip().lstrip("/") for n in (containers or "").split(",") if n.strip()]

    if requested:
        lines.append("指定容器：")
        missing: list[str] = []
        for name in requested:
            item = by_name.get(name)
            if item is None:
                # Docker allows prefix matching — offer it when unambiguous.
                prefix_hits = [n for n in by_name if n.startswith(name)]
                if len(prefix_hits) == 1:
                    item = by_name[prefix_hits[0]]
                    name = prefix_hits[0]
                elif len(prefix_hits) > 1:
                    lines.append(
                        f"  ! {name}（名称不完整，匹配到多个：{'、'.join(prefix_hits[:5])}）"
                    )
                    continue
                else:
                    missing.append(name)
                    lines.append(f"  ✗ {name}（未找到该容器）")
                    continue
            lines.append(_render_container(item))
        if missing:
            lines.append(
                f"可能原因：容器名拼写错误，或该容器不属于当前 Docker 守护进程"
                f"（未创建 / 已经在别的主机）。现有容器名："
                f"{'、'.join(sorted(by_name)[:10]) or '（无）'}"
            )
            lines.append("处理建议：用 `docker ps -a` 核对容器名；确认容器已创建。")
    else:
        lines.append("全部容器：")
        for item in all_containers[:_MAX_CONTAINERS_SHOWN]:
            lines.append(_render_container(item))
        if len(all_containers) > _MAX_CONTAINERS_SHOWN:
            lines.append(f"  ...（其余 {len(all_containers) - _MAX_CONTAINERS_SHOWN} 个已省略）")
        if not all_containers:
            lines.append("  （当前没有任何容器）")

    return _truncate("\n".join(lines))


# ── Tool 3: service check ───────────────────────────────────────────────────


def _host_allowed(host: str) -> tuple[bool, str]:
    """Check an ad-hoc host against ``OPS_ALLOWED_HOSTS`` (exact / CIDR)."""
    if not host:
        return False, "地址中没有主机名。"
    if host.lower() in _METADATA_HOSTS:
        return False, f"{host} 是云厂商元数据地址，出于安全考虑一律拒绝。"

    allowed = get_settings().ops_allowed_hosts_list
    if not allowed:
        return False, (
            "服务端未配置 OPS_ALLOWED_HOSTS，因此拒绝任何临时目标"
            "（这是防止 SSRF 的默认策略）。"
        )

    host_l = host.lower().strip("[]")
    for entry in allowed:
        entry_l = entry.strip().lower()
        if entry_l == host_l:
            return True, ""
        try:
            network = ipaddress.ip_network(entry_l, strict=False)
        except ValueError:
            continue
        try:
            if ipaddress.ip_address(host_l) in network:
                return True, ""
        except ValueError:
            continue
    return False, f"主机 {host} 不在允许清单 OPS_ALLOWED_HOSTS 中。"


def _parse_target(target: str) -> tuple[str, str, str, int | None, str]:
    """Parse a target into (scheme, host, path, port, error)."""
    raw = (target or "").strip()
    if not raw:
        return "", "", "", None, "目标为空。"

    if "://" not in raw:
        # Bare "host:port" (or ":port") → treat as a TCP port probe.
        raw = f"tcp://{raw}"

    try:
        parts = urlparse(raw)
    except ValueError as exc:
        return "", "", "", None, f"地址无法解析：{exc}"

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https", "tcp"}:
        return "", "", "", None, f"不支持的协议 '{scheme}'（仅支持 http / https / tcp）。"

    if "@" in parts.netloc:
        return "", "", "", None, "地址中不允许携带用户名/密码。"

    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError as exc:
        return "", "", "", None, f"地址中的端口不合法：{exc}"

    if not host:
        return "", "", "", None, "地址中没有主机名。"
    if port is not None and not (1 <= port <= 65535):
        return "", "", "", None, f"端口越界：{port}"

    if scheme in {"http", "https"} and port is None:
        port = 443 if scheme == "https" else 80
    if scheme == "tcp" and port is None:
        return "", "", "", None, "TCP 检查必须指定端口，例如 db:5432。"

    path = parts.path or "/"
    if scheme == "tcp":
        path = ""
    return scheme, host, path, port, ""


async def _check_http(url: str, timeout: float) -> tuple[bool, str]:
    """GET an HTTP(S) URL with a timeout; never follows redirects."""
    started = time.perf_counter()
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            cookie_jar=aiohttp.DummyCookieJar(),  # no cookie persistence
        ) as session:
            async with session.get(url, allow_redirects=False) as resp:
                body = await resp.text(errors="replace")
                elapsed = int((time.perf_counter() - started) * 1000)
                content_type = resp.headers.get("Content-Type", "").lower()
                if "html" in content_type:
                    # A full HTML page is noise in a health report.
                    body_note = "，响应为 HTML 页面（已省略正文）"
                else:
                    preview = _redact(
                        body[:_MAX_BODY_PREVIEW].replace("\n", " ").strip()
                    )
                    body_note = (
                        f"，响应片段：{preview}" if preview else "（响应体为空）"
                    )
                healthy = 200 <= resp.status < 400
                return healthy, f"HTTP {resp.status}，耗时 {elapsed} ms{body_note}"
    except asyncio.TimeoutError:
        return False, f"请求超时（>{timeout}s，未在超时时间内收到响应）"
    except aiohttp.ClientConnectorError as exc:
        return False, f"连接失败（目标不可达 / 端口未监听）：{exc}"
    except aiohttp.ClientError as exc:
        return False, f"HTTP 请求失败：{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"检查失败：{type(exc).__name__}: {exc}"


async def _check_tcp(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Open a TCP connection with a timeout, then close it immediately."""
    started = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - closing best effort
            pass
        elapsed = int((time.perf_counter() - started) * 1000)
        return True, f"TCP 端口可连接，耗时 {elapsed} ms"
    except asyncio.TimeoutError:
        return False, f"连接超时（>{timeout}s）"
    except ConnectionRefusedError:
        return False, "连接被拒绝（端口未监听）"
    except OSError as exc:
        return False, f"连接失败：{exc}"


def _render_service_targets() -> str:
    """List the operator-configured health endpoints."""
    endpoints = get_settings().ops_health_endpoints_map
    allowed = get_settings().ops_allowed_hosts_list
    lines = ["【服务检查】未指定目标，以下是服务端预先配置的检查目标："]
    if endpoints:
        for name, url in endpoints.items():
            lines.append(f"- {name} → {_redact_url(url)}")
    else:
        lines.append("（无：OPS_HEALTH_ENDPOINTS 尚未配置任何目标）")
    lines.append("")
    lines.append("临时目标（host:port 或 http://…）：" + ("允许，白名单：" + "、".join(allowed) if allowed else "已禁用（OPS_ALLOWED_HOSTS 为空）"))
    lines.append("提示：把上面某个名称传给 check_service 的 target 参数即可发起检查。")
    return _truncate("\n".join(lines))


@tool
async def check_service(target: str = "", timeout: float = _DEFAULT_TIMEOUT) -> str:
    """检查一个服务是否健康（运维健康检查的第 3 步）。

    支持两种目标：
    ① 预先配置的名称（推荐）——服务端在 OPS_HEALTH_ENDPOINTS 里写好的
       "名称=地址"，例如 backend=http://backend:8080/health。模型只能按名称调用，
       地址本身由运维人员控制，从根本上避免 SSRF。
    ② 临时目标 —— http(s)://… 或 host:port。只有当主机在 OPS_ALLOWED_HOSTS
       白名单里才允许；云厂商元数据地址（169.254.169.254 等）一律拒绝。

    HTTP 目标用 GET 探测（不跟随跳转），2xx/3xx 视为健康，其余为异常；
    tcp://host:port 只做 TCP 连接测试。所有请求都带超时，不会挂起。

    Args:
        target: 检查目标名称或地址，例如 "backend"、"http://127.0.0.1:8080/health"、
                "db:5432"。留空则列出所有已配置的目标名称。
        timeout: 超时秒数，默认 5 秒（会被限制在 0.5~15 秒之间）。

    Returns:
        中文检查报告：目标 / 总体状态 / 检查证据（状态码、耗时）/ 处理建议。
    """
    timeout = _clamp_timeout(timeout)
    raw_target = (target or "").strip()
    if not raw_target or raw_target.lower() in {"list", "ls"}:
        return _render_service_targets()

    endpoints = get_settings().ops_health_endpoints_map
    name = raw_target.lower()
    # `is_configured` drives the security decision below — never a label string.
    is_configured = name in endpoints
    if is_configured:
        url = endpoints[name]
        source = f"已配置目标：{name}"
    else:
        url = raw_target
        source = "临时目标（白名单校验）"

    # `path` is validated by _parse_target but the full URL is used for the
    # probe, so only the scheme / host / port are needed afterwards.
    scheme, host, _path, port, error = _parse_target(url)
    if error:
        return _truncate(
            f"【服务检查】{raw_target}\n"
            f"总体状态：已拒绝\n"
            f"原因：{error}\n"
            f"处理建议：使用 check_service 不带参数先列出可用的目标名称。"
        )

    # Configured targets are trusted (operator-controlled); ad-hoc ones must
    # pass the host allow-list.
    if not is_configured:
        ok, reason = _host_allowed(host)
        if not ok:
            configured = "、".join(endpoints) if endpoints else "（无）"
            return _truncate(
                f"【服务检查】{_redact_url(raw_target)}\n"
                f"总体状态：已拒绝\n"
                f"原因：{reason}\n"
                f"已配置的目标名称：{configured}\n"
                f"处理建议：改用上面已配置的名称，或让运维人员把该主机加入 "
                f"OPS_ALLOWED_HOSTS / 把地址配置到 OPS_HEALTH_ENDPOINTS。"
            )

    display = _redact_url(url) if scheme in {"http", "https"} else f"{scheme}://{host}:{port}"

    if scheme == "tcp":
        healthy, detail = await _check_tcp(host, port or 0, timeout)
    else:
        healthy, detail = await _check_http(url, timeout)

    lines = [f"【服务检查】{raw_target}（{source}）"]
    lines.append(f"目标地址：{display}")
    lines.append(f"总体状态：{'健康' if healthy else '异常'}")
    lines.append(f"检查证据：{detail}")
    lines.append(f"超时设置：{timeout}s")
    if not healthy:
        lines.append(
            "可能原因：服务未启动 / 端口未监听 / 网络或防火墙不通 / 健康检查路径错误 / "
            "服务内部报错（如依赖的数据库不可用）。"
        )
        lines.append(
            "处理建议：① 用 check_docker 确认对应容器是否 running；"
            "② 查看容器日志 `docker logs <容器名>`；"
            "③ 核对健康检查路径与容器内实际监听端口。"
        )
    return _truncate("\n".join(lines))


# ── Public helper (used by ``app.agents.supervisor`` and by tests) ──────────

OPS_TOOLS: tuple[Any, ...] = (check_project, check_docker, check_service)
