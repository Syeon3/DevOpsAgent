"""日志分析引擎 —— 纯函数，不做任何 I/O。

特意从 ``ops.py`` 里拆出来：

- 这里全是**纯函数**（文本进 → 结论出），不依赖 Docker、socket 或任何配置，
  因此可以单独做单元测试；
- ``ops.py`` 负责 I/O（调用 Docker API）和安全策略（允许读哪些容器、脱敏），
  然后调用本模块。

三件事：

1. ``demux_docker_log`` —— 解析 Docker 日志接口返回的内容。容器没有 TTY 时，
   Docker 会把 stdout/stderr 复用成一个带 8 字节头的分帧格式；有 TTY 时返回裸流。
   两种都要能处理，否则读出来就是乱码。
2. ``analyze_logs`` —— 用一张人工整理的故障模式表匹配日志（Python 异常、数据库
   连接失败、HTTP 5xx、超时……），给出命中次数和证据行。结果按**分类**合并：
   同一分类下的多个模式（例如"异常类名"和"Traceback"都叫「Python 异常」）
   只输出一条，避免报告里出现两行同名条目。
3. ``scan_injection`` —— 标记那些"在跟模型说话"而不是"在跟人说话"的日志行
   （通过日志内容做提示词注入）。

模式表的设计原则：**只给证据，不下结论。** 匹配成功只代表"这段文本看起来像 X"，
绝不代表"服务就是因为 X 坏的"。报告里始终保留原始行，方便人（或模型）自己判断。
"""

import re
from dataclasses import dataclass, field

# ── 数量上限（防止一条日志把输出撑爆、把 token 烧光）────────────────────────

_MAX_EVIDENCE_PER_FINDING = 5  # 每个故障模式最多保留几条证据
_EVIDENCE_MAX_LEN = 220  # 每条证据最多显示多少字符
_MAX_INJECTION_HITS = 5  # 最多标记几条疑似注入
_MAX_UNMATCHED_ERRORS = 10  # 最多列几条"没匹配上任何模式的 ERROR 行"

# 打在疑似注入行前面的标记，模型看到它就明白这行不可信。
INJECTION_MARK = "[⚠疑似指令注入]"


# ── 1. Docker 日志流解码 ────────────────────────────────────────────────────


class _NotMultiplexed(Exception):
    """缓冲区不是"8 字节头 + 内容"的分帧格式时抛出。"""


def _demux_frames(raw: bytes) -> str:
    """解码 Docker 复用日志流（stdout / stderr 分帧）。

    每一帧的格式固定：

        ┌────────┬────────┬────────┬────────┬─────────────────────┐
        │ 类型 1B │ 保留 3B（全 0） │      长度 4B（大端）      │  内容 N 字节  │
        └────────┴────────┴────────┴────────┴─────────────────────┘
        类型：0=stdin 1=stdout 2=stderr

    只要有一帧不符合格式，就说明这不是分帧流（例如容器开了 TTY），
    直接抛 ``_NotMultiplexed`` 让上层回退成纯文本解码。
    """
    parts: list[str] = []
    offset = 0
    total = len(raw)

    while offset < total:
        if total - offset < 8:
            raise _NotMultiplexed("帧头不完整")
        stream_type = raw[offset]
        # 头部的第 1~3 字节保留为 0，第 4~7 字节是大端的长度。
        if stream_type not in (0, 1, 2) or raw[offset + 1 : offset + 4] != b"\x00\x00\x00":
            raise _NotMultiplexed("帧头非法")
        size = int.from_bytes(raw[offset + 4 : offset + 8], "big")
        if size > total - offset - 8:
            raise _NotMultiplexed("声明的长度超过缓冲区")
        parts.append(raw[offset + 8 : offset + 8 + size].decode("utf-8", errors="replace"))
        offset += 8 + size

    return "".join(parts)


def demux_docker_log(raw: bytes) -> str:
    """把 Docker ``/containers/{id}/logs`` 的响应转成日志文本。

    用 ``tty: true`` 启动的容器返回裸字节流，其他容器返回分帧流。
    这里先按分帧格式解析，解析失败再按 UTF-8 纯文本处理。
    """
    if not raw:
        return ""
    try:
        return _demux_frames(raw)
    except _NotMultiplexed:
        return raw.decode("utf-8", errors="replace")


# ── 2. 故障模式表 ───────────────────────────────────────────────────────────

# 排序用的严重程度权重，数字越小越靠前。
_SEVERITY_RANK = {"严重": 0, "警告": 1, "提示": 2}


@dataclass(frozen=True)
class LogPattern:
    """一种可识别的故障模式。"""

    name: str  # 模式标识（英文，便于写测试）
    category: str  # 展示给用户的中文分类
    severity: str  # 严重 / 警告 / 提示
    regex: re.Pattern[str]  # 匹配用的正则
    hint: str  # 可能原因，直接写进报告


@dataclass(frozen=True)
class LogFinding:
    """某个模式的一次汇总结果。"""

    name: str
    category: str
    severity: str
    hint: str
    count: int  # 命中行数
    examples: tuple[tuple[int, str], ...] = field(default=())  # （行号，行内容）


_LOG_PATTERNS: tuple[LogPattern, ...] = (
    LogPattern(
        name="python_traceback",
        category="Python 异常",
        severity="严重",
        regex=re.compile(r"Traceback \(most recent call last\)"),
        hint="Python 抛出了未捕获异常：要么业务代码有缺陷，要么它调用的下游（数据库 / 模型接口）失败了。",
    ),
    LogPattern(
        name="python_exception",
        category="Python 异常",
        severity="严重",
        regex=re.compile(
            r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Z][A-Za-z0-9_]*"
            r"(?:Error|Exception|Fault)\b\s*[:：]"
        ),
        hint="异常类型已经写明：结合异常消息和它上面的调用栈定位到具体代码位置。",
    ),
    LogPattern(
        name="db_connect",
        category="数据库连接失败",
        severity="严重",
        regex=re.compile(
            r"could not connect to server"
            r"|connection to server at .{0,60} failed"
            r"|password authentication failed"
            r"|remaining connection slots are reserved"
            r"|too many clients already"
            r"|FATAL:\s+\S"
        ),
        hint="数据库不可达 / 密码错误 / 连接数打满：先确认数据库容器是否 running，再查连接池配置。",
    ),
    LogPattern(
        name="db_error",
        category="数据库错误",
        severity="严重",
        regex=re.compile(
            r"\b(?:asyncpg|psycopg2?|sqlalchemy)\.\w*(?:Error|Exception)"
            r"|OperationalError|UndefinedColumnError|UndefinedTableError|IntegrityError"
            r"|deadlock detected"
            r"|duplicate key value violates"
            r'|relation "[^"]{0,80}" does not exist'
        ),
        hint="数据库层面报错：常见原因是代码 / ORM 与表结构不一致、死锁或唯一约束冲突。",
    ),
    LogPattern(
        name="http_5xx",
        category="HTTP 5xx 响应",
        severity="严重",
        regex=re.compile(
            r'"\s*5\d\d\s'
            r'|HTTP/\d(?:\.\d)?"\s+5\d\d'
            r"|\b5\d\d (?:Bad Gateway|Service Unavailable|Gateway Time-?out|Internal Server Error)"
            r"|status(?:_code)?[=:]\s*5\d\d"
        ),
        hint="服务端返回 5xx：接口内部报错、上游不可用，或网关（nginx）转发超时。",
    ),
    LogPattern(
        name="timeout",
        category="超时",
        severity="警告",
        regex=re.compile(
            r"\b(?:Read|Connect|Write|Request|Socket)?Timeout(?:Error|Exception)?\b"
            r"|\btimed? ?out\b"
            r"|\bETIMEDOUT\b"
            r"|context deadline exceeded"
        ),
        hint="等待下游（数据库 / 模型接口 / 第三方 API）超过时限：检查下游健康度和超时阈值设置。",
    ),
    LogPattern(
        name="auth",
        category="认证 / 权限失败",
        severity="严重",
        regex=re.compile(
            r"AuthenticationError|invalid_api_key|Incorrect API key"
            r"|401 Unauthorized|403 Forbidden|\bpermission denied\b|Unauthorized"
        ),
        hint="凭证无效或过期、权限不足：核对 API Key、数据库密码、文件和目录权限。",
    ),
    LogPattern(
        name="resource",
        category="资源不足",
        severity="严重",
        regex=re.compile(
            r"MemoryError|OOMKilled|Cannot allocate memory|out of memory"
            r"|no space left on device|disk full|too many open files"
        ),
        hint="内存 / 磁盘 / 文件句柄耗尽：检查容器资源限制、磁盘占用，以及连接或文件是否泄漏。",
    ),
    LogPattern(
        name="network",
        category="网络错误",
        severity="警告",
        regex=re.compile(
            r"Connection refused|Connection reset by peer|Broken pipe"
            r"|Name or service not known|getaddrinfo|no such host"
            r"|Temporary failure in name resolution|EOF occurred"
        ),
        hint="网络层失败：目标服务没监听、DNS 解析不了，或者连接被对端重置。",
    ),
    LogPattern(
        name="crash",
        category="进程崩溃 / 被终止",
        severity="严重",
        regex=re.compile(
            r"\bpanic:|Segmentation fault|core dumped|\bKilled\b|SIGKILL|\bFatal error\b"
        ),
        hint="进程崩溃或被系统杀掉：常见原因是内存超限（OOM）或被外部强制终止。",
    ),
)

# 即使没匹配上上面任何模式，出现这些词也说明是错误级别的日志。
_ERROR_LEVEL_RE = re.compile(r"\b(?:ERROR|CRITICAL|FATAL)\b")


def _clip(line: str, limit: int = _EVIDENCE_MAX_LEN) -> str:
    """截断过长的日志行，避免一行把整个报告撑满。"""
    line = line.rstrip()
    return line if len(line) <= limit else f"{line[:limit]}…"


def _merge_same_category(members: list[LogFinding], max_examples: int) -> LogFinding:
    """把同一分类下的多个模式合成一条结果。

    为什么要合并：``python_traceback`` 和 ``python_exception`` 的分类名都叫
    「Python 异常」。不合并的话报告里会出现「1. [严重] Python 异常 × 2」和
    「3. [严重] Python 异常 × 1」两行**同名条目**，读者会以为是重复输出的 bug。

    合并规则：

    - 严重程度取**最严重**的那个 —— 宁可高估风险，不可低估；
    - 命中次数相加；
    - 证据**轮流取**：先每个模式各拿一条，再回头拿第二条，直到凑满上限。
      这样即使某个模式命中 500 次、另一个只命中 1 次，那 1 次也不会被淹没。
    - 可能原因把各模式的说明拼起来，不丢信息。

    只有一个成员时原样返回，不做任何包装。
    """
    if len(members) == 1:
        return members[0]

    cap = min(max_examples, _MAX_EVIDENCE_PER_FINDING)
    buckets = [list(member.examples) for member in members]
    seen: set[int] = set()

    def take(bucket: list[tuple[int, str]]) -> tuple[int, str] | None:
        """从桶里取出第一条还没被别的模式用过的证据。"""
        while bucket:
            number, line = bucket.pop(0)
            if number not in seen:
                seen.add(number)
                return (number, line)
        return None

    picked: list[tuple[int, str]] = []
    while len(picked) < cap:
        added = False
        for bucket in buckets:
            if len(picked) >= cap:
                break
            item = take(bucket)
            if item is not None:
                picked.append(item)
                added = True
        if not added:  # 所有桶都空了（或剩下的都是重复行）
            break
    picked.sort()  # 报告里按行号顺序读起来更顺

    hints = list(dict.fromkeys(member.hint for member in members))
    return LogFinding(
        name="+".join(member.name for member in members),
        category=members[0].category,
        severity=min(members, key=lambda m: _SEVERITY_RANK.get(m.severity, 9)).severity,
        hint=" ".join(hints),
        count=sum(member.count for member in members),
        examples=tuple(picked),
    )


def analyze_logs(text: str, max_examples: int = 3) -> list[LogFinding]:
    """用模式表匹配 ``text``，返回命中的故障**分类**。

    同一分类可能由多个模式命中（见 ``_merge_same_category``），这里合并成一条，
    所以结果里每个 ``category`` 只出现一次 —— 报告里的"发现 N 类"才和条目数对得上。

    Args:
        text: 日志文本（调用方应当已经脱敏）。
        max_examples: 每个分类最多保留几条证据行。

    Returns:
        按"严重程度 → 命中次数"排序的结果列表；没有命中就返回空列表。
    """
    lines = text.splitlines()
    by_category: dict[str, list[LogFinding]] = {}

    for pattern in _LOG_PATTERNS:
        count = 0
        examples: list[tuple[int, str]] = []
        for number, line in enumerate(lines, start=1):
            if pattern.regex.search(line):
                count += 1
                if len(examples) < min(max_examples, _MAX_EVIDENCE_PER_FINDING):
                    examples.append((number, _clip(line)))
        if count:
            by_category.setdefault(pattern.category, []).append(
                LogFinding(
                    name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    hint=pattern.hint,
                    count=count,
                    examples=tuple(examples),
                )
            )

    findings = [
        _merge_same_category(members, max_examples) for members in by_category.values()
    ]
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), -f.count))
    return findings


def matched_line_numbers(text: str) -> set[int]:
    """返回**所有**能被任一模式命中的行号。

    必须是全集，不能只用 ``LogFinding.examples``：证据行每个模式最多留 3 条，
    如果拿证据行当全集，那么一个命中 100 次的超时错误就会有 97 行被误判成
    「未匹配到已知模式」，报告自相矛盾。
    """
    lines = text.splitlines()
    matched: set[int] = set()
    for pattern in _LOG_PATTERNS:
        for number, line in enumerate(lines, start=1):
            if number not in matched and pattern.regex.search(line):
                matched.add(number)
    return matched


def find_unmatched_error_lines(
    text: str, matched: set[int], limit: int = _MAX_UNMATCHED_ERRORS
) -> list[tuple[int, str]]:
    """错误级别、但没有任何模式认得出来的行 —— 也就是"意料之外"的错误。"""
    out: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(out) >= limit:
            break
        if number in matched:
            continue
        if _ERROR_LEVEL_RE.search(line):
            out.append((number, _clip(line)))
    return out


# ── 3. 提示词注入扫描 ───────────────────────────────────────────────────────

# 日志内容由容器里的程序写出来，内容不可信：可能是程序真的这么打印，
# 也可能是有人故意写进去、想指挥模型。命中不等于恶意，只表示"值得警惕"。
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "要求忽略既有指令",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}"
            r"\b(?:previous|above|prior|earlier|all)\b[^.\n]{0,24}"
            r"\b(?:instruction|prompt|rule|direction)s?\b"
        ),
    ),
    (
        "要求忽略既有指令（中文）",
        re.compile(
            r"忽略(?:以上|之前|前面|先前)?(?:的)?(?:所有)?(?:指令|提示|要求|规则)"
            r"|不要(?:再)?遵守|新指令|新的指令"
        ),
    ),
    (
        "角色扮演劫持",
        re.compile(
            r"(?i)\byou are now\b|\bact as (?:a|an|the)\b|\bpretend (?:to be|you are)\b"
            r"|你现在是|现在开始你是"
        ),
    ),
    (
        "探测系统提示词",
        re.compile(
            r"(?i)\b(?:system prompt|reveal your (?:instructions|prompt))\b"
            r"|系统提示词|打印你的(?:提示|指令)"
        ),
    ),
    (
        "对话 / 工具特殊标记",
        re.compile(
            r"<\|(?:im_start|im_end|system|endoftext|tool_call)\|>"
            r"|\[/?INST\]|<<SYS>>|<tool_call>|</tool_call>|<function_call>"
        ),
    ),
    (
        "伪造对话角色",
        re.compile(r"(?m)^(?:#{0,3}\s*)?(?:System|Assistant|Human)\s*:"),
    ),
)


def scan_injection(text: str) -> list[tuple[int, str, str]]:
    """找出"看起来在给模型下指令"的日志行。

    返回 ``(行号, 命中的类别, 行内容)`` 列表。调用方只**标记**这些行，不删除 ——
    日志行的价值就是它是证据，哪怕内容是恶意的。
    """
    hits: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for label, regex in _INJECTION_PATTERNS:
            if regex.search(line):
                hits.append((number, label, _clip(line)))
                break  # 一行只打一个标签就够了
        if len(hits) >= _MAX_INJECTION_HITS:
            break
    return hits


# ── 4. 时间范围 ─────────────────────────────────────────────────────────────

_TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def extract_time_range(text: str) -> tuple[str, str]:
    """返回这段日志的时间范围（``timestamps=1`` 时 Docker 会给每行加上时间戳）。

    取的是**第一行的第一个时间戳**和**最后一行的第一个时间戳**，而不是整段文本里
    第一个和最后一个时间戳。这个区别很重要：程序自己打印的时间戳也长得一样
    （例如 ``2026-10-14 11:26:54.415 UTC [1] LOG: ...``），如果按"整段文本的最后一个"
    去取，就会取到某一行**中间**的时间戳，得出 11:34 → 09:00 这种倒着走的区间。

    取不到时间戳就返回两个空字符串。
    """
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return "", ""

    def first_stamp(line: str) -> str:
        found = _TIMESTAMP_RE.search(line)
        return found.group(1) if found else ""

    first = next((stamp for stamp in map(first_stamp, lines) if stamp), "")
    last = next((stamp for stamp in map(first_stamp, reversed(lines)) if stamp), "")
    return first, last
