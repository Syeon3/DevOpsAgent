"""Agent tools for AgentHub.

Shared tools that agents use to interact with the world.
Located at app/agents/tools/ — tools are part of the agent layer
and injected into agents via create_agent(tools=[...]).

Available tools:
- time: Current time in any timezone
- web: Web search via Tavily
- vectorstore_retriever: Semantic search over vector store
- memory: Long-term memory (save/search/delete) over the LangGraph store
- ops: Ops tools (project / Docker / service checks + container logs + config / startup analysis) — 只读、白名单制
- log_analysis: 日志故障模式匹配引擎（纯函数，被 ops.check_container_logs 调用）
- config_check: 配置解析与比对引擎（纯函数，被 ops.check_config / diagnose_startup 调用）
"""

from .time import get_current_time
from .web import create_web_search
from .vectorstore_retriever import vectorstore_search
from .memory import delete_memory, save_memory, search_memory
from .ops import (
    OPS_TOOLS,
    check_config,
    check_container_logs,
    check_docker,
    check_project,
    check_service,
    diagnose_startup,
)

__all__ = [
    "get_current_time",
    "create_web_search",
    "vectorstore_search",
    "save_memory",
    "search_memory",
    "delete_memory",
    "OPS_TOOLS",
    "check_project",
    "check_docker",
    "check_service",
    "check_container_logs",
    "check_config",
    "diagnose_startup",
]
