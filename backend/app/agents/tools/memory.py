"""Long-term memory tools — user-scoped persistent memory backed by the LangGraph store.

Memory survives across conversations (threads):

- Facts the model saves are automatically injected into the system prompt by the
  ``supervisor_prompt`` middleware before every model call (best-effort).
- The model can also explicitly search / delete memories through these tools.

Store namespace layout::

    ("memories", <user_id>, <category>) -> key -> {"content": str, "importance": int}

Semantic search is available when an embedding model is configured (see
``app.infra.database.store``); the search tool degrades to a plain listing otherwise.

The user is resolved from the injected ``ToolRuntime`` (the ``AgentRuntimeContext``
dataclass built per request in ``app.utils.request``), *not* from tool arguments —
the model cannot read or forge another user's memory namespace.
"""

import logging
from typing import Tuple

from langchain_core.tools import tool
from langgraph.prebuilt import ToolRuntime
from langgraph.store.base import BaseStore

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────────

_ROOT_NS = "memories"
_MAX_CONTENT_PREVIEW = 300  # chars per memory in search output
_DEFAULT_CATEGORY = "general"
_DEFAULT_IMPORTANCE = 3


# ── Internal helpers ────────────────────────────────────────────────────────


def _resolve(runtime: ToolRuntime) -> Tuple[BaseStore, str] | str:
    """Resolve (store, user_id) from the injected runtime, or an error message.

    Returns:
        A (store, user_id) tuple on success, or a user-facing error string.
    """
    store = runtime.store
    if store is None:
        return "Memory is unavailable in this deployment."

    ctx = getattr(runtime, "context", None)
    user_id = getattr(ctx, "user_id", None) if ctx else None
    if user_id is None:
        return "No authenticated user in this request — memory is user-scoped."

    return store, str(user_id)


def _namespace(user_id: str, category: str | None = None) -> tuple[str, ...]:
    """Build the store namespace for a user (and optional category)."""
    ns = (_ROOT_NS, user_id)
    return (*ns, category) if category else ns


# ── Tools ───────────────────────────────────────────────────────────────────


@tool
async def save_memory(
    content: str,
    key: str,
    category: str = _DEFAULT_CATEGORY,
    importance: int = _DEFAULT_IMPORTANCE,
    runtime: ToolRuntime = None,
) -> str:
    """Save a fact or preference about the user to long-term memory.

    Use this when the user reveals something worth remembering across
    conversations: their environment, preferences, recurring tasks, names,
    decisions, or anything they explicitly ask you to remember. Saving with an
    existing (category, key) pair overwrites the old value.

    Args:
        content: The fact to remember, written as a complete sentence.
        key: Short unique slug identifying this memory, e.g. "server-location".
        category: Grouping label, e.g. "preferences", "environment", "projects".
        importance: How important this memory is, from 1 (trivial) to 5 (critical).

    Returns:
        Confirmation message.
    """
    resolved = _resolve(runtime)
    if isinstance(resolved, str):
        return resolved
    store, user_id = resolved

    if not 1 <= importance <= 5:
        importance = _DEFAULT_IMPORTANCE

    await store.aput(
        _namespace(user_id, category),
        key,
        {"content": content, "importance": importance},
    )
    return f"Saved to long-term memory: '{category}/{key}'."


@tool
async def search_memory(
    query: str,
    category: str = "",
    limit: int = 5,
    runtime: ToolRuntime = None,
) -> str:
    """Search the user's long-term memories for facts relevant to the query.

    Use this before answering questions about the user's environment,
    preferences, or history, and whenever context from earlier conversations
    might matter. Semantic search — describe what you are looking for in
    natural language. (Relevant memories are also injected into your context
    automatically; search only when you need more detail.)

    Args:
        query: What to look for, e.g. "user's production environment details".
        category: Optional grouping filter (e.g. "preferences"). Empty = search all.
        limit: Maximum number of memories to return (default 5).

    Returns:
        Matching memories as a list, or a message when nothing matches.
    """
    resolved = _resolve(runtime)
    if isinstance(resolved, str):
        return resolved
    store, user_id = resolved

    items = await store.asearch(
        _namespace(user_id, category or None),
        query=query,
        limit=limit,
    )
    if not items:
        return "No matching memories found."

    lines = []
    for item in items:
        value = item.value or {}
        content = str(value.get("content", ""))[:_MAX_CONTENT_PREVIEW]
        item_category = (
            item.namespace[-1] if len(item.namespace) > 2 else _DEFAULT_CATEGORY
        )
        lines.append(f"- [{item_category}] {item.key}: {content}")
    return "\n".join(lines)


@tool
async def delete_memory(
    key: str,
    category: str = _DEFAULT_CATEGORY,
    runtime: ToolRuntime = None,
) -> str:
    """Delete one memory by key.

    Use this ONLY when the user explicitly asks to forget something.
    Never delete memories on your own initiative.

    Args:
        key: The key of the memory to delete.
        category: The category the memory was saved under (default "general").

    Returns:
        Confirmation message.
    """
    resolved = _resolve(runtime)
    if isinstance(resolved, str):
        return resolved
    store, user_id = resolved

    await store.adelete(_namespace(user_id, category), key)
    return f"Deleted memory '{category}/{key}'."
