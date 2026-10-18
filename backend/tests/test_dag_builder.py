"""DagBuilder 的回归测试：摘要压缩上下文后仍能还原本轮完整步骤。

背景：``SummarizationMiddleware`` 在 token 超限时会用
``[RemoveMessage(REMOVE_ALL_MESSAGES), 摘要, 最近 N 条]`` 重写消息列表。
最终状态的消息数因此可能不增反减，``messages[before_message_count:]``
会切出空列表，右侧执行面板显示"该会话没有记录的步骤"。

对应修复：``DagBuilder`` 改为遍历本轮 checkpoint 历史，按消息 id 取并集，
被摘要删掉的消息仍然能从更早的快照里找回来。

Run with:  python -m pytest      (from the backend/ directory)
"""

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from app.utils.dag import DagBuilder


class _Snapshot:
    """最小化的 StateSnapshot 替身，只保留 DagBuilder 用到的字段。"""

    def __init__(self, checkpoint_id: str, messages: list):
        self.config = {"configurable": {"checkpoint_id": checkpoint_id}}
        self.values = {"messages": messages}


class _FakeAgent:
    """只实现 DagBuilder 需要的两个异步查询方法（不连数据库）。"""

    def __init__(
        self,
        before_id: str,
        before_messages: list,
        snapshots: list,
        final_messages: list,
    ):
        self._before_id = before_id
        self._before_messages = before_messages
        self._snapshots = snapshots  # 旧 → 新
        self._final_messages = final_messages

    async def aget_state(self, config):
        checkpoint_id = config["configurable"].get("checkpoint_id")
        if checkpoint_id == self._before_id:
            return _Snapshot(self._before_id, self._before_messages)
        return _Snapshot("final", self._final_messages)

    async def aget_state_history(self, config):
        # 与真实 API 一致：从新到旧
        for snapshot in reversed(self._snapshots):
            yield snapshot


def _old_messages(count: int = 23) -> list:
    """构造"上一轮结束"时的历史消息（数量超过摘要后保留的 20 条）。"""
    return [
        HumanMessage(content=f"旧问题{i}", id=f"old-h{i}") for i in range(count)
    ]


def _summary_message() -> HumanMessage:
    """构造 SummarizationMiddleware 注入的摘要消息。"""
    return HumanMessage(
        content="Here is a summary of the conversation to date:\n\n……",
        id="summary",
        additional_kwargs={"lc_source": "summarization"},
    )


def _summarized_turn(old: list, turn: list, keep: int = 20) -> list:
    """模拟摘要：摘要消息 + 最近 keep 条消息。"""
    return [_summary_message()] + (old + turn)[-keep:]


async def test_dag_rebuilt_from_history_when_summarization_shrinks_state():
    """本轮消息被摘要挤出最终状态时，仍应从 checkpoint 历史还原全部步骤。"""
    old = _old_messages(23)
    human = HumanMessage(content="帮我做一次完整系统体检", id="turn-h")
    ai_tool = AIMessage(
        content="",
        id="turn-a1",
        tool_calls=[{"name": "check_docker", "args": {}, "id": "call-1"}],
    )
    tool = ToolMessage(
        content="3 个容器全部健康",
        id="turn-t1",
        tool_call_id="call-1",
        name="check_docker",
    )
    ai_final = AIMessage(content="体检完成，一切正常", id="turn-a2")

    snapshots = [
        # 真实的历史列表包含本轮起点这个 snapshot，遍历到它时停止
        _Snapshot("before", old),
        _Snapshot("c1", old + [human]),
        _Snapshot("c2", old + [human, ai_tool]),
        _Snapshot("c3", old + [human, ai_tool, tool]),
        # 摘要发生：最终状态只剩 21 条，比本轮开始前的 23 条还少
        _Snapshot("c4", _summarized_turn(old, [human, ai_tool, tool])),
        _Snapshot("c5", _summarized_turn(old, [human, ai_tool, tool]) + [ai_final]),
    ]
    final = _summarized_turn(old, [human, ai_tool, tool]) + [ai_final]
    assert len(final) <= len(old), "前置条件：按条数切片会得到空列表"

    agent = _FakeAgent("before", old, snapshots, final)
    dag = await DagBuilder(agent).get_execution_dag(
        "thread-1",
        before_checkpoint_id="before",
        before_message_count=len(old),
    )

    assert [node.message_type for node in dag.steps] == ["human", "ai", "tool", "ai"]
    assert dag.steps[0].content == "帮我做一次完整系统体检"
    assert dag.steps[2].tool_name == "check_docker"
    assert dag.steps[2].tool_output == "3 个容器全部健康"
    # 摘要消息不是用户输入，不能出现在步骤里
    assert all("summary of the conversation" not in (s.content or "") for s in dag.steps)
    # 用户 → AI → 工具 → AI 的连线完整
    assert len(dag.edges) == 3


async def test_dag_falls_back_to_message_count_without_checkpoint_id():
    """首次对话没有 before_checkpoint_id 时，仍按条数切片。"""
    old = _old_messages(2)
    human = HumanMessage(content="你好", id="turn-h")
    answer = AIMessage(content="在线", id="turn-a")
    final = old + [human, answer]

    agent = _FakeAgent("before", old, [], final)
    dag = await DagBuilder(agent).get_execution_dag(
        "thread-2",
        before_checkpoint_id=None,
        before_message_count=len(old),
    )

    assert [node.message_type for node in dag.steps] == ["human", "ai"]
    assert dag.steps[-1].content == "在线"


async def test_dag_falls_back_when_boundary_checkpoint_is_missing_from_history():
    """历史被裁剪、找不到本轮起点时，退回按条数切片而不是返回空 DAG。"""
    old = _old_messages(2)
    human = HumanMessage(content="继续", id="turn-h")
    answer = AIMessage(content="好的", id="turn-a")
    final = old + [human, answer]

    snapshots = [_Snapshot("c1", final)]
    agent = _FakeAgent("before", old, snapshots, final)
    dag = await DagBuilder(agent).get_execution_dag(
        "thread-3",
        before_checkpoint_id="before",
        before_message_count=len(old),
    )

    assert [node.message_type for node in dag.steps] == ["human", "ai"]
