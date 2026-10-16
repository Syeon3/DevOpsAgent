# AgentHub 环境配置和使用说明（SETUP）

> 本文档的目标读者：完全陌生的新同学，或者几个月后忘了细节的自己。
> 照着做就能把项目跑起来；遇到问题先翻「四、踩坑记录」和「六、常见问题」。

---

## 一、项目简介

本项目基于开源项目 [AgentHub](https://github.com/realyinchen/AgentHub)（Apache 2.0）二次开发。
AgentHub 是一个基于 **FastAPI + LangGraph** 的多 Agent 运行时平台，本仓库在其基础上：

- 修复了 Windows + Docker 环境下的一系列构建和运行问题（详见踩坑记录）
- 调整了模型配置方式，接入智谱 GLM（open.bigmodel.cn OpenAI 兼容接口）
- **目标方向：面向后端服务的智能运维诊断 Agent** —— 让 Agent 能根据对话排查服务问题。
  目前底座（聊天、多轮记忆、工具调用、模型管理）已跑通，下一步是在
  `backend/app/agents/tools/` 里按需增加运维类工具（如日志查询、指标查询、命令执行）。

### 当前已实现的功能

| 功能 | 说明 |
|---|---|
| Web 聊天 | 多轮对话、流式输出（SSE）、对话历史持久化 |
| 多模型管理 | Web UI 里动态增删模型 / 供应商，无需改代码重启 |
| 动态模型切换 | 聊天框下拉随时切换模型（LiteLLM 统一调用） |
| 工具调用 | 当前时间、Web 搜索（Tavily）、知识库语义检索（pgvector） |
| 长期记忆 | 跨会话记忆（save/search/delete + 自动注入），详见 `AgentHub_MEMORY_IMPLEMENTATION.md` |
| 运维健康检查 | 项目目录 / Docker 容器 / 服务端口三类只读检查，生成中文诊断报告，详见 `项目与服务健康检查功能说明.md` |
| 执行可视化 | Kanban 页面以 DAG 形式展示 Agent 每一步执行过程 |
| 用户体系 | JWT 认证 + 两个内置 mock 用户（Jack / Rose）方便调试 |
| 微信渠道 | 预留 WeChat iLink 机器人接入能力 |

### 当前环境状态（本机）

- 已配置供应商 `local`：base_url = `https://open.bigmodel.cn/api/paas/v4`（智谱 OpenAI 兼容接口），API Key 在 Web UI 设置里配置，加密存于数据库
- 已配置模型 `glm-4.5-flash`（provider=local）
- 系统默认模型（backend/.env）：`zai/glm-4.5-flash`

---

## 二、环境要求

| 项目 | 要求 | 备注 |
|---|---|---|
| 操作系统 | Windows 10/11、macOS、Linux 均可 | 本文以 Windows 11 + Docker Desktop 为准（实际验证过） |
| Docker | Docker Desktop 4.x（含 docker compose v2） | Windows 需启用 WSL2 后端 |
| Git | 任意较新版本 | Windows 下注意 autocrlf 问题（见踩坑记录） |
| Node.js | **仅本地前端开发需要**，18+（Docker 内用 node:24） | 纯 Docker 部署不需要 |
| Python | **仅本地后端开发需要**，3.12 | 纯 Docker 部署不需要 |

磁盘空间预留 10GB 以上（镜像 + 构建缓存）。

---

## 三、快速开始

### 1. 克隆项目

```bash
git clone <仓库地址> AgentHub
cd AgentHub
```

### 2. 配置环境变量

#### backend/.env（必填 3 项，其余有默认值）

```bash
cp backend/.env.example backend/.env
```

| 变量 | 必填 | 说明 |
|---|---|---|
| `SYSTEM_DEFAULT_LLM_MODEL` | ✅ | 系统默认模型，如 `zai/glm-4.5-flash`（LiteLLM 命名格式） |
| `SYSTEM_DEFAULT_LLM_API_KEY` | ✅ | 该模型对应的 API Key |
| `API_KEY_ENCRYPTION_KEY` | ✅ | 加密 Web UI 里保存的各供应商 API Key 用，**生成后不要改**（改了已存 Key 解不开） |
| `JWT_SECRET_KEY` | ✅（生产） | JWT 签名密钥；开发用默认值也能跑，生产务必改 |
| `MODE` | 可选 | `dev` / `prod`，默认 dev |
| `POSTGRES_*` | 可选 | Docker 部署保持默认即可（compose 会自动把 HOST 覆盖为 `db`） |
| `SYSTEM_DEFAULT_EMBEDDING_MODEL` | 可选 | 向量检索用；不用知识库检索功能可不配（其 Key 在 Web UI 的供应商设置里配） |
| `LANGCHAIN_*` | 可选 | LangSmith 链路追踪，不追踪保持 `false` |
| `TAVILY_API_KEY` | 可选 | Web 搜索工具需要 |
| `AMAP_KEY` | 可选 | 高德地图 |
| `WEIXIN_ILINK_BASE_URL` | 可选 | 微信渠道 |

生成加密密钥 / JWT 密钥：

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**注意**：Web UI 里各供应商（如 `local`）的 API Key 是单独在页面设置里填的，加密后存数据库，
不走 .env。`.env` 里的 Key 只服务"系统默认模型"。

#### frontend/.env（通常不用改）

```bash
cp frontend/.env.example frontend/.env
```

- `VITE_API_BASE_URL=/api/v1` —— 保持默认（nginx 反向代理到后端）
- `NGINX_BACKEND_HOST=backend` / `NGINX_BACKEND_PORT=8080` —— Docker 内服务名，保持默认
- 本地前端开发（`npm run dev`，端口 5173）时才需要关心 `VITE_DEV_PROXY_TARGET`

### 3. 启动项目

```bash
# 首次构建（国内网络下 Dockerfile 已内置镜像降级，直接跑即可）
docker compose build

# 启动全部服务
docker compose up -d
```

验证启动成功：

```bash
docker ps    # 应看到 3 个容器：agenthub-db / agenthub-backend / agenthub-frontend，前两个显示 healthy
```

访问地址：

| 地址 | 内容 |
|---|---|
| http://localhost | 前端页面（nginx 80 端口） |
| http://localhost/api/v1/auth/status | 后端接口自检，返回 `{"authenticated":false,...}` 即正常 |
| postgres://localhost:5432 | 数据库直连（langchain/langgraph，库 agentdb） |

> 注意：后端 8080 端口**没有**映射到宿主机，只能通过前端的 nginx 代理（80 端口 `/api/` 路径）访问，这是设计如此。

首次登录：页面提供 mock 用户登录（Jack / Rose），也可以看 WeChat 扫码登录（需要配置渠道）。

### 4. 配置模型（Web UI）

1. 打开 http://localhost → 设置（Settings）→ 模型配置
2. 供应商：选 `local`，填 API Key（智谱）和 base_url `https://open.bigmodel.cn/api/paas/v4`，保存
3. 添加模型：Provider 选 `local`，Model ID 填 `glm-4.5-flash`，保存
4. 聊天框底部下拉选择模型，开聊

---

## 四、踩坑记录（重要）

### 1. Docker 构建时 pip install 卡住（进度条不动、速度在跳）

**原因**：Dockerfile 原本只用清华 PyPI 镜像，且 pip 参数是 `--timeout 120 --retries 5`，
镜像节点一拥塞，每个包可能挂 10 分钟才重试，看起来像死机。

**已修复**：[backend/Dockerfile](backend/Dockerfile) 改为**镜像降级循环**：
清华 → 阿里云 → 官方 PyPI，每次尝试只用单个镜像，超时降到 30 秒 × 3 次，
坏掉的镜像几分钟内自动切换，不再无限挂起。

**如果再卡**：先在宿主机 `curl` 测镜像速度；换时段重试；或检查代理/VPN 是否干扰了 Docker。

### 2. 容器反复崩溃：`exec ./entrypoint.sh: no such file or directory`

**原因**：Windows 上 git 默认 `core.autocrlf=true`，把 `entrypoint.sh` 检出成 CRLF 行尾，
shebang 变成 `#!/bin/bash\r`，Linux 内核找不到解释器。文件明明存在却报"不存在"。

**已修复**（三层保险）：
- 仓库加了 [.gitattributes](.gitattributes)：`*.sh text eol=lf`
- Dockerfile 构建时 `sed -i 's/\r$//' entrypoint.sh` 强制去 CR
- 本地文件已转 LF

**排查技巧**：`head -1 文件 | od -c` 看行尾有没有 `\r`。

### 3. 聊天报 `Model 'xxx' not found in database`（出现过两次，两个不同根因）

这是本项目踩得最深的坑，务必理解：

**第一次（前缀污染）**：前端编辑模型时 PATCH 会把 `provider/` 前缀拼进 `model_id` 存库
（存成 `local/glm-4.5-flash`），而后端查缓存时按裸名查 → 不匹配。
修复：前端 PATCH 归一化剥前缀 + 后端 `manager.get_model()` 宽容匹配（完整名/裸名/后缀三种拼写都能命中）。

**第二次（事务/缓存时序，最隐蔽）**：删除模型后重新添加，聊天**立即**报 not found。
根因：所有 CRUD 只 `flush` 不 `commit`，事务在请求返回后才提交；
而"刷新模型缓存"发生在提交**之前**，用另一条连接读库 → 读不到未提交的新行 → 缓存被清空且没装进新模型。
之后聊天会一直失败，直到某次 CRUD 或重启才自愈。

**已修复**：[backend/app/api/v1/models.py](backend/app/api/v1/models.py) 四个写接口
（增/改/删模型、改供应商）全部改为**先 `await db.commit()` 再刷新缓存**。

**排查命令**（时间线一目了然）：

```bash
docker logs agenthub-backend 2>&1 | grep -E "Refreshing model|POST /api/v1/models|DELETE /api/v1/models|ValueError"
```

### 4. API Key 泄露风险

- `.gitignore` 已包含 `.env`（匹配所有子目录），`backend/.env`、`frontend/.env` **未被 git 跟踪**，实测安全
- **不要**删掉 .gitignore 里的 `.env` 行；**不要** `git add -f` 强制提交 .env
- `.env` 里的 `SYSTEM_DEFAULT_LLM_API_KEY` 是真实 Key，只在本机
- Web UI 里保存的各供应商 Key 用 `API_KEY_ENCRYPTION_KEY` 加密后存数据库，
  换机器迁移时需带上同一个加密密钥，否则已存 Key 解不开
- 若 Key 已泄露：立即去智谱开放平台吊销重发，再更新配置

### 5. 其他已顺手修掉的小坑

- **npm install 慢**：[frontend/Dockerfile](frontend/Dockerfile) 已加 npmmirror 国内镜像，失败自动回退官方源
- **compose SQL 挂载路径错误**：[docker-compose.yml](docker-compose.yml) 原本挂载不存在的
  `init_database.sql`，已改为实际的 `000_init_database.sql`（数据库表实际由后端启动时自动初始化，幂等）

### 6. 聊天正常，但右侧面板报 "Failed to fetch DAG: 404"

**现象**：聊天、长期记忆都正常，但每条 AI 回复右侧的执行步骤（DAG）面板报 404。

**根因**：代码里的 `TraceExecution` 模型（[models/trace.py](backend/app/models/trace.py)）
有 `input_tokens / output_tokens / total_tokens` 三列，但初始化 SQL
（[000_init_database.sql](backend/scripts/sql/000_init_database.sql)）建表时漏了这三列。
聊天结束后落库时报 `UndefinedColumnError`，被代码里的 try/except 静默吞掉 →
trace 永远写不进数据库 → 前端查询必然 404。

**修复**（2026-10-13）：
1. 手动 ALTER 补列（已执行，幂等）：
   ```sql
   ALTER TABLE public.trace_executions
       ADD COLUMN IF NOT EXISTS input_tokens  BIGINT NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS output_tokens BIGINT NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS total_tokens  BIGINT NOT NULL DEFAULT 0;
   ```
2. 初始化 SQL 已补上这三列，新初始化数据库的用户不会再踩坑。

> 排查技巧：trace 落库失败不会影响聊天（异常被吞），要看 `docker logs agenthub-backend`
> 里的 `Failed to persist DAG` 才能发现；`trace_executions` 表 0 行就是信号。

### 7. 运维检查工具"写好了却永远说不可用"——容器是隔离的

**现象**：给 Agent 加了检查宿主机目录 / Docker 容器的工具，代码没问题，
但 Agent 永远回答"路径不在允许范围内"或"Docker 不可用"。

**根因**：backend 容器原本是**完全隔离**的（docker-compose.yml 里只有 db 服务挂了卷），
容器内既看不到宿主机的 `E:\Projects`，也没有 `/var/run/docker.sock`。
工具再怎么写都读不到东西。

**修复**（2026-10-13）：给 backend 服务加两个**只读**挂载：

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # Docker 容器状态查询
      - ${OPS_PROJECTS_DIR:-./}:/ops/projects:ro       # 项目目录检查
```

并用 `OPS_PROJECT_ROOTS=/ops/projects` 告诉工具"只允许查这个目录"。
要检查别的宿主机目录，用环境变量指过去：
`OPS_PROJECTS_DIR=E:/Projects docker compose up -d backend`（改挂载必须重建容器）。

> 排查技巧：`docker exec agenthub-backend ls /ops/projects` ——
> 宿主机目录没挂进来时这里会是空的或报错，一看就知道是挂载问题而不是代码问题。

### 8. 跑后端测试：`No module named pytest`

**原因**：测试依赖（pytest / pytest-asyncio）**故意不装进生产镜像**
（见 [backend/requirements-dev.txt](backend/requirements-dev.txt)）；
而且后端代码是 COPY 进镜像的，每次 `docker compose build backend` 都会
**用新容器替换旧容器**，之前临时 `pip install` 的包会一起消失。

**用法**（脚本会自动装依赖，带国内镜像降级）：

```bash
docker exec -w /app agenthub-backend bash scripts/run_tests.sh
docker exec -w /app agenthub-backend bash scripts/run_tests.sh -k ops -v   # 跑子集
```

实测输出：`286 passed`（见 `项目配置与启动问题分析功能说明.md` 第八节）。

### 9. Docker HTTP API 的 `since` 只认 Unix 时间戳（不是 CLI 那套写法）

**现象**：给容器日志工具传 `since=10m`，Docker 直接返回 HTTP 400：

```json
{"message":"invalid value for \"since\": invalid timestamp ..."}
```

**原因**：`docker logs --since 10m` 里的 `10m` 是 **CLI 自己的语法糖**，
CLI 会先把它换算成 Unix 秒再调用 API。直接调 Engine API 时，
`since` 只接受纯数字的 Unix 时间戳。

实测（对同一容器逐个探测 `/containers/{id}/logs?since=…`）：

| `since` 取值 | 结果 |
|---|---|
| `1750000000` | ✅ 200 |
| `10m` / `1h30m` / `30s` | ❌ 400 |
| `2026-10-14` | ❌ 400 |
| `2026-10-14T00:00:00`、`…Z` | ❌ 400 |

**本项目的处理**：工具内部用 `_since_to_unix_seconds()` 做转换，
所以对**模型和用户**来说 `since=10m` 依然可用；但如果你自己写脚本直接调
Docker API，记得自己换算。

> **通用教训**：CLI 的参数语法 ≠ API 的参数语法。照抄 CLI 文档去调 API 一定会翻车，
> 拿真实请求探测一遍最省事。这也是本次开发中实测才发现的两个 bug 之一。

### 10. Compose 的 `${VAR}` 插值**不认** `env_file`（配了也白配）

**现象**：`.env` 放在 `svc/` 里、由 `env_file` 指过去，compose 里写
`image: myapp:${TAG}`，结果镜像名变成了 `myapp:`（TAG 是空的），
`environment: TOK: ${MY_TOKEN}` 也变成空字符串 —— 但 `env_file` 本身是生效的。

**原因**：Compose 的变量插值发生在**读取 compose 文件的那一刻**，它只查两个地方：
**compose 文件同级目录的 `.env`** 和 **shell 环境变量**。
`env_file` 是"容器启动时注入给进程的环境变量"，两者时序不同 ——
`env_file` 里的值进入容器时，`${...}` 早就替换完了。

实测原文（`docker compose config`，`svc/.env` 里写了 `TAG=v1.2.3` / `MY_TOKEN=abc`）：

```
level=warning msg="The \"TAG\" variable is not set. Defaulting to a blank string."
level=warning msg="The \"MY_TOKEN\" variable is not set. Defaulting to a blank string."
name: compose-interp-demo
services:
  app:
    environment:
      MY_TOKEN: abc      # ← env_file 确实注入进来了
      TAG: v1.2.3        # ← 同上
      TOK: ""            # ← 但 ${MY_TOKEN} 在插值阶段就已经是空的
    image: 'myapp:'      # ← 镜像名被截断成 myapp:
```

**本项目的处理**：`check_config` / `diagnose_startup` 会检查每个 `${VAR}`
有没有默认值、有没有在同级 `.env` 或环境里定义，没定义就报
「Compose 变量未定义」并说明这个坑。

**规避**：把参与插值的变量写进 **compose 同级的 `.env`**，
或者写成带默认值的形式 `${VAR:-默认值}`。

---

## 五、项目架构

### 整体三层

```
浏览器 (React)
   │  http://localhost:80  (nginx 托管前端静态文件 + /api 反向代理)
   ▼
frontend 容器 (nginx) ── /api/* ──► backend 容器 (FastAPI, 8080, 仅内网)
                                        │
                                        ▼
                                   db 容器 (PostgreSQL 18 + pgvector)
```

### 后端内部结构

```
backend/app/
├── api/v1/          REST 接口：auth、models(模型管理)、chat(会话/流式)、traces、weixin
├── agents/          Agent 层：supervisor 统一入口 + middleware(动态模型选择) + tools
│   └── tools/       时间 / Web 搜索(Tavily) / 向量库语义检索
├── services/        业务编排：streaming(SSE 流式输出)、chat
├── infra/           基础设施：llm(模型管理器+缓存)、database(pgvector)、auth(JWT)、security
├── crud/            数据库读写层
├── models/          SQLAlchemy ORM 表结构
└── schemas/         Pydantic 请求/响应模型
```

### 关键机制

- **模型管理**：`providers` + `models` 两张表存配置；`ModelManager` 内存缓存，
  写接口提交事务后刷新缓存（见踩坑记录 3）；运行时通过 `factory.get_llm()` 每次创建
  新的 ChatLiteLLM 实例，支持请求级动态切换模型（middleware 读取上下文里的 model_name）
- **对话记忆**：会话存 `conversations` 表；LangGraph 状态通过 `langgraph-checkpoint-postgres`
  存入 PostgreSQL，容器重启不丢
- **向量检索**：pgvector 扩展 + langchain_pg_* 表，用于知识库工具
- **前端**：React 19 + Vite + Tailwind；`features/chat`（聊天+模型管理），
  `features/kanban`（Agent 执行 DAG 可视化）

### 二次开发方向（运维诊断 Agent）

底座已具备多轮对话、工具调用、动态模型。做运维 Agent 主要在
`backend/app/agents/tools/` 添加工具（如日志查询、指标查询、告警查询），
在 `backend/app/agents/prompts/` 调整系统提示词，告诉 Agent 遇到哪类问题用哪个工具。

---

## 六、常见问题

### 聊天报错怎么排查

1. 先看报错文案分类：
   - `Model 'xxx' not found in database` → 模型缓存问题，看踩坑记录 3；
     应急办法：重启后端容器 `docker compose restart backend`（启动时会重建缓存）
   - `AuthenticationError / 身份验证失败` → API Key 错了或过期，去设置里核对供应商 Key
   - `Connection error / timeout` → base_url 不通或模型服务限流
2. 查后端日志：

```bash
docker logs -f agenthub-backend          # 实时日志
docker logs agenthub-backend 2>&1 | grep -iE "error|valueerror" | tail -20
```

3. 查数据库状态：

```bash
docker exec agenthub-db psql -U langchain -d agentdb -c "SELECT provider, model_id, is_active FROM models;"
docker exec agenthub-db psql -U langchain -d agentdb -c "SELECT provider, is_openai_compatible, base_url FROM providers;"
```

### 端口冲突

- **80 被占**（Windows 上常见 IIS/其他服务占用）：改 [docker-compose.yml](docker-compose.yml)
  里 frontend 的 `"80:80"` 为如 `"8088:80"`，然后访问 http://localhost:8088
- **5432 被占**（本机装过 PostgreSQL）：改 db 的 `"5432:5432"` 为如 `"5433:5432"`
  （容器内端口保持 5432，只改左侧宿主机端口）

### 如何切换/新增模型

- **切换**：聊天框底部下拉直接选
- **新增**：设置 → 模型配置 → 供应商处填 API Key 和 base_url → 添加模型。
  对 OpenAI 兼容的接口（智谱、DeepSeek、Kimi 等），Provider 选 `local` 或新建，
  `is_openai_compatible` 开启，base_url 填对应的 `/v4` 端点即可
- **系统默认模型**：改 backend/.env 的 `SYSTEM_DEFAULT_LLM_MODEL` + Key，重启后端

### 改了代码怎么生效

```bash
docker compose build backend     # 或 frontend
docker compose up -d
```

前端只改了 `src/` 时构建约 1-3 分钟（npm 层有缓存）；后端改代码构建很快（pip 层有缓存）。

### 完全重置（数据库也不要了）

```bash
docker compose down -v    # -v 会删除数据库数据卷，谨慎！
docker compose up -d
```

### 本地开发模式（不进 Docker）

- 前端：`cd frontend && npm install && npm run dev`（http://localhost:5173，vite 代理到 127.0.0.1:8080）
- 后端：需要本机 Python 3.12 + PostgreSQL（含 pgvector），
  `cd backend && pip install -r requirements.txt && python run_backend.py`，
  并把 `POSTGRES_HOST` 改回 `localhost`
