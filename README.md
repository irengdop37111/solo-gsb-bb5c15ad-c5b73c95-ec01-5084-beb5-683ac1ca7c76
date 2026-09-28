# JSON Redaction API

基于 **Python + FastAPI** 的 JSON 结构脱敏服务。接收任意 JSON 文档与一组规则，
按 [JSON Pointer (RFC 6901)](https://www.rfc-editor.org/rfc/rfc6901) 路径定位节点，
支持 `*` / `**` 通配，执行 `mask`、`remove`、`sha256` 三种动作，并返回完整审计轨迹。

规则集既可以随请求**内联**提供，也可以存入服务内置的**持久化版本化策略库**
（SQLite）：策略按名字管理，每次更新生成不可变递增版本，脱敏时可引用最新版本或
锁定任意历史版本，审计轨迹标明实际生效的策略名与版本。

## 一键启动（8080 端口）

```bash
docker compose up --build
```

服务在 <http://localhost:8080> 就绪：

- `POST /redact` — 脱敏接口（内联规则或引用策略，二选一）
- `PUT  /policies/{name}` — 创建/更新策略（ETag 乐观并发控制）
- `GET  /policies/{name}` — 查询策略最新版本
- `GET  /policies/{name}/versions/{version}` — 查询不可变历史快照
- `POST /policies/{name}/impact` — 策略变更影响预览（只读，不产生新版本）
- `GET  /health` — 健康检查
- `GET  /docs`   — Swagger UI（可直接在线试用）

策略库为 SQLite 数据库，compose 已挂载命名卷 `policy-data` 到容器内 `/data`，
容器重建或重启后**所有历史版本均保留**：

```bash
docker compose down          # 仅停容器，卷保留
docker compose down -v       # 同时删除策略数据卷（谨慎）
docker compose logs -f redact
```

不想用 Docker 时：

```bash
pip install -r requirements.txt
REDACT_SALT=change-me POLICY_DB=./data/policies.db \
  uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 规则路径（JSON Pointer + 通配）

| 写法 | 含义 |
| --- | --- |
| `/users/0/email` | 字面路径；`~1` 表示 `/`，`~0` 表示 `~`（RFC 6901 转义） |
| `""`（空字符串） | 整个文档根节点 |
| `/users/*/email` | `*` 匹配**恰好一个**段（任意 key 或数组下标） |
| `/**/ssn` | `**` 匹配**零个或多个**段，可位于任意深度（含零宽，即 `/ssn` 也命中） |
| `/drop/**` | 命中 `/drop` 子树内所有节点（含 `/drop` 自身） |

数组下标即对应段，例如 `/items/2`。带 `/`、`~` 的 key 按 RFC 6901 转义书写。

## 动作

| 动作 | 效果 |
| --- | --- |
| `mask` | 将节点整体替换为固定字符串 `"***REDACTED***"` |
| `remove` | 删除对象键或数组元素；命中根节点时结果为 `null` |
| `sha256` | 将节点替换为加盐哈希字符串。哈希输入为 `SHA256(REDACT_SALT + canonical_json(node))`，其中 canonical JSON 对 key 排序、无多余空白（`sort_keys=True, separators=(",",":")`），故哈希结果与 key 书写顺序无关 |

### 盐值配置

盐通过环境变量 `REDACT_SALT` 注入，默认空字符串。Docker 部署时可在 Shell 或 `.env`
文件中设置：

```bash
echo 'REDACT_SALT=your-strong-secret' > .env
docker compose up --build -d
```

相同输入 + 相同盐才会得到相同摘要；**请在生产环境务必设置非空盐**。

## 多规则冲突的裁决

当多条规则同时命中同一节点时，按以下优先级选出**唯一**生效规则：

1. **字面段更多**者胜（精确路径优先于通配路径）；
2. 字面段相同时，**通配段更少**者胜（`/users/*/email` 胜过 `/**/*/email`）；
3. 仍相同时，**声明顺序更靠后**者胜（后写的覆盖先写的）。

所有匹配均基于**原始结构**一次性计算完成：先解析出每个原始节点的命中规则，
再统一执行。因此删除数组元素不会造成后续指针错位——例如同时配置
`/items/0` remove 与 `/items/*/x` mask，`/items/2/...` 始终指向原始第 3 个元素。

当一个节点被子树规则整体处理（mask/remove/sha256）时，其后代不会重复处理，
审计轨迹中只记录该子树的最近命中规则。

## 持久化策略库

策略是一组规则的**命名快照**。`PUT /policies/{name}` 采用全量替换语义，并通过
`If-Match` ETag 实现乐观并发控制：

| 场景 | 请求 | 结果 |
| --- | --- | --- |
| 首次创建 | `PUT`，**不带** `If-Match` | `201`，生成版本 1，返回该版本 ETag |
| 后续更新 | `PUT`，携带当前版本的 `ETag` | `200`，追加不可变新版本（2、3、…，严格递增） |
| 更新未带 / 带了过期 ETag | — | `412 Precondition Failed`，响应体带回 `current_etag` |
| 带 `If-Match: *` | 要求策略已存在才更新，不存在则 `412` |

每个版本的规则内容一旦写入便**不可变、不删除**；ETag 由
`SHA256(name, version, canonical_rules)` 派生，即使两版规则完全相同，版本不同则
ETag 不同。版本号在每个策略内部从 1 开始连续递增，无空洞。

创建策略：

```bash
curl -s -X PUT http://localhost:8080/policies/pii-basic \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"pointer":"/users/*/email","action":"mask"}]}' \
  -D -
# HTTP/1.1 201 Created
# ETag: "8413359f14af6314d496d407e5500e6d"
# {"name":"pii-basic","version":1,"rules":[...],"etag":"\"...\"","created_at":"..."}
```

更新时必须回传上一版的 ETag（并发更新时只有一方成功，另一方拿到 412 后重新读取
`current_etag` 再重试即可）：

```bash
curl -s -X PUT http://localhost:8080/policies/pii-basic \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "8413359f14af6314d496d407e5500e6d"' \
  -d '{"rules":[
        {"pointer":"/users/*/email","action":"mask"},
        {"pointer":"/users/*/password","action":"remove"}
      ]}'
```

查询快照（旧版本永不改变，可长期复现）：

```bash
curl -s http://localhost:8080/policies/pii-basic                 # 最新版
curl -s http://localhost:8080/policies/pii-basic/versions/1      # 指定历史版
# 策略或版本不存在 -> 404
```

策略名限 `[A-Za-z0-9]` 开头，可含 `.` `_` `-`，长度 1–64。

## 策略变更影响预览（只读）

修改策略前，可以用 `POST /policies/{name}/impact` 先预览候选规则相对**当前版本**
会带来哪些差异。接口对当前策略执行一次**原子读取**，**不会创建新版本、不写入任何
数据**；服务对每个样本分别用当前规则与候选规则各跑一遍脱敏，再对比两次**审计轨迹
中的实际生效动作**，按原始 JSON Pointer 输出三类差异：

| 类别 | 含义 |
| --- | --- |
| `added` | 候选规则下新出现的生效动作（当前规则完全不处理该原始节点） |
| `removed` | 候选规则下消失的生效动作（当前规则处理、候选规则不再处理） |
| `changed` | 同一原始 Pointer 在两边都有动作，但**生效动作不同**（如 `mask` → `sha256`） |

对比基于**审计中实际生效的规则**，因此引擎既有的短路与稳定性保证在预览中同样成立：

- **子树短路**：父节点整体 `mask`/`remove`/`sha256` 后，后代不会出现在任何一方的
  审计里。例如当前对 `/card` 整体 mask，候选即使新增 `/card/cvv` remove，该规则也
  永远不会生效，预览为空；若候选去掉父规则改为分别处理子节点，则 `/card` 计入
  `removed`、各子节点计入 `added`。
- **数组下标稳定**：审计 Pointer 始终指向**原始下标**，候选规则删除数组元素不会让
  后续下标错位；例如新增 `/items/0` remove，只会报 `/items/0` 新增、`/items/0/v`
  消失，`/items/1/v`、`/items/2/v` 因两边动作相同而不报。
- 仅命中规则不同（如两条不同的 `mask` 规则）但**生效动作相同**时不计差异——对文档
  的外部影响没有变化。

请求体携带候选 `rules`（1～20 个样本放在 `samples`；候选规则本身允许为空，表示
预览“清空策略”的效果）：

```bash
curl -s -X POST http://localhost:8080/policies/pii/impact \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [
      {"pointer": "/users/*/email", "action": "sha256"},
      {"pointer": "/users/*/password", "action": "remove"}
    ],
    "samples": [
      {"users": [{"email": "a@x.io", "password": "p", "name": "a"}]}
    ]
  }'
```

响应返回基准策略版本（原子读到的具体 `version` 与 `etag`）、逐样本差异与汇总计数：

```json
{
  "baseline": { "name": "pii", "version": 2, "etag": "\"…\"" },
  "samples": [
    {
      "index": 0,
      "diff": {
        "added": [
          { "pointer": "/users/0/password", "action": "remove",
            "rule": { "index": 1, "pointer": "/users/*/password", "action": "remove" } }
        ],
        "removed": [],
        "changed": [
          { "pointer": "/users/0/email",
            "before": { "action": "mask",
                        "rule": { "index": 0, "pointer": "/users/*/email", "action": "mask" } },
            "after":  { "action": "sha256",
                        "rule": { "index": 0, "pointer": "/users/*/email", "action": "sha256" } } }
        ]
      },
      "counts": { "added": 1, "removed": 0, "changed": 1 },
      "has_changes": true
    }
  ],
  "summary": { "added": 1, "removed": 0, "changed": 1, "samples": 1 }
}
```

错误情况：策略不存在 → `404`；样本数量不在 1～20、候选规则的 pointer/action 非法或
出现多余字段 → `422`。

## 请求 / 响应

### 规则来源：内联 rules 与 policy 引用二选一

`POST /redact` 的请求体在两种规则来源间**互斥**：

- 内联：`rules`（与旧版完全兼容；省略 `rules` 与 `policy` 时按空规则处理）；
- 引用：`policy: {"name": ..., "version": 可选}`。
  - 不指定 `version`：处理请求时**原子读取**当时最新已提交版本；
  - 指定 `version`：锁定不可变历史快照，结果永远可复现。
- 同时给 `rules` 与 `policy` → `422`；引用的策略/版本不存在 → `404`。

内联请求：

```json
{
  "data": { "任意": "JSON" },
  "rules": [
    { "pointer": "/users/*/password", "action": "remove", "name": "可选名称" },
    { "pointer": "/users/*/email", "action": "mask" },
    { "pointer": "/**/ssn", "action": "sha256" }
  ]
}
```

策略引用请求：

```json
{
  "data": { "users": [{ "email": "a@x.io", "password": "p" }] },
  "policy": { "name": "pii-basic" }
}
```

锁定历史版本：`"policy": {"name": "pii-basic", "version": 1}`。

响应体：

```json
{
  "redacted": { "users": [{ "email": "***REDACTED***" }] },
  "audit": [
    {
      "pointer": "/users/0/email",
      "action": "mask",
      "rule": { "index": 0, "pointer": "/users/*/email", "action": "mask" },
      "policy": { "name": "pii-basic", "version": 2 }
    }
  ],
  "policy": { "name": "pii-basic", "version": 2 }
}
```

- `redacted`：脱敏结果（输入文档不会被修改）；
- `audit`：每个实际生效的动作一条记录，按原始文档深度优先顺序排列；
  - `pointer`：被处理节点在**原始文档**上的 JSON Pointer；
  - `action`：实际执行的动作；
  - `rule`：命中的规则，含声明下标 `index`、规则 `pointer`、`action` 及可选 `name`；
  - `policy`：规则来自策略时出现，标明**实际生效**的策略名与具体版本（未指定版本
    时此处展示原子解析出的版本号）；内联规则时该字段缺省。
- 顶层 `policy`：与审计中的含义相同；内联请求为 `null`。

## 端到端示例

```bash
# 1) 创建 v1（-D - 把响应头也打印出来，从中取 ETag）
ETAG=$(curl -s -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"pointer":"/users/*/email","action":"mask"}]}' \
  -D - -o /dev/null | grep -i '^etag:' | tr -d '\r' | awk '{print $2}')
echo "$ETAG"   # 形如 "8413359f14af6314d496d407e5500e6d"

# 2) 用当前 ETag 更新到 v2（密码也删除）
curl -s -X PUT http://localhost:8080/policies/pii \
  -H 'Content-Type: application/json' -H "If-Match: $ETAG" \
  -d '{"rules":[
        {"pointer":"/users/*/email","action":"mask"},
        {"pointer":"/users/*/password","action":"remove"}
      ]}'

# 3) 不传 version -> 自动使用最新版（v2），响应/审计带 policy.version=2
curl -s -X POST http://localhost:8080/redact \
  -H 'Content-Type: application/json' \
  -d '{"data":{"users":[{"email":"a@x.io","password":"p"}]},"policy":{"name":"pii"}}'

# 4) 锁定 v1 -> 历史行为永远一致（密码不会被删）
curl -s -X POST http://localhost:8080/redact \
  -H 'Content-Type: application/json' \
  -d '{"data":{"users":[{"email":"a@x.io","password":"p"}]},"policy":{"name":"pii","version":1}}'
```

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REDACT_SALT` | 空 | `sha256` 动作的盐，生产环境务必设置非空值 |
| `POLICY_DB` | `/data/policies.db`（镜像内） | SQLite 策略库路径；compose 挂载命名卷到 `/data`，本地裸跑可指向任意可写路径（目录会自动创建） |

SQLite 以 WAL 模式运行；写事务使用 `BEGIN IMMEDIATE` + ETag 乐观锁，读不阻塞写。
更新冲突时失败方得到 `412`，重读 `GET /policies/{name}` 的 ETag 后重试即可。

## 本地开发与测试

```bash
pip install -r requirements.txt pytest httpx
python -m pytest -q
```

测试使用临时数据库文件（见 `tests/conftest.py`），互不污染。

## 项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 应用：/redact、/policies、/impact 路由
│   ├── redaction.py     # 核心引擎：pointer 解析、通配匹配、冲突裁决、动作执行
│   ├── impact.py        # 影响预览：两次审计对比 added/removed/changed
│   ├── policy_store.py  # SQLite 版本化策略库：ETag 乐观锁、不可变版本、原子读取
│   ├── schemas.py       # 请求/响应 Pydantic 模型
│   └── config.py        # REDACT_SALT / POLICY_DB 环境变量
├── tests/
│   ├── conftest.py      # 每测例一个临时 SQLite 库
│   ├── test_engine.py   # 引擎单元测试（通配、优先级、数组稳定性、根节点等）
│   ├── test_impact.py   # 影响预览测试（短路、下标稳定、逐样本差异、404/422）
│   ├── test_api.py      # /redact HTTP 层集成测试
│   └── test_policies.py # 策略库测试：ETag 生命周期、并发更新、历史复现
├── Dockerfile           # 内置 /data 卷点（nobody 可写）
├── docker-compose.yml   # 命名卷 policy-data -> /data，8080 端口
└── requirements.txt
```

## 安全说明

- 盐只影响 `sha256` 动作，mask 标记固定可见；不要把哈希当作加密，它无法还原但可被字典猜测。
- 服务本身不做鉴权/限流，生产环境请置于网关之后并妥善保管盐值（不要提交 `.env`）。
