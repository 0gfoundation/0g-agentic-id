# Sealed Bootstrap 框架重设计

本文定义运行在 0G AgenticID 之上的 sealed agent 的链上数据模型、加密布局、
生命周期流程、以及 framework adapter 契约。本文是当前最终版,取代任何
之前版本。

设计上故意保持 framework-agnostic。openclaw 是第一个具体 adapter;
同一套协议必须能在不修改协议层的前提下被未来的 framework(eliza、
自研框架等)复用。


## 1. 目标

1. 保留现有的一次性 bootstrap 行为(attestation 自校验、向 attestor 申请
   provisioning、从链上拉取加密的 iData、解密、交给 agent 运行时)。
2. 增加长期运行的控制平面:
   - HTTP 反向代理 + serve-proof 签名(已有,保留)。
   - Agent 进程 supervisor,带重启与阈值语义。
   - 自评估 agent 进化数据,决定是否回写到链上。
   - framework 支持热重载时,优先热重载。
3. 把"定义 agent 行为的数据"作为可交易资产对待:**只有"既定义 agent 行为
   又可在所有者之间转移"的数据才上链**。其它一律不上链。


## 2. 模块布局

```
test/sealed/
  cmd/bootstrap/main.go        # 入口,组装所有依赖
  internal/
    attest/        # phase 0 自校验(SEAL_KEY 与 attestation 配对)
    provision/    # phase 1 attestor 握手(ECIES 解出 agent_seal_priv)
    chain/        # AgenticID 合约读取(intelligentDatasOf,扫 ITransferred 事件)
    dataplane/    # 0g-storage 上传/下载 + AES-GCM-256 + ECIES 工具
    framework/    # adapter 接口 + 注册
    framework/openclaw/       # openclaw 适配器实现
    manager/      # agent 进程 supervisor (start/stop/restart/health)
    proxy/        # HTTP server + 反向代理 + serve-proof 签名
    state/        # 状态机 + agentState(全局唯一真相源)
    evaluator/    # 按维度的进化触发策略
    uploader/     # 加密 + 上传 0g-storage + 写链 + 发 sealedKey 事件
    report/       # 向 attestor 上报 status
    config/       # env 驱动的配置 + 私钥生命周期
```


## 3. 数据模型

### 3.1 维度

每个 agent 的链上数据被拆成一组固定维度。第一条是协议级别;其余由 adapter
定义。

| 位置 | Label | 拥有者 | openclaw 内容 |
| --- | --- | --- | --- |
| 0 | `framework` | 协议级 | framework 名 + runtime 版本 + 协议 schema 版本 |
| 1 | `persona` | owner | model + agent 级 system prompt + memory 引擎选择 + provider auth profile |
| 2 | `knowledge` | agent 自进化 | MEMORY.md + DREAMS.md(已合并的长期记忆) |
| 3 | `skills` | owner | 已装插件 manifest(name + version + 每插件 config) |
| 4 | `ops` | owner | channels(配置 + system prompt + access policy,**不含**凭据)+ MCP servers + hooks + cron + browser |

其它 framework 可以定义不同维度集;协议层只保留 `framework` 这一个保留 label。

### 3.2 不上链的内容(及理由)

| 状态 | 排除理由 |
| --- | --- |
| Channel 凭据(`agents/<id>/auth-profiles.json`) | 安全风险;非可交易资产;通过 dashboard OAuth 现填 |
| 每日记忆流水(`workspace/memory/YYYY-MM-DD.md`) | 合并前的中间产物;短暂;只有合并产物 MEMORY.md / DREAMS.md 才是资产 |
| 对话 / session 历史 | 隐私敏感;短暂;只有 agent 主动合并到 MEMORY.md 的才被保留 |
| 插件源代码 | 在 npm registry 上;manifest 写明插件名,运行时重装 |
| `gateway.auth.token` | 每次容器启动重新生成 |
| `gateway.controlUi.*` / logging / OTel / cache | 运行时配置,无行为语义 |

这些项要么由 owner 通过 dashboard 在每次部署时提供,要么短暂重新生成,要么
来自公开来源(npm)。**不上链是有意设计**。


## 4. iData Schema

每条 iData entry 形态完全相同。**没有 inline 模式,默认值也不是特例**。
默认值是真实(很小)的加密 blob,有真实 sealedKey,这样 iTransferFrom 的
re-keying 流程对每条 entry 完全一致。

```
IntelligentData {
  dataHash:        bytes32         // 0g-storage 返回的 root hash;永不为零
  dataDescription: string          // 角色 label:"framework" 或 adapter 自定义维度名
}

// ITransferred 事件中:
SealedKeyEntry {
  dataHash:    bytes32             // 跟 IntelligentData.dataHash 配对
  sealedKey:   bytes               // ECIES.encrypt(agent_seal_pubkey, data_key);永不为空
}
```

### 4.1 Label 命名规约

- 全部小写 ASCII,不含空格
- `framework` 是协议保留 label,且必须出现且仅出现一次
- 其它 label 由 adapter 定义(`Framework.Dimensions()` 返回)
- adapter **不能**用 `framework` 作为维度名

### 4.2 每个 plaintext 里装什么

加密前的字节内容因 label 而异。

```
"framework" plaintext:
  JSON: {"name": "<framework name>", "version": "<runtime version>", "schema_version": 1}
  约 50 字节。schema_version 是协议 schema 版本,不是 framework runtime 版本。

"persona" plaintext (openclaw):
  tar.gz,内含:
    + openclaw-config-persona.json   (从 openclaw.json cherry-pick 的子集)
    + PERSONA.md                     (agent 级 system prompt;我们的约定)

"knowledge" plaintext (openclaw):
  tar.gz,内含:
    + workspace/MEMORY.md
    + workspace/DREAMS.md

"skills" plaintext (openclaw):
  JSON manifest:{"plugins": [{"name", "version", "config"}, ...]}

"ops" plaintext (openclaw):
  tar.gz,内含:
    + channels.json   (channel 配置,不含凭据)
    + mcp.json        (MCP server 端点 + 选项)
    + hooks.json      (webhook 配置)
    + cron.json       (定时任务)
    + browser.json    (CDP profile 选择)
```

具体格式由 adapter 决定。Reader(sandbox bootstrap)只把解密后的字节交给
`adapter.Restore(label, bytes)`,让 adapter 自己解读。


## 5. 加密布局

每个维度 entry 的加密链路:

```
plaintext_bytes  = (按维度定义的内容)
data_key         = 随机 32 字节
nonce            = 随机 12 字节
ciphertext       = nonce || AES-GCM-256-encrypt(plaintext_bytes, data_key, nonce) || auth_tag(16)
storage_root     = 0g-storage.upload(ciphertext)
sealed_key       = ECIES.encrypt(agent_seal_pubkey, data_key)
```

链上 entry:`IntelligentData{dataHash: storage_root, dataDescription: label}`。
对应的 sealedKey 在该 tokenId 最新的 `ITransferred` 事件里(按下标跟
IntelligentData 数组配对)。

默认值走同样流程:adapter 给出一份"默认"plaintext(例如内含空 MEMORY.md
的 tar.gz),正常加密上传。**不存在 sentinel 机制**。


## 6. 生命周期流程

### 6.1 Mint

owner 向 attestor 提交表单(model、system_prompt、插件选择等)。attestor 执行:

```
adapter = framework.Get("openclaw")

# 每个维度组合 plaintext。owner 没填的字段走 adapter.Defaults() 默认值。
fw_plain      = json.marshal({"name": "openclaw", "version": "2026.5.6", "schema_version": 1})
persona_plain = adapter.BuildInitial("persona",   merge(adapter.Defaults().persona,   form.persona))
know_plain    = adapter.BuildInitial("knowledge", adapter.Defaults().knowledge)   # owner 不能预填
skills_plain  = adapter.BuildInitial("skills",    merge(adapter.Defaults().skills,  form.skills))
ops_plain     = adapter.BuildInitial("ops",       merge(adapter.Defaults().ops,     form.ops))

entries = []; sealedKeys = []
for (label, plaintext) in [("framework", fw_plain), ("persona", persona_plain),
                            ("knowledge", know_plain), ("skills", skills_plain),
                            ("ops", ops_plain)]:
    data_key      = random(32)
    ciphertext    = AES-GCM(plaintext, data_key)
    storage_root  = 0g-storage.upload(ciphertext)
    sealed_key    = ECIES.encrypt(agent_seal_pubkey, data_key)
    entries.append(IntelligentData{dataHash: storage_root, dataDescription: label})
    sealedKeys.append(sealed_key)

AgenticID.registerWithSeal(
    to:                owner,
    agentURI:          "...",
    metadata:          [],
    intelligentDatas:  entries,
    sealedKeys:        sealedKeys,
    agentSeal_:        <TEE 派生的 agent seal 地址>,
    sealId:            <bytes32>
)
# 合约 emit ITransferred(0, owner, agentId, [...5 个 SealedKeyEntry...])
```

5 次 storage 上传,1 次链上交易。

### 6.2 Evolution(例如 agent 更新 knowledge)

由 evaluator 策略在 agent 侧触发:

```
new_plain     = adapter.EvolutionFor("knowledge")
data_key      = random(32)
ciphertext    = AES-GCM(new_plain, data_key)
new_root      = 0g-storage.upload(ciphertext)
new_sealed_key= ECIES.encrypt(agent_seal_pubkey, data_key)

# 读现有 iData(需要不变维度的 dataHash)和现有 sealedKeys
cur_entries     = AgenticID.intelligentDatasOf(agentId)
cur_sealed_keys = scan_latest_ITransferred(agentId)

# 按 label 找到要替换的那条
new_entries     = list(cur_entries)
new_sealed_keys = list(cur_sealed_keys)
for i, e in enumerate(cur_entries):
    if e.dataDescription == "knowledge":
        new_entries[i]     = IntelligentData{dataHash: new_root, dataDescription: "knowledge"}
        new_sealed_keys[i] = new_sealed_key
        break

# 通过维度感知的写入函数提交(详见 Phase 1 合约改动)
sealUpdate(agentId, new_entries, new_sealed_keys)
# 合约 emit ITransferred(seal, owner, agentId, [...5 个 SealedKeyEntry...])
```

只 1 次 storage 上传(只传变化的维度),1 次链上交易。其它维度的 storage_root
和 sealed_key 保持不变,跟随全量数组重新提交以满足合约的 replace 语义。

### 6.3 Restart(sandbox 启动时的读路径)

```
entries     = AgenticID.intelligentDatasOf(agentId)
sealed_keys = scan_latest_ITransferred(agentId)

by_label = {}
for i, e in enumerate(entries):
    if e.dataDescription in by_label:
        FAIL("duplicate label: " + e.dataDescription)
    by_label[e.dataDescription] = (e, sealed_keys[i])

# Step 1:解 framework binding 选 adapter
fw_e, fw_sk = by_label["framework"]
fw_plain    = decrypt(fw_e.dataHash, fw_sk, agent_seal_priv)
fw_info     = json.parse(fw_plain)
if fw_info["schema_version"] not in SUPPORTED_SCHEMAS:
    FAIL("unsupported schema_version: " + fw_info["schema_version"])
adapter     = framework.Get(fw_info["name"])
adapter.CheckCompatible(fw_info["version"])

# Step 2:每个 adapter 维度恢复
for dim in adapter.Dimensions():
    if dim not in by_label:
        log_warning("missing dimension " + dim + ", using defaults")
        adapter.Restore(dim, adapter.Defaults().for_dim(dim))
        continue
    e, sk      = by_label[dim]
    plaintext  = decrypt(e.dataHash, sk, agent_seal_priv)
    adapter.Restore(dim, plaintext)

# Step 3:链上有但 adapter 不认识的 label(比如新 adapter 删掉了某维度)
for label in by_label:
    if label != "framework" and label not in adapter.Dimensions():
        log_warning("unknown label, ignoring: " + label)

# Step 4:启动 agent。adapter 必须把所有 Restore() 调用合成为有效运行状态。
adapter.Start()
```

注意:`adapter.Restore(dim, ...)` 调用顺序由具体实现决定(map 迭代顺序)。
adapter **必须**保证 Restore 顺序无关且幂等(详见 7.2 节)。

### 6.4 Transfer(iTransferFrom)

ERC-7857 标准 re-keying。新 owner 提供自己的 agent_seal_pubkey;旧 owner
(或其代理)对每条 entry 重新 wrap data_key:

```
for each i in 0..N:
    # 用旧 seal 解出 data_key
    old_dk = ECIES.decrypt(old_seal_priv, old_sealed_keys[i])
    # 用新 owner 的 agent_seal_pubkey 重新 wrap
    new_sk = ECIES.encrypt(new_agent_seal_pubkey, old_dk)
    # 提交 OwnershipProof entry(按 ERC-7857)

# 用新 sealed_keys 调 iTransferFrom。
# 合约校验 proof,替换 sealed keys,emit 新 ITransferred(old, new, agentId, entries)
```

因为每条 entry 形态相同(storage 模式 + 真实 sealedKey),re-keying 循环
没有任何特殊分支。


## 7. Framework Adapter 契约

### 7.1 接口

```go
package framework

type Framework interface {
    // 身份
    Name() string                                       // 例如 "openclaw"
    Version(ctx context.Context) (string, error)        // 检测到的运行时版本
    CheckCompatible(version string) error               // 接受/拒绝 fw_info.version

    // Dimensions 返回该 adapter 理解的 label,**不**含协议级 "framework"。
    // 顺序仅供参考。
    Dimensions() []string

    // Defaults 返回 adapter 对每个维度的"空/默认"内容。
    // mint 时 owner 不填的字段走这个;restart 时链上某维度缺失也走这个。
    Defaults() InitialConfig

    // BuildInitial 在 mint 时根据高层 config(owner 输入合并默认值)
    // 组合出某维度的 plaintext 字节。
    BuildInitial(ctx context.Context, dim string, cfg InitialConfig) ([]byte, error)

    // EvolutionFor 把当前运行时状态导出为某维度的 plaintext 字节
    // (uploader 后面会加密)。
    EvolutionFor(ctx context.Context, dim string) ([]byte, error)

    // Restore 把某维度的 plaintext 应用到 framework 运行时状态。
    // 多次 Restore 调用(每维度一次)**必须满足**交换律和幂等性。详见 7.2 节。
    Restore(ctx context.Context, dim string, plaintext []byte) error

    // 进程生命周期
    Start(ctx context.Context, rt RuntimeContext) (StartResult, error)
    Stop(ctx context.Context, gracefulTimeout time.Duration) error

    // 健康
    Liveness(ctx context.Context) error                // 进程在 + 端口 listen
    Readiness(ctx context.Context) error               // 能接请求
}

// 可选:adapter 实现这个接口,manager 在 evolution 时优先 Reload,
// 否则 fallback 到 Stop+Start。
type Reloadable interface {
    Reload(ctx context.Context, changedDim string) error
}

type RuntimeContext struct {
    DataDir string
    APIKey  string
    Logger  *zap.Logger
}

type StartResult struct {
    Upstream string  // 例如 "http://127.0.0.1:3284"
    Secret   string  // framework 特异凭据(如 openclaw token)
    PID      int
}

type InitialConfig struct {
    // adapter 特定的结构化表单输入。openclaw 用:
    Persona    PersonaSpec
    Skills     []SkillSpec
    Ops        OpsSpec
    // Knowledge 没有高层表单输入;永远从 adapter.Defaults() 起步。
}
```

### 7.2 Compose / Decompose 契约(顺序无关性的硬性要求)

openclaw 把 `openclaw.json` 存在单一文件里,但**多个维度同时贡献该文件的不同
字段**(persona 贡献 `agents.defaults.model`;ops 贡献 `channels`、`mcp` 等)。

adapter 实现**必须**:

1. 维护一份内存中的 composed 状态,**不**在每次 Restore 时直接写盘。
2. 每次 `Restore(dim, plaintext)` 只更新 composed 状态中由该维度拥有的切片。
3. `Start()` 是**唯一**把 composed 状态落盘(例如写到 `~/.openclaw/openclaw.json`)
   并启动运行时进程的函数。
4. `EvolutionFor(dim)` 从运行时实时状态(或某个持久化的快照)中读取由该维度
   拥有的切片,**独立于其它维度**。

这样保证:
- Restore 调用顺序不影响最终 composed 状态。
- 同一维度连续两次 Restore 不同输入,只有第二次生效(语义上幂等)。
- 某维度演化(重新加密、上传、应用)不会影响其它维度。


## 8. Reader 策略

### 8.1 重复 label

如果两条 iData entry 的 `dataDescription` 相同,reader **必须拒绝**启动:

```
log_error("duplicate label", label)
report_error("agent metadata corrupted: duplicate label " + label)
state.Set(Failed)
exit
```

理由:同维度声称两个不同的 storage_root 时 agent 身份不确定。**fail loud
比静默挑一条更安全**。

### 8.2 缺失 label

某 adapter 维度链上没有对应 entry 时,reader 用 `adapter.Defaults()`:

```
log_warning("missing dimension, using defaults", dim)
adapter.Restore(dim, adapter.Defaults().for_dim(dim))
```

理由:adapter 后续版本新增维度时,老 agent 仍可启动。owner 可以后面 mint
新 entry 把这维度补上。

### 8.3 未知 label

链上有 entry 但 label 不在 `adapter.Dimensions()` 也不是协议保留 `framework`,
reader 记 warning 后忽略:

```
log_warning("unknown label, ignoring", label)
```

理由:adapter 后续版本删掉某维度时,老链上数据仍可正常工作。历史 entry
保留在链上(不可变)但变成休眠状态。

### 8.4 schema 版本不匹配

framework binding plaintext 中的 `fw_info.schema_version` 不在 reader 支持
集合时,reader 立即 fail:

```
FAIL("unsupported schema_version: " + n)
```

理由:schema 级别变化按定义就是不兼容的。强制运维方部署支持该 schema 的
sandbox image 是正确做法。


## 9. Schema 版本管理

`schema_version` 放在 framework binding 的 plaintext 里,**不**在链上
dataDescription 字段。这样每条 entry 零开销,同时仍能演化协议。

兼容规则:

- 当前 schema 版本是 `1`
- 老 sandbox image 可以拒绝启动用未来 schema 版本(`fw_info.schema_version > 1`)
  mint 出来的 agent
- 新 sandbox image 必须继续支持 schema 1 与所有更新的 schema(向前兼容 reader)
- schema 版本升级**只**用于"破坏 plaintext 字段语义到老 reader 无法容忍的
  程度"的修改。新增可选字段不需要升级 schema 版本。


## 10. Manager / Supervisor

manager 拥有 agent 进程的生命周期:

- `manager.Start()` 调 `adapter.Start()`,然后每 5 秒轮询 `adapter.Liveness()`
- Liveness 失败时 manager 用 backoff 尝试重启:
  `1s, 2s, 4s, 8s, 16s, 30s, 60s, 60s, ...`
- manager 有可配置的 `maxRetries`(默认 `5`)。超过阈值,state 转入 `Failed`,
  reporter 上报 `error`
- 硬错误(二进制不存在、配置 corrupt)跳过 backoff,直接 `Failed`
- evolution 触发的重启,如果 adapter 实现了 `Reloadable` 就优先用 `Reload(dim)`,
  否则 fallback 到 `Stop + Start`


## 11. 状态机

```
Bootstrapping  -- attest + provision + 链上读 + 解密 + adapter.Restore + adapter.Start
                  此阶段 /hello 返回 503
        |
        v
Running        -- 正常服务。evaluator 周期跑;manager 周期跑 Liveness。
        |
        +-- agent 死了 -----> Restarting (manager backoff 循环)
        |                    /hello 返回 503;重启成功 -> Running;达到 maxRetries -> Failed
        |
        +-- evolution -----> Evolving (跟 Running 并发,**不阻塞 proxy**)
        |                    1) adapter.EvolutionFor(dim)
        |                    2) 加密 + 上传 0g-storage
        |                    3) 链上写 + 等 tx 落块
        |                    4) state.AppendDataHash(dim, new_root)
        |                    5) 可选:adapter.Reload(dim) 或 Stop+Start
        |                    -> Running
        |
        +-- 不可恢复 -------> Failed
                              /hello 返回 503;reporter 发 "error";
                              外层 attestor 决定是否 force-stop sandbox
```

proxy serve-proof 签名永远用 `state.dataHashes` 当前值。这些值只在链上 tx
落块**之后**(上面 step 4)才更新,所以 **proxy 永远不会签出"链上无据可查"
的 dataHash**。


## 12. 存储 / 上传成本(参考)

每次 mint(全默认表单,owner 完全没自定义):

| 动作 | 次数 | 大致成本 |
| --- | --- | --- |
| 0g-storage 上传 | 5(每维度 1 次) | 约 5 份小 ciphertext(每份约 500 字节) |
| 链上交易 | 1(`registerWithSeal`) | 5 条 IntelligentData + 事件里 5 个 SealedKeyEntry |

每次 evolution(只动一个维度):

| 动作 | 次数 | 大致成本 |
| --- | --- | --- |
| 0g-storage 上传 | 1 | 该维度 tar.gz 的大小 |
| 链上交易 | 1(`sealUpdate`) | 全量 5 条 entry 全数组重传(其中 4 条不变) |


## 13. 待办事项

下面这些故意延后,单独跟踪:

1. 合约层写入函数(`sealUpdate`)及维度感知鉴权。Evolution 流程依赖它,
   读流程不依赖。
2. `evaluator` 的具体策略(默认 TimerStrategy;DiffStrategy 与 LLMStrategy
   是后续工作)。
3. Channel 凭据通过 dashboard 注入的实现机制。合约层无关(超出本文范围),
   但设计决定是"短暂存在,永不上链"。
4. 选择性 `iCloneFrom` 语义(只克隆某些维度)。维度独立后理论上可行,
   v1 不做。


## 14. 实施 Phase

| Phase | 范围 | 依赖 |
| --- | --- | --- |
| 1 | 合约:`sealUpdate(tokenId, IntelligentData[], bytes[] sealedKeys)` 带维度感知鉴权 + emit ITransferred | 无 |
| 2 | 重构 `bootstrap.go` 读路径为维度感知(基于 label 分发) | 无(用现有读 API) |
| 3 | 模块拆分:从单文件 `bootstrap.go` 拆到 `internal/` 各包;新增 `manager` | Phase 2 |
| 4 | 出站:`evaluator` + `uploader`;首次接合约新函数 | Phase 1 + Phase 3 |
| 5 | 改 attestor mint 流程:每维度调 `BuildInitial`,加密 + 上传,`registerWithSeal` 写 N 条 entry | Phase 1(合约支持新调用形态) |
| 6 | 文档刷新;每个新包加 README | 最后 |

**Phase 2 可以在 Phase 1 之前做**——读路径用现有的 `intelligentDatasOf` 和
`ITransferred` 事件接口,这两个不变。这样可以**先**部署一个向前兼容的
reader,**后**改写入侧,降低协调迁移的风险。


## 15. Agent 服务扩展性

本章节回答一个实际问题:owner 让 agent "对外暴露一个服务"时,**agent 阻力
最小的路径是什么**,以及系统**怎么自动保证**这条路径的响应都带 serve-proof
签名。

### 15.1 协议契约

`http://8080-<sandbox-id>.<proxy-domain>/` 是唯一对外可达且**保证**带
`X-Agent-Proof` 的 URL 前缀。Verifier SDK **必须**:

1. 只承认带有 `X-Agent-Proof` 的响应是真的
2. 用该 header 校验 agent 的链上 `agentSeal` 地址
3. 交叉校验 `proof.data_hashes` 跟 `intelligentDatasOf(agentId)` 一致

没有有效 `X-Agent-Proof` 的响应**按定义**不属于 sealed agent 的回应,
verifier 视而不见。

### 15.2 信任模型

架构是为**诚实 agent** 设计的——可能有 bug 或者天真,但不恶意。三点观察:

- `agent_seal_priv` 只在 bootstrap 进程内,openclaw 和它 spawn 的子进程
  都拿不到。**只有** `proxy.writeServeProof` 能签名
- 诚实 agent 想让自己的响应可被验证,会主动选**自动签名的路径**(15.4
  节)。它没有动机绕过
- 恶意 agent 即便绕过链上扩展机制,产生的响应没签名。Verifier 协议
  (15.1)直接当不存在,攻击者一无所获

系统**不**做 seccomp / proc 监控 / fork-exec env scrub 来防绕过。
威胁模型接受"恶意 agent 可以跑没签名的服务",前提是这种服务**没有任何权威**。

### 15.3 外部 URL 格式

0g-sandbox proxy 用子域名做端口路由:

```
  http://<port>-<sandbox-id>.<proxy-domain>:<proxy-port>/<path>
         |     |             |              |
         |     |             |              proxy 端口(如 4000)
         |     |             |
         |     |             proxy host(如 47.236.111.154.nip.io)
         |     |
         |     sandbox UUID
         |
         请求转发到容器内的端口
```

具体例子:`http://8080-bd178e46-...nip.io:4000/api/ppt/generate` 命中 sealed
容器内 8080 端口,也就是 bootstrap 的 proxy.Server。

其它端口前缀会尝试访问容器内不同端口。能不能访问取决于服务 bind 到 `0.0.0.0`
还是 `127.0.0.1`。openclaw 用 `--bind loopback` 只 bind 127.0.0.1,daytona
proxy **跨容器 namespace 边界连不到 loopback**,所以 `:3284-<id>...` 这种
URL 自然无法访问。

### 15.4 默认暴露路径:openclaw plugin + `registerHttpRoute`

openclaw plugin 在 `register(api)` 里调
`api.registerHttpRoute({path, auth, match, handler})`,handler 跑在
gateway 进程内,在 `127.0.0.1:3284` 上服务注册的路径。

例子(Node.js plugin 生成 PPT 文件):

```typescript
import PptxGenJS from "pptxgenjs";

export function register(api) {
  api.registerHttpRoute({
    path: "/api/ppt/generate",
    auth: "plugin",       // 信任边界在我们 :8080 上,这里放行
    match: "exact",
    handler: async (req, res) => {
      const body = await readJsonBody(req);
      const pptx = new PptxGenJS();
      // 从 body.topic / body.outline 等填充幻灯片
      const buf = await pptx.write({ outputType: "nodebuffer" });
      res.statusCode = 200;
      res.setHeader("Content-Type",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation");
      res.end(buf);
      return true;
    },
  });
}
```

装好(npm 包 + `openclaw config plugin enable`)之后,路由就在
`127.0.0.1:3284/api/ppt/generate` 上。bootstrap 的 proxy.Server 有
catch-all `/*` 反向代理,所以外部流量打到
`http://8080-<id>.<host>/api/ppt/generate` 会到达 plugin handler,
响应被 `proxy.writeServeProof` 自动签名。

**owner 让 agent 暴露服务时,这是 agent 应该默认选的路径**。plugin 代码
完全不接触 serve-proof 相关逻辑。

### 15.5 agent 怎么知道自己的公开 URL

agent 本身**不知道** sandbox UUID、proxy host,因此也不知道自己的公开 URL。
URL 由 bootstrap 在容器内**拼装**而成,源头是两个 env 变量:

| 拼装片段 | 来源 env | 谁注入 |
| --- | --- | --- |
| `<sandbox-uuid>` | `DAYTONA_SANDBOX_ID` | Daytona 启动容器时自动注入 |
| `<proxy-domain>` | `SANDBOX_PROXY_DOMAIN` | 0g-sandbox proxy 通过 `InjectSeal` 注入,从 billing 服务的 `PROXY_DOMAIN` env 复制过来 |

bootstrap 拼装:
```
SANDBOX_PUBLIC_URL = "http://8080-" + DAYTONA_SANDBOX_ID + "." + SANDBOX_PROXY_DOMAIN
                   = "http://8080-bd178e46-...:4000"
```

`InjectSeal` 运行时 Daytona 还没分配 UUID,所以**不能**直接注入完整 URL ——
但 `SANDBOX_PROXY_DOMAIN` 是静态已知的,`DAYTONA_SANDBOX_ID` 是 Daytona 自身
惯例自动注入的元信息,创建容器后自然就有。**没有两阶段 env 更新的问题**。

bootstrap 拼装好后在三个地方暴露给 agent:

1. **`/hello` 响应**:bootstrap 把 `public_url` 加到签名后的 JSON body 里,
   verifier 可以交叉校验"我访问的 URL"和"agent 自报的 URL"是不是一致

2. **`~/.openclaw/0g-public-url.txt`**:bootstrap 写一个已知路径的文件,
   任何 plugin 可以 `fs.readFile` 拿到 URL 用于自己响应里构造完整链接

3. **`AGENT_PUBLIC_URL` env**:bootstrap 加进 openclaw 子进程的启动 env
   白名单。plugin 直接 `process.env.AGENT_PUBLIC_URL` 读

agent 用其中任意一个把 URL 转告 owner。

如果 `SANDBOX_PROXY_DOMAIN` 没设置(比如本地 dev 跑在 proxy 基础设施之外),
bootstrap 把 `/hello` 的 `public_url` 留空,跳过文件/env 暴露。系统仍可运行,
agent 没法自我广告 URL,owner 需要手动告知。

### 15.6 owner 验证流程

owner 收到 agent 自报的 URL,可以做端到端四步校验:

1. `curl <claimed-url>/hello` 返回 200,且头里有 `X-Agent-Proof`
2. `ethers.verifyMessage(envelope, sig)` 还原出来的地址
   等于链上 `AgenticID.agentSeals[agentId]` 绑定的地址
3. envelope 里的 `public_url` 字段等于 `<claimed-url>`
4. envelope 里的 `data_hashes` 字段等于
   `AgenticID.intelligentDatasOf(agentId)` 转 hex 后的集合

四步全过 → URL 真实可信、agent 是链上对应的、运行时跑在链上声明的数据上。

### 15.7 Future work: 给非 openclaw 服务的多 upstream 路由

如果 agent 想暴露**不是 openclaw 服务**的 endpoint(比如自己跑 Python ML
推理微服务在另一个端口),bootstrap proxy 需要"路径前缀 -> 上游端口"映射:

```go
type RouteRule struct {
    PathPrefix   string  // 例如 "/api/inference/"
    UpstreamPort int     // 9999(永远 127.0.0.1:port)
}
```

路由声明在链上(比如新加一个 `routes` 维度),这样 owner 签名认可、可审计。
**故意不支持运行时动态注册**——否则被攻陷的 openclaw 可以静默把外部流量
导向攻击者的 handler。

延后到真有非 openclaw 服务需求时再做。v1 用 `registerHttpRoute` 就能覆盖
绝大多数场景。


## 16. 术语表

- **agent_seal_priv / agent_seal_pubkey**:每个 agent 由 trusted attestor
  派生的 secp256k1 密钥对,在所有 bootstrap 同一 agent 的 sandbox 间稳定。
  pubkey 通过 `setAgentSeal` 绑到链上,用于 ECIES 包 data_key
- **data_key**:每个 iData entry 用的随机 32 字节 AES-GCM-256 密钥。用
  agent_seal_pubkey 通过 ECIES 封装成 sealedKey
- **dimension(维度)**:agent 定义数据的命名切片(例如 persona、knowledge)。
  每个维度对应链上一条 iData entry
- **framework binding**:协议保留的 iData entry(label = `framework`),
  指明哪个 adapter 负责其它维度
- **label**:`IntelligentData.dataDescription` 字段值,作为 entry 的角色标识
- **schema_version**:协议版本号,在 framework binding plaintext 里。用作
  向前兼容门控
- **sentinel**:本设计**不**使用。默认值是真实加密 blob,不是链上 marker
