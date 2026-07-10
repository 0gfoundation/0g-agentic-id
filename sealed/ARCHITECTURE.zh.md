# sealed 架构

sealed 是 0G AgenticID 系统中的 **agent 运行时容器** —— 在 TEE
sandbox 里把链上一组加密的 iData 还原成可运行的 agent，跑起来后
持续把 agent 的状态演化写回链上。它跑在受 attestor 远程认证 (RA)
后下发密钥的 sandbox 里，进程内既是 framework 适配器的宿主，也是
对外 :8080 的反向代理，还顺便提供一个 unix socket 让 agent 本人
做需要钱包私钥的签名。

跟它对接的外部组件：

| 组件 | 关系 |
|---|---|
| attestor | sandbox 起来后向 attestor 发起 RA，换 `agent_seal_priv`。详见 `0g-agent-nft` 仓库 |
| AgenticID 合约 | 读 `intelligentDatasOf` / `sealedKeysOf`、签 `update` tx 把演化推上链 |
| 0G storage | 每条 iData 的加密 plaintext 真正的承载层；sealed 通过 `0g-storage-client` CLI 上传下载 |
| openclaw | 唯一打包的 agent framework（链上 binding 点名时选中,或作为无 binding 的 fallback）；npm 包，由 sealed 安装并 spawn 成子进程，监听 127.0.0.1:3284。adapter 接口本身框架无关（见 `FRAMEWORK_ADAPTER.zh.md`）；第二个框架 claude-code 曾作为接缝探针接入、验证完成后下线，移植实录保留在该文档 §12 |

本文档讲**当前代码里实际跑的形态**和**为什么这么分**。

## 1. 启动流程

`main.go` 的 5 个 phase 严格按顺序走，前一步失败整个容器退出，让
sandbox supervisor 重新起：

```
Phase 0  attest           解析环境、校验 SANDBOX_SEAL_KEY ↔ attestation.pubkey、
                          恢复 TEE signer (TEE_SIGNER_ADDRESS 校验若设了的话)
                          ↓
Phase 1  provision        POST /provision → ECIES 解出 agent_seal_priv，
                          listen sign socket (/run/seal-sign.sock)
                          ↓
Phase 2  chain bootstrap  WaitForMint(sealId) → agentId
                          IntelligentDatasOf(agentId) → []IntelligentData
                          SealedKeysOf(agentId) → map[dataHash][]sealedKey
                          逐条 download (0g-storage) + AES-GCM decrypt
                          按 binding 的 name 解析 framework adapter
                          ↓
Phase 3  framework        Restore (A→B→C 三轮) → seedCurrentSnapshots (phase 1) →
                          mgr.Start (spawn openclaw + writeRuntimeSections +
                          upsert IDENTITY/SOUL/TOOLS sealed sections) →
                          sleep 5s → seedCurrentSnapshots (phase 2 baseline) →
                          watcher.New + Start
                          ↓
Phase 4  status report    通知 attestor /status 整条流水线成功（level="running"）
                          ↓
长跑期                     proxy on :8080 + sign socket + watcher 30s tick +
                          manager 监工 agent 进程 + 5min heartbeat 把
                          currentStatus（severity 单点真源）回报给 attestor
```

只在 Phase 4 之后才有"agent 在线"。Phase 3 的 phase 1 seed 是
pre-Start 快照、phase 2 seed 是 openclaw 启动稳定后的 baseline ——
这是 watcher 比对的真起点（详见 §4）。

## 2. 包结构

```
sealed/
├── main.go                       入口；编排上面 5 个 phase + heartbeat + handleDrift
├── status.go                     runtimeStatus 单点真源（running/warning/error）+
│                                 severityOf 错误分类器；handleDrift + heartbeat 都读它
├── internal/
│   ├── config/                   env 解析、运行参数
│   ├── chain/                    AgenticID 合约 view + tx 包装
│   ├── dataplane/                ECIES 解 sealedKey + AES-GCM 解/加密 iData
│   ├── provision/                /provision RA 请求 + 响应解封装
│   ├── report/                   /status 上报到 attestor
│   ├── logger/                   结构化日志（公共写入 logger.Logf，被 proxy 暴露成 /log.html）
│   ├── framework/                framework 适配器抽象 + 可选能力接口
│   │   ├── openclaw/             openclaw 适配器实现
│   │   └── conformance/          可执行不变量套件,每个 adapter 在测试里跑
│   ├── inference/                框架无关的 provider 知识(0g router 端点、按模型的线格式,
│   │                             读 router 实时目录);adapter 只做 Route → 自家配置方言的翻译
│   ├── manifest/                 directory-manifest 格式 + 确定性 tar.gz
│   ├── state/                    Agent 共享状态（chainSnapshot + currentSnapshot + phase）
│   ├── manager/                  agent 进程生命周期 + 监工
│   ├── uploader/                 drift → 0g-storage upload + 签名 chain.Update
│   ├── watcher/                  30s tick 跑 EvolutionFor、触发 uploader.Apply
│   └── proxy/                    :8080 反向代理 + 签名 + 日志页
└── images/openclaw/              openclaw base 镜像构建脚本（独立产物，跟 sealed bootstrap 镜像分层）
```

### 各包职责一句话

- **chain**：所有链 view / tx 在这里收口，外面拿不到 `*ethclient.Client`，只能拿语义 API（`WaitForMint` / `IntelligentDatasOf` / `Update` 等）
- **dataplane**：crypto-only，不碰链、不碰文件。`UnsealDataKey(sealed, priv) → dataKey`、`Decrypt(ct, key)`、`Encrypt(pt, key)`
- **framework**：定义 `Framework` 接口（adapter 协议）+ `RuntimeContext` + `RoleSpec{Name, Shape}` + 共享类型如 `StartParams`、`StartResult`。**不依赖具体框架**
- **framework/openclaw**：唯一的 adapter 实现。又内部拆成 `restore.go`/`restore_paths.go`、`evolution.go`/`evolution_paths.go`、`spawn.go`、`ingest.go`（persona legacy）、`inference.go`（model 路由）、`disk.go`（openclaw.json read/write）、`whitelist.go`（npm 版本白名单）、`identitymd.go`/`soulmd.go`/`toolsmd.go`（IDENTITY/SOUL/TOOLS 三份 sealed-managed 平台段 + 共享 marker 工具）
- **manifest**：directory-manifest 的 `Manifest{SchemaVersion, Kind, Entries []Entry{Path, Kind, ContentHash, Size, StoragePtr}}` + 确定性序列化（按 Path 排序）+ `StripStoragePtrs` 把 entries 的 StoragePtr 置零以便算 watcher-facing hash + 确定性 tar.gz（用于 skill/canvas 子树）
- **state**：`Agent` 持有 `chainSnapshot` + `currentSnapshot` 两个 `Snapshot{PerDim: map[string]DimEntry{ContentHash, DataHash}}`，所有 drift 比对都走这里
- **manager**：`Start(ctx, params)` 调 adapter.Start spawn agent + 起 supervisor goroutine，agent 死了清状态 + 触发 onFailed
- **uploader**：`Apply(plaintexts)` 拿 watcher 收集的"每个 role 当前 plaintext"，跟 chainSnapshot 比对，调 `pushLeaf` 或 `pushManifest` 上传 0g-storage，再签 `chain.Update`
- **watcher**：30s ticker，跑 `EvolutionFor` 收每个 role 的现在 plaintext，调 `UpdateCurrentSnapshot` 算 drift，有 drift 就触发 OnDrift（接到 uploader.Apply）
- **proxy**：:8080 上的 fasthttp，承担三个职责：(1) `/hello` 返回 agent 身份信息 + serve-proof，(2) 把对外请求转给 framework upstream（openclaw :3284），(3) `/log.html` / `/log/agent.html` 实时日志页

## 3. 核心抽象：Framework adapter

外面（main / watcher / uploader / proxy）只认 `framework.Framework`
接口，不知道 openclaw 长什么样。这就是接其他 framework 的口子。

> **想接入别的 agent 框架？** 完整的 adapter 契约——逐方法语义、
> 不变量、调用点地图、manifest 格式、以及"哪些还接死在 openclaw 上"
> 的如实清单——在 [FRAMEWORK_ADAPTER.zh.md](FRAMEWORK_ADAPTER.zh.md)。
> 本节只是架构概览。

```go
type Framework interface {
    Name() string
    Version(ctx) (string, error)                     // best-effort 探测（core 暂未消费）
    Roles() []RoleSpec                               // 声明本 adapter 拥有的所有 dim
    Defaults(role string) []byte                     // 返回该 role 的 canonical 空状态
    Restore(ctx, role, plaintext []byte) error       // 把 plaintext 落到内存/磁盘
    LoadEntry(ctx, role, path) ([]byte, error)       // 读一个 manifest 子条目的 canonical plaintext
    RestoreEntry(ctx, role, path, plaintext) error   // 反向：写一个 manifest 子条目
    EvolutionFor(ctx, role) ([]byte, error)          // 读现在磁盘/内存 → canonical plaintext
    HandleLegacy(ctx, role, plaintext) error         // 不在 Roles() 里的链上 role（如 persona）
    Start(ctx, RuntimeContext) (StartResult, error)  // spawn agent 子进程
    AuthResponse(ctx) (any, error)                   // /_seal/auth 的 owner 专属载荷
    Stop(ctx, gracefulTimeout) error                 // SIGTERM → SIGKILL
    Liveness(ctx) error                              // 监工探针
    Readiness(ctx) error
}
```

必选接口之外：

- **`MonitorExit(onExit func(err error))`** ——`manager.Adapter` 额外
  要求的（进程死亡 callback，让监工不用轮询）。`main.go` 启动时
  assert；真实 adapter 都实现它。
- **可选能力接口**（`VersionReconciler`、`SubprocessLogProvider`、
  `SettleDelayer`）——core type-assert,
  adapter 缺哪个就优雅降级哪个。表格见 FRAMEWORK_ADAPTER.zh.md §2.2。

激活的 adapter 由**链上 framework binding 的 `name`** 决定——Phase 2
解密完 iData 后,`main.resolveAdapter` 经 `framework.Get` 查注册表选出
(每个打包进二进制的 adapter 在自己的 `New()` 里自注册)。
`AGENT_FRAMEWORK` env 只是链上无 binding 时的 fallback(本地 dev);
两者不一致时 binding 赢。

（`framework.Reloadable` 声明了可选热重载钩子，但目前没有消费方；
`manager.Reload` 永远走 Stop + Start。）

**两个 Shape**（见 `framework.go:21-32`）：

- **Leaf**：iData 加密 plaintext = role 的 canonical 字节本身。`framework`（3 字段 binding JSON）、`openclaw.json`（openclaw 主配置）走这条。
- **DirectoryManifest**：iData 加密 plaintext 是一个 manifest，列出子条目；每个子条目自己是一份独立的加密 blob，按 manifest entry 的 `StoragePtr` 找。`workspace/`、`workspace/skills/`、`workspace/canvas/` 走这条。

**两态 plaintext**（DirectoryManifest 专属，§7 详细讲）：

- **empty-ptr 形态**：`EvolutionFor` 输出，每个 entry 的 StoragePtr 字段是 zero。这份 plaintext 的 sha256 = "watcher-facing contentHash"，是 `chainSnapshot[dim].ContentHash` 应该存的值。
- **filled-ptr 形态**：`pushManifest` 上传前把每个 entry 的 StoragePtr 填上对应 0g-storage root + size，再 marshal，加密上传。链上 `dataDescription.storage_ptr.root_hash` 指向 filled-ptr 那个 blob。

下次 bootstrap 从链拿到的是 filled-ptr 形态，**必须**先 `manifest.StripStoragePtrs` 转成 empty-ptr 再 sha256 才能跟 watcher 算的对得上，否则每次重启都 phantom drift（这是 §7 的一个修复点）。

**`Restore` 必须满足交换律 + 幂等性**：每个 role 只拥有磁盘 / 内存中自己那一片切片，所以 adapter 的 `Restore(role, plaintext)` 在多次调用之间顺序无关——任意排列同一组输入产出同样的最终 composed 状态；同一 role 连续 Restore 不同输入只有最后一次生效。bootstrap 的 A→B→C 三轮 Restore（先 leaf、再 manifest 父、再 manifest 子条目）依赖这条性质：每轮独立处理一类 role，相互不破坏。`Start` 是唯一的"落盘 + spawn 子进程"入口，把 adapter 内部累积的 composed 状态一次性交给子进程。

## 4. 核心状态：两个 snapshot

`internal/state/state.go` 的 `Agent` 持有两个独立 `Snapshot{PerDim: map[string]DimEntry}`：

| 字段 | 谁写 | 含义 |
|---|---|---|
| `chainSnapshot[dim]` | bootstrap `SeedChainSnapshot` 初始化一次；之后只有 `RecordChainUpload` 在 chain.Update tx 确认后再更新 | 链上**当前**这条 iData 的 ContentHash + DataHash；placeholder（链上没条目）时 ContentHash 取 `sha256(adapter.Defaults(dim))`、DataHash 为空 |
| `currentSnapshot[dim]` | phase 1 seed、phase 2 seed、watcher tick 都会调 `UpdateCurrentSnapshot` | **采样簿** —— 上一次跑 `EvolutionFor(dim)` 算出来的 ContentHash 落账 |

drift 公式：

```
drifted = (chainSnapshot[dim].ContentHash != currentSnapshot[dim].ContentHash)
```

`UpdateCurrentSnapshot` 同时打日志：

```
iData local[init]:   dim=X hash=A chain=B (pinned|placeholder) -> DRIFT|MATCH   ← prev 为空（首次采样）
iData local[change]: dim=X hash=A (prev=P) chain=B (pinned|placeholder) -> DRIFT|MATCH   ← 真发生变化
```

`SeedChainSnapshot` 打：

```
iData chain: dim=X hash=H pinned (data=0x..)              ← 链上真有
iData chain: dim=X hash=H placeholder (no on-chain entry) ← 链上没有，H 是 defaults 占位
```

**为什么是采样而非 live**：watcher 比对的是「上次跑 EvolutionFor 出
来的 hash」vs「链上 hash」。如果 currentSnapshot 是 live（每次访
问都重新跑），它跟自身永远相等，drift 检测就空转了。

## 5. iData 演化机制

```
              ┌─ watcher tick (30s) ───────────────────────────────────┐
              │  for each role:                                        │
              │    pt := adapter.EvolutionFor(role)                    │
              │    h := sha256(pt)                                     │
              │    drifted := agent.UpdateCurrentSnapshot(role, h)     │
              │  if any drifted: OnDrift(plaintexts, drifted)          │
              └───────────────────────────┬────────────────────────────┘
                                          │
                                          ▼
                                   uploader.Apply(plaintexts)
                                          │
       chainEntries := chain.IntelligentDatasOf(agentID)               ← 拉链上当前快照
       chainSealedKeys := chain.SealedKeysOf(agentID)                  ← 同步拿 sealedKeys
                                          │
       ┌─ 对每个 role 决定 outcome ───────────────────────────────────┐
       │  isDefault → 略掉（§16.10：plaintext = defaults ↔ 无链条目） │
       │  cachedChainHash == contentHash → 复用链上 entry 原样塞回    │
       │  diverged → resolveKey → pushLeaf 或 pushManifest             │
       └───────────────────────────────────────────────────────────────┘
                                          │
       newEntries + newSealedKeys 准备好后                              ← wholesale 替换语义
       chain.Update(agentID, newEntries, newSealedKeys, signerPriv)    ← 一笔 tx 替换整个 iData[]
                                          │
                                          ▼
       per role 调 agent.RecordChainUpload(role, contentHash, dataHash)
       同步 chainSnapshot 到刚上链的值
```

几个值得注意的语义点：

- **wholesale replace**：合约的 `update(tokenID, newDatas, sealedKeys)` 替换整个 iData 数组，不是 patch。要"删"一条 role 就让 newDatas 里不包含它（uploader.Apply 把 isDefault 的 role 自然剔除，所以"恢复默认 → 链上消失"）。
- **三种 outcome**：unchanged 复用、isDefault 不带、diverged 真的上传。
- **single tx coalescing**：30s 内连续 N 个 drift 在同一 tick 里被打包成一笔 tx，gas 只花一次。
- **stale-chain-row 处理**：`apply.go` 在 tx 之前重新从链上拉 `chainEntries`，不依赖 chainSnapshot 缓存。
- **duplicate-role hard-fail**：链上若出现两条相同 `dataDescription` 的 iData，bootstrap 立刻拒绝启动并上报 error。同一 role 配两个不同 `storage_root` 时 agent 身份不确定，fail loud 比静默挑一条更安全。

### push_leaf vs push_manifest

```
pushLeaf(role, plaintext, dataKey):
    ct := Encrypt(plaintext, dataKey)
    root := 0g-storage.Upload(ct)
    return IntelligentData{DataDescription: desc(role, root, indexer), DataHash: root}

pushManifest(role, plaintext, dataKey, oldChainEntry):
    newM := manifest.Unmarshal(plaintext)            ← empty-ptr 形态
    oldM := fetch + decrypt + Unmarshal(oldChainEntry)  ← 可选，仅复用 StoragePtr
    for each entry e in newM.Entries:
        if oldM.EntryByPath(e.Path).ContentHash == e.ContentHash:
            e.StoragePtr = oldM.EntryByPath(e.Path).StoragePtr   ← 复用，不重新上传
        else:
            content := adapter.LoadEntry(role, e.Path)
            ct := Encrypt(content, dataKey)
            root := 0g-storage.Upload(ct)
            e.StoragePtr = {root, len(ct)}                        ← 全新
    filled := newM.Marshal()                          ← filled-ptr 形态
    mCT := Encrypt(filled, dataKey)
    mRoot := 0g-storage.Upload(mCT)
    return IntelligentData{DataDescription: desc(role, mRoot, indexer), DataHash: mRoot}
```

复用 StoragePtr 是性能关键：一个 5MB 的 skill 没变就别再上传 5MB 进 0g-storage。

## 6. openclaw 适配器现状

```
internal/framework/openclaw/
├── openclaw.go          Adapter 类型 + Roles() 声明 + Defaults()
├── config.go            in-memory state（只保留 framework binding 3 字段，其余走盘）
├── restore.go           dispatch；framework leaf 的 Restore
├── restore_paths.go     openclaw.json / workspace/* 的 Restore 实现 + LoadEntry/RestoreEntry
├── evolution.go         dispatch；framework leaf 的 EvolutionFor（probe `openclaw --version`）
├── evolution_paths.go   openclaw.json / workspace/* 的 EvolutionFor 实现 + 平台注入 strip
├── ingest.go            HandleLegacy[persona]：把老 mint-only persona 翻成新 auth/agents 字段
├── inference.go         model provider 注入（0g-compute / openai / anthropic 路由）
├── spawn.go             writeRuntimeSections + upsert IDENTITY/SOUL/TOOLS sealed 段 +
│                        spawn `openclaw gateway run` + version probe
├── disk.go              ~/.openclaw/openclaw.json 读写
├── identitymd.go        IDENTITY.md 的 sealed 段：agentSeal 身份事实 + 信任链
├── soulmd.go            SOUL.md 的 sealed 段：主权宣言 + sign 拒绝规则 + 伪造识别
├── toolsmd.go           TOOLS.md 的 sealed 段：sign 端点 + public URL + serve-proof；
│                        共享 marker 工具（upsertMarkedSection / stripPlatformInjection）
├── whitelist.go         supportedOpenclawVersions[] + whitelistMax()
└── paths.go             $HOME/.openclaw/* 路径常量
```

**5 个 declared role**（见 `openclaw.go:Roles()`）：

| Name | Shape | EvolutionFor 内容 |
|---|---|---|
| `framework` | Leaf | 3 字段 binding：`{name, package_version, schema_version}` |
| `openclaw.json` | Leaf | 白名单过滤后的主配置：只保留 `agents` / `auth` / `models` 三个顶层键 |
| `workspace/` | DirectoryManifest | `~/.openclaw/workspace/*.md`（每个 .md 都走 `stripPlatformInjection` 把 marker 包裹的 sealed 注入段砍掉，所以 IDENTITY/SOUL/TOOLS 都是 round-trip 干净的） |
| `workspace/skills/` | DirectoryManifest | `~/.openclaw/workspace/skills/<slug>/`（每个 slug 是 entry，content 走确定性 tar.gz） |
| `workspace/canvas/` | DirectoryManifest | `~/.openclaw/workspace/canvas/`（混合：file entry + dir entry） |

设计取舍：

- **openclaw.json 用白名单而非黑名单**：openclaw 进程自己会写 `logging`/`wizard`/`discovery`/`push`/`cli` 等键，这些不属于 iData。白名单确保未来 openclaw 加任何新键都不会触发 phantom drift。
- **三文件平台注入 + 通用 strip**：spawn 时往 `IDENTITY.md`（身份事实）/`SOUL.md`（拒绝规则）/`TOOLS.md`（sign 端点 + public URL）各注入一段被 `<!-- 0g-platform-injected:start/end -->` marker 包裹的平台段，分摊三种关切。文件分布对齐 openclaw 的 `CODEX_BOOTSTRAP_CONTEXT_ORDER`（SOUL=10 > IDENTITY=20 > TOOLS=40，数字越小越优先）。算 hash 和 LoadEntry 时 `stripPlatformInjection` 会从 **任何** workspace 根级 .md 里砍掉 marker 段，让 ContentHash 跟具体 sandbox 实例无关、未来加新平台文件不用动 evolution 代码。
- **framework binding 实时 probe**：`evoFramework` 跑 `openclaw --version` 拿真实版本号覆盖到 `cfg.framework.PackageVersion` 上 —— Reconcile 触发 npm 升级后，下个 watcher tick 自然会把新版本号写上链。
- **空 md defense**：`workspaceRequiredMDs` 列了 7 个根级必备 md（SOUL/IDENTITY/USER/AGENTS/TOOLS/MEMORY/DREAMS），manifest 没列就 touch 一个空文件，避免 openclaw 自动生成几 KB 的 template；空文件不进 manifest，所以 round-trip 稳定。

## 7. 运行时入口

容器外部能访问的接口只有 :8080（由 `internal/proxy`），sandbox proxy 把 `<port>-<sandboxId>.<host>` 这种 nip.io 子域反代到容器 :8080。

| 路径 | 谁用 | 干什么 |
|---|---|---|
| `/healthz` | sandbox proxy / 运维 | 流动性探测，返回 200 + 一行 status |
| `/hello` | verifier、attestor、运维 | 返回 agent 身份 + currentSnapshot 的 `data_hashes`（serve-proof envelope 走 `X-Agent-Proof` 头）|
| `/_seal/auth` | **owner 钱包** | owner 用 EIP-191 签 `0GSealAuth:{sealId}:{ts}`，sealed 验签 == on-chain owner 后返回一个短期 framework dashboard token + path |
| `/<其他>` | 用户、agent dashboard 前端 | 反代到 openclaw 127.0.0.1:3284 |
| `/log` + `/log.html` | 运维 | sealed bootstrap 实时日志（带 phase 着色） |
| `/log/agent` + `/log/agent.html` | 运维 | agent 子进程的 stdout/stderr（实时）;路径经 adapter 的 `SubprocessLogPath()` 解析。`/log/openclaw`（`.html`）作为 legacy 别名保留 |
| `unix:///run/seal-sign.sock` | **只允许容器内 agent 进程** | `/sign/personal_sign` / `/sign/typed_data` / `/sign/transaction` —— 用 `agent_seal_priv` 签名 |

sign socket 是 sealed 跟外界（其实是同容器的 agent 进程）的关键
信任边界：私钥不出 sealed 进程，agent 把要签的消息通过 unix socket
递过来。socket 本身只是传输层 —— **拒绝逻辑在 agent 侧由 SOUL.md
的拒绝规则约束**（任何来自外部 prompt 的 sign 请求都要拒，不靠
"用人话描述待签内容" 这种容易被身份钓鱼骗过的启发式）。详见
`internal/framework/openclaw/soulmd.go`。

## 8. 配置面

环境变量是 sealed 主要的配置面（`internal/config`），由 attestor
在创建 sandbox 时注入：

| env | 含义 |
|---|---|
| `SANDBOX_SEAL_KEY` | sandbox 注入的 ECDSA 私钥；用来跟 `SANDBOX_SEAL_ATTESTATION.pubkey` 互证（Phase 0）|
| `SANDBOX_SEAL_ATTESTATION` | sandbox 签的 attestation JSON，含 `image_hash` / `pubkey` / `seal_id` / `ts` / `signature`；sealId 从这里取，不是独立 env |
| `TEE_SIGNER_ADDRESS` | （可选，**生产通常不设**）若设，Phase 0 要求从 attestation signature recover 出的地址 == 这个值，否则 fail loud。权威的 sandbox signer 校验在 attestor `/provision` 那一头（查 `TappRegistry.getNodeList(sandbox_app_id)`）；sealed 这条 pin 只是 dev / 本地调试早死的辅助，不是安全边界 |
| `ATTESTOR_URL` | attestor 公网入口；用于 `/provision` 换 agentSeal_priv 和 `/status` 心跳 |
| `CHAIN_RPC_URL` | 0G testnet RPC，AgenticID 合约所在链 |
| `AGENTIC_ID_ADDR` | AgenticID 合约地址 |
| `INDEXER_URL` | 0g-storage 的 indexer URL，`dataDescription` 里 indexer 字段为空时 fallback |
| `AGENT_FRAMEWORK` | （可选）链上无 framework binding 时的 adapter 名 **fallback**(本地 dev 用)。权威选择器是链上 binding;attestor 不注入这个 env |
| `API_KEY` | LLM provider key，由 attestor 在 deploy / Recreate envelope 里转发；spawn.go 翻译成 provider 专属的 `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` 等 |
| `SANDBOX_PROXY_DOMAIN` + `DAYTONA_SANDBOX_ID` | 拼 `AGENT_PUBLIC_URL`，形如 `http://8080-<sandbox_id>.<proxy_domain>`；agent 自己暴露端口固定 `:8080`，由 sealed proxy 写死 |

### `AGENT_PUBLIC_URL` 怎么暴露给 agent

bootstrap 拼装好 `AGENT_PUBLIC_URL = http://8080-${DAYTONA_SANDBOX_ID}.${SANDBOX_PROXY_DOMAIN}` 后在**三个表面**暴露给 agent，agent 怎么用看 framework 习惯：

1. **`/hello` 响应 JSON 的 `public_url` 字段** —— verifier 拿到响应后可以交叉校验跟它请求的 URL 是否一致
2. **`~/.openclaw/0g-public-url.txt`** —— plugin 能从已知文件路径读
3. **`AGENT_PUBLIC_URL` 子进程 env** —— spawn.go 的 env 白名单允许它穿到 openclaw 子进程

本地 dev `SANDBOX_PROXY_DOMAIN` 未设时，上述三处全部留空，系统仍可运行（agent 只是不知道自己对外是哪个 URL，签名响应不带 `public_url` 字段）。

## 9. 状态汇报与心跳

sealed 在 Phase 4 起就持续向 attestor 上报 `/status`，attestor 那侧负责
落库 `last_heartbeat` 列 + 用心跳缺失检测做被动兜底（见 attestor
README 的 sweep 部分）。

### 三件东西一张图

| 角色 | 写还是读 `currentStatus` | 什么时候动 |
|---|---|---|
| **`currentStatus`**（`status.go`）| —— 共享状态本身 | 是 `runHeartbeat` + `handleDrift` 共享的**单点真源**：当前 severity（`running` / `warning` / `error`）+ message |
| **`handleDrift`**（`main.go`）| **写** | watcher 每 30s 一次 tick 跑 drift + uploader.Apply，按结果分类后写进 currentStatus；warning / error 状态转换时**还会立刻**自己 POST 一次 `/status`，不等心跳 |
| **`runHeartbeat`**（`main.go`）| **读** | 每 5 分钟一次 ticker，把当下的 currentStatus 复读一遍 POST 给 attestor —— 像心跳一样让 attestor 持续看到这条 deployment 是活的 + 当前在哪个 severity |

—— 一句话：**handleDrift 决定 "现在是什么状态"，runHeartbeat 负责 "定期告诉别人"**。两个不互相覆盖，因为它们读写的是同一个 `currentStatus`，谁动了对方下次也能看到。

attestor 那侧 15min 没收到任何 `/status` 就把 deployment flip 成
`Failed { reason: "heartbeat timeout (15min)" }` 并广播 `ContainerFailed`
事件 —— 这是 sealed 真挂了（进程死、网络全断）才会发生。

### `handleDrift` 的三态 severity

`handleDrift` 是 watcher 每次 tick 检测到 drift 后的回调：调
`uploader.Apply` 把 drift 推上链，然后按 Apply 的返回结果写
`currentStatus`。它分类的是 **"提交 drift 上链这一步发生了什么"** ——
包括 agentSeal 钱包没 gas（gas 不足 → `chain.Update` tx 进不去 → Apply
失败），所以钱包余额这种事也归它管。

Apply 的三种结果对应三种 severity：

| Apply 结果 | severity | 上报时机 | 失败计数 |
|---|---|---|---|
| **成功**（drift 上链了，或无 drift）| `running` | 不立刻上报，等 runHeartbeat 复读 | 累计错误清零 |
| **失败，owner-recoverable** —— 典型：agentSeal 钱包没 gas、API key 配错、provider rate limit | `warning` | 第一次出现**立刻**上报，不等心跳 | **不**累加（这不是系统故障，是 owner 自己得处理的事）|
| **失败，系统级** —— 典型：0g-storage 上传超时、RPC 异常、indexer 不可达 | `error` | 累计 **5 次连续** Apply 失败才升级到 error 上报，避免单次网络抖动误判 | 累加，恢复后清零 |

`status.go::severityOf` 是把具体 error 字符串翻译到这三种 severity 的分类器
（认 "insufficient funds" → `warning`、"connection refused" → `error`、etc.）。
分类失败兜底 `error`。

### `runHeartbeat` 的 5min ticker

`main.go` 在 Phase 4 之后起一个 goroutine：每 5 分钟一次
`currentStatus.Get()`，POST `/status`。上报失败只打日志，不影响进程 ——
attestor 那侧靠 15min 阈值兜底。

### serve-proof 的 `data_hash` 来源

每条 serve-proof envelope 里 `data_hashes[role]` 带两字段：
- `content_hash` = sha256(本地 plaintext)
- `data_hash` = 该加密包在 0g-storage 的 root hash（链上引用的那个）

drift 检测只用 `content_hash`，但 serve-proof 要带 `data_hash` 给 verifier
做"链上引用 == 我现在跑的"的交叉校验。`data_hash` 的来源有两条路：

1. **本 sealed 实例自己上传过该 role 的加密包** —— `RecordChainUpload` 落
   `currentSnapshot[role].DataHash = 新上传的 root`
2. **本实例从没上传过、但本地 plaintext 跟链上一致** —— `state.go::UpdateCurrentSnapshot`
   兜底：若 `prev.DataHash == ""` 且 `contentHash == chainSnapshot.ContentHash`
   且 `chainSnapshot.DataHash != ""`，把 `chainSnapshot[role].DataHash` 抄进
   currentSnapshot。语义：本地 plaintext 跟链上一致 → 链上那个 storage root
   就是现在能背书的 data_hash

路径 2 覆盖的典型场景：`framework` role —— attestor 默认值跟实际安装的
openclaw 版本对得上时永远不会 drift，本实例自然没有自上传过，但链上有
attestor mint 时上传的版本。没有路径 2 的话 envelope 里那条 role 报不出
data_hash，verifier 会判 ✗。
