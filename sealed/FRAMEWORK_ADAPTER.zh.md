# sealed Framework Adapter 接入契约

> English version: [FRAMEWORK_ADAPTER.md](FRAMEWORK_ADAPTER.md)。

这份文档是给 **agent 框架作者** 的接入契约:要把你的框架(eliza、
autogen、自研编排器……)跑进 Sealed Sandbox,需要实现什么、sealed 会
在你的进程周围提供什么,以及哪些工作仍在仓库之外。树内有一个 adapter
作参照实现:`openclaw`(服务型框架)。第二个 `claudecode`(CLI 型框架,
经 HTTP bridge 托管)是当初用来验证 seam 的探针,**已下线**——每次请求
现拉起的 CLI 托不住这个平台真正要的"owner 委托、可对外调用的服务"
(openclaw 的常驻 server 才行)。适配器代码已移除,但移植过程的经验正是
这份契约里很多条款的由来,见 §12 实录。

权威来源是代码:接口定义在
[`internal/framework/framework.go`](internal/framework/framework.go);
本文补充 Go doc 注释讲不透的语义、不变量和调用点。文档与代码冲突时以
代码为准——同时请提 issue。

前置阅读:[ARCHITECTURE.zh.md](ARCHITECTURE.zh.md) §1(启动序列)、
§4–5(双 snapshot + 进化管线)。本文假设你已经知道 iData、role、
watcher/uploader 循环是什么。

---

## 1. 分工

实现一个 adapter,你的框架就获得完整的 AgenticID 生命周期,而不用碰
任何加密或链上代码:

| sealed core 负责 | 你的 adapter 负责 |
|---|---|
| RA provisioning、保管 `agent_seal_priv` | iData role ↔ 你的磁盘布局之间的映射 |
| 链上读写(`intelligentDatasOf`、`update` 交易) | 拉起 / 停止你的框架进程 |
| 0g-storage 上传下载、AES-GCM + ECIES | 产出每个 role 的 canonical plaintext 字节 |
| `:8080` 反向代理 + `X-Agent-Proof` 签名 | 你的进程的健康探针 |
| agent 专用签名 socket(`/run/seal-sign.sock`) | 把运行时事实(sign socket 路径、public URL、链上身份)以你的框架消费 context 的方式交给 agent |
| 漂移检测(30s watcher)+ 整体替换式 `chain.Update` | 决定什么算 agent 状态(什么算运行时噪音) |
| 进程监工、重启退避、attestor 心跳 | owner 鉴权载荷(`AuthResponse`) |

adapter 永远看不到 `agent_seal_priv`,永远不直接上链,也不做任何加密。
它做的是在 **canonical plaintext 字节**(sealed 拿去 hash、加密、锚定
上链的东西)和 **你的框架自己的磁盘/内存状态** 之间的双向转换。

## 2. 接缝到底在哪

契约就是 `framework.Framework`(`internal/framework/framework.go`)。
sealed 的四个组件各自通过一个窄切面消费它:

| 消费方 | 调用的方法 | 时机 |
|---|---|---|
| bootstrap(`main.go`) | `Roles`、`Defaults`、`Restore`、`RestoreEntry`、`HandleLegacy`、`EvolutionFor`(snapshot 播种) | Phase 3,一次性 |
| manager(`internal/manager`) | `Start`、`Stop`、`Liveness`、`Readiness`、`MonitorExit` | Start 一次;探针每 5s;重启和 reload 时 Stop/Start |
| watcher(`internal/watcher`) | `Roles`、`EvolutionFor` | 每 30s tick |
| uploader(`internal/uploader`) | `Roles`、`Defaults`、`EvolutionFor`、`LoadEntry` | 有漂移时,在 `Apply` 内 |
| proxy(`internal/proxy`) | `AuthResponse` | 每次验证通过的 `POST /_seal/auth` |

### 2.1 哪些已经抽象,哪些仍在仓库之外

自 claudecode 移植(见 §12)之后,core 已经是注册表驱动:以下组件只
持有接口(或其窄子集),换框架**零改动**——`main.go`、`manager`、
`watcher`、`uploader`、`proxy`、`state`、`manifest`、`dataplane`、
`chain`、`platform`。

- **adapter 选择由 binding 驱动**:adapter 在自己的 `New()` 里
  `framework.Register` 自注册;`main.go` 注册所有随二进制打包的
  adapter,Phase 2 解密完 iData 后按**链上 framework binding 的
  `name`** 选出激活的那个——决定"哪个框架解释这份 iData"的是 agent
  被 mint 的身份,不是部署配置。`AGENT_FRAMEWORK` env 只是链上无
  binding 时的 fallback(本地 dev);两者都在且不一致时 binding 赢,
  记一条 warning。把你的 adapter 加进二进制只需在 `main.go` 加一行
  注册。
- **框架相关行为** 走可选能力接口(§2.2),core type-assert 后优雅
  降级:版本回正、子进程日志页、settle 延迟。
- **一个通用镜像**:`images/sealed/` 只烧 node + sealed 二进制,打包
  的框架以 npm 预装作为**热缓存**——每个 adapter 在首次 Start 时按
  binding 重新钉版本;CLI 框架如带 shim,`go:embed` 在二进制里、
  Start 时落盘(已下线的 claudecode bridge 就是这个模式)。接入新的
  node 系框架不需要新镜像,顶多加一行热缓存。

仍然真正在仓库之外的:

1. **镜像 allowlist 治理**:通用镜像的 hash 要进 attestor 的
   allowlist;重新构建(新 sealed 二进制、新热缓存条目、版本
   allowlist 提升)= 新 allowlist 条目。
2. **attestor 的 mint 支持**:部署 API 是 WYSIWYS 的——客户端交付
   agent 的**完整 iData**(owner 签的就是上链的字节,attestor 不做
   任何合成),`role="framework"` binding 条目为必填,其 `name` 在
   不可逆的 mint **之前**对支持名单校验。attestor 保持框架无关:
   名字是不透明字符串,binding 无版本(`{"name","schema_version"}`
   ——adapter 把空版本解析为自己的 whitelistMax),默认内容的便利性
   归客户端(SDK 的 `defaultIData()`、控制台的部署表单),它们负责
   构造 binding + `persona` 种子(§5.4)这一对。

### 2.2 配套接口与可选能力接口

- **`manager.Adapter`** = `framework.Framework` + `MonitorExit(onExit
  func(err error))`。MonitorExit 必须在你 spawn 的进程退出时(从
  goroutine 里)恰好调用一次 `onExit`,参数是 `cmd.Wait` 的错误。
  manager 把 **非 nil 错误当 crash**(立即重启),把 **nil 只当提示**
  (交给 liveness 探针裁决——有些框架自重启时 fork-exec 出替身子进程
  后主进程以 0 退出,子进程继续持有端口;跟它抢会造成 crashloop)。
  `main.go` 启动时就 assert 并 fail loud,所以实践中 MonitorExit 是
  必选项。

可选能力接口(定义在 `framework.go`;core type-assert,缺失时优雅
降级):

| 接口 | 方法 | 消费方 | 缺失时 |
|---|---|---|---|
| `VersionReconciler` | `ReconcileFramework(ctx)` | drift handler,`framework` role 漂移时 | 漂移原样上链(审计诚实,强制关闭) |
| `SubprocessLogProvider` | `SubprocessLogPath()` | proxy `/log/agent` | 日志页报不可用 |
| `SettleDelayer` | `SettleDelay()` | bootstrap 基线采集 | 保守的 5s 默认值 |

实现了哪个就写哪个的编译期断言(`var _ framework.VersionReconciler = (*Adapter)(nil)`)——可选接口
悄悄没实现 = 功能悄悄关闭。

移植后仍然是死表面的部分:

- **`framework.Reloadable`**(`Reload(ctx, changedDim)`)声明为可选的
  热重载钩子,但 **目前没有任何消费方**;`manager.Reload` 现在永远走
  Stop + Start。不要依赖它。
- **`Version(ctx)`** 在接口里,但生产代码中 **目前没有调用方**
  (adapter 都是在 `EvolutionFor("framework")` 内部自己探测版本的)。
  按 best-effort 探测实现即可;预期以后会接进 serve-proof 元数据。

## 3. Role 与 Shape

一个 **role** 就是链上的一条 iData:agent 持久状态中由你端到端负责的
一个命名切片。`Roles()` 用 `RoleSpec{Name, Shape}` 声明你的 role 集。

两种 Shape(`framework.Shape`):

- **`Leaf`** ——该 role 链上 iData 指向一个加密 blob,其 plaintext
  就是 role 的 canonical 字节本身(比如一份配置 JSON)。
- **`DirectoryManifest`** ——iData 指向一份加密的 *manifest*(见
  §4),manifest 的每个条目各自指向独立的加密内容 blob。目录形态或
  体积大的东西走这条:换来按条目增量上传(没变的 5MB skill 永远不会
  重传)。

约定与规则:

- **命名**:manifest role 以 `/` 结尾,leaf 不带斜杠
  (`workspace/skills/` vs `openclaw.json`)。只是信息性约定——
  `Shape` 才是权威——但请遵守;工具链会读 role 名。
- **`framework` role 是协议保留的。** 每个 adapter 必须把它声明为
  `Leaf`,plaintext 是 binding JSON:

  ```json
  {"name": "openclaw", "package_version": "2026.6.2", "schema_version": 1}
  ```

  binding 的 `name` 就是启动时选 adapter 的依据(§2.1)——它是 agent
  的框架身份,由 attestor 在 mint 时写入。两条容错规则让 attestor 得以
  保持框架无关:

  - `Restore("framework", nil)`(链上无此条目)回退到你的 adapter 名
    + 你的 allowlist 最高版本 + `schema_version: 1`;
  - binding 存在但 **`package_version` 为空/缺失** 时解析为你的
    whitelistMax——attestor mint 无版本 binding,因为版本知识属于校验
    版本的代码(你的 allowlist)。预期首次启动有一笔 drift-commit 把
    具体版本钉上链。

  `name` 不是你的 binding 必须 fail loud——那意味着选择和 adapter 对
  "这个 agent 是什么框架"意见不一(部署坏了,或有人手工构造 adapter),
  硬启动等于伪造身份。
- **没有必填 role。** `RoleSpec` 有意不设 `Required` 字段:sealed 把
  所有 role 都当可选,链上缺谁就用 `Defaults(role)` 顶上。"mint 时
  owner 必须提供什么"由 attestor 强制,不归 sealed。
- **链上重复 role 是硬失败。** 两条 iData 带同一个 role 时 bootstrap
  拒绝启动——身份会变成未定义。
- **未知 role 不报错。** `Restore` 遇到不认识的 role 应记日志并返回
  nil(legacy role 的真正去处见 §5.4 `HandleLegacy`)。

### 3.1 `Defaults` 与"链上缺席"不变量

`Defaults(role)` 返回 canonical 的 **空** plaintext:manifest role 是
空 manifest(`{"schema_version":1,"kind":"directory_manifest","entries":[]}`),
leaf 是你的自然零值(openclaw 的主配置是 `{}`,`framework` 是当前
binding,没有有意义默认值的返回 nil)。

uploader 用它维持一条双向不变量:

> **plaintext == Defaults(role) ⟺ 该 role 在链上没有 iData 条目。**

每次 `Apply`,当前 plaintext 的 hash 等于 `sha256(Defaults(role))` 的
role 会被 *排除* 在整体替换式 `update` 交易之外——于是"恢复默认"等于
链上条目消失,全默认状态的新 agent 链上足迹最小。因此你的 `Defaults`
必须永远字节稳定(它是按 sha256 比较的),且 `Restore(role, nil)` 落
出的磁盘状态经 `EvolutionFor` 必须精确回到这份默认字节——否则每次开机
都是 phantom drift,白白往链上写。

## 4. Manifest 格式(DirectoryManifest role)

定义在 `internal/manifest`。plaintext 是确定性 JSON:

```json
{
  "schema_version": 1,
  "kind": "directory_manifest",
  "entries": [
    {
      "path": "MEMORY.md",
      "kind": "file",
      "content_hash": "0x<plaintext 的 sha256>",
      "size": 1234,
      "storage_ptr": {"root_hash": "0x…", "size": 1290}
    },
    {
      "path": "my-skill/",
      "kind": "dir",
      "content_hash": "0x<确定性 tar.gz 的 sha256>",
      "size": 51200,
      "storage_ptr": {"root_hash": "0x…", "size": 51260}
    }
  ]
}
```

- 条目 **按 `path` 排序**;marshal 字段顺序稳定。相同磁盘状态必须
  产出相同字节——watcher 的 sha256 比较全靠这个。
- `kind: "file"` → 条目 blob 的 plaintext 是文件原始字节。
  `kind: "dir"`(path 以 `/` 结尾)→ blob 是子树的 **确定性 tar.gz**
  (`manifest.PackDir`:排序遍历、时间戳/属主清零)。绝不要 shell 出
  去跑 `tar czf`。
- 所有条目 blob 共用父 role 的 `data_key` 和 indexer;没有按条目的
  加密或 indexer 覆写。

**两态 plaintext——第一号 phantom-drift 陷阱。**
`EvolutionFor` 必须输出 **empty-ptr 形态**:所有 `storage_ptr` 清零。
uploader 负责填指针(`content_hash` 没变的条目复用旧指针),填好的
**filled-ptr 形态** 才是被加密、锚定上链的东西。下次开机链上还回来的
是 filled-ptr 字节;sealed 会先跑 `manifest.StripStoragePtrs` 再 hash,
让 `chainSnapshot` 播种 empty-ptr 的 hash。如果你的 adapter 在任何
地方 hash 或输出 filled 形态,每次重启都会看起来在漂移,整个 role
全量重传。

## 5. 逐方法契约

按管线阶段分组。"调用方"对应 §2 的表。

### 5.1 身份:`Name`、`Version`

`Name()` 是静态 adapter id,必须等于 `framework` binding JSON 里的
`name` 字段。`Version(ctx)` 是 best-effort 运行时探测(可以 exec
CLI);当前(未)接线状态见 §2.2。

### 5.2 恢复方向:`Restore`、`RestoreEntry`

`Restore(ctx, role, plaintext)` 把一个 role 的 plaintext 落到你的
磁盘/内存。要求:

- **跨 role 满足交换律 + 单 role 幂等。** 每个 role 必须拥有互不相交
  的磁盘切片;同一组 Restore 调用任意排列产出相同终态,重放相同字节
  是 no-op。bootstrap 的三轮顺序(§6)依赖这条。
- `plaintext == nil` 意为"链上无此条目":应用 `Defaults`。
- manifest role 的 `Restore` 收到的是(filled-ptr)manifest 字节,
  应解析/记录,但 **绝不自己去取条目 blob** ——调用方负责逐条目下载
  + 解密,再喂给 `RestoreEntry(ctx, role, path, plaintext)`(file
  条目给文件字节,dir 条目给待解包的 `PackDir` tar.gz)。
- Restore 跑在 `Start` **之前** ——你的框架进程还没起来。别在这里调
  框架的 API;直接写文件。

### 5.3 进化方向:`EvolutionFor`、`LoadEntry`

`EvolutionFor(ctx, role)` 读取当前磁盘/内存状态,返回该 role 的
canonical plaintext。它在 **每个 30s watcher tick 对每个声明的 role**
各调一次,外加 bootstrap 时两次基线播种。硬性要求:

- **确定性**:相同状态 ⇒ 相同字节(字段顺序稳定、条目排序、manifest
  用 empty-ptr)。
- **round-trip 稳定**:`Restore(x)` 之后的 `EvolutionFor` 必须复现
  `x`(leaf)/ `StripStoragePtrs(x)`(manifest)。你的运行时 *注入*
  进被管理文件的任何内容都必须在这里剥掉——openclaw adapter 把注入的
  IDENTITY/SOUL/TOOLS 段包在 `<!-- 0g-platform-injected:start/end -->`
  标记里,hash 时剥除,这样单个沙箱的事实永远不会漏进链上身份。
- **过滤运行时噪音。** 如果你的框架会往被管理文件里写非身份键(日志、
  会话缓存、向导标记),对身份键用 **allowlist** 而不是 denylist——
  框架未来版本会加你没预料到的键,denylist 下每个新键都是一次
  phantom drift。
- **要便宜。** 每个 role 每 30s 跑一次;重探测的活要缓存或摊销。
- 不认识的 role 返回 `framework.ErrUnsupportedDim`(调用方会跳过,
  不会失败)。

`LoadEntry(ctx, role, path)` 是 `RestoreEntry` 的按条目逆操作:
uploader 对每个 `content_hash` 变化的 manifest 条目调它,拿 plaintext
去加密 + 上传。它返回的字节 hash 必须精确等于你 `EvolutionFor`
manifest 里给该 path 声明的 `content_hash`(同样的剥除逻辑),否则
上传会打转。

### 5.4 种子摄入:`HandleLegacy` 与 `persona` role

链上 iData 条目的 role **不在** `Roles()` 里时,bootstrap 对每条各调
一次 `HandleLegacy(ctx, role, plaintext)`。它在所有声明 role 的
Restore **之后** 运行,所以摄入能可靠覆盖默认值。必须幂等;不认识的
role 必须记日志并忽略(返回 nil),绝不报错——链上可能带实验性
role,为它拒绝启动比部分迁移更糟。

**`persona` 是协议级种子 role,摄入它是强制契约。** attestor 框架
无关且什么都不合成(WYSIWYS——owner 签什么就铸什么);由部署客户端
(SDK `defaultIData()`、控制台表单)构造这一条中性种子——

```json
{"system_prompt": "You are <name>. <description>\n",
 "inference": {"provider": "anthropic", "model": "claude-opus-4-6"}}
```

——从不书写任何框架的配置 schema。翻译是你的 adapter 的职责:把
`system_prompt` 和推理钉选映射到你自己的路径驱动产物上(openclaw →
SOUL.md + openclaw.json 的 model/auth;已下线的 claudecode 移植 →
CLAUDE.md + settings.json 的 `model`)。忽略 `persona` 的 adapter 会把 owner 在
mint 时写的 prompt 和模型选择静默丢掉——claudecode 移植初版恰好带着
这个 bug 出厂,这条规则因此成文。框架无法兑现钉选的某部分时(比如非
原生的推理 provider),记日志、保留自己的默认值,不要写下框架解析不了
的配置。

注意不对称性:被摄入的 role 是只读输入。uploader 会把 `Roles()` 之外
的链上条目从下一次整体替换 `update` 里丢掉,所以 `persona` 首次开机
被消费、首次漂移提交后从链上消失,留下路径驱动的 role 作为持久形态。

### 5.5 进程生命周期:`Start`、`Stop`、`Liveness`、`Readiness`、`MonitorExit`

`Start(ctx, rt RuntimeContext) (StartResult, error)` 基于之前 Restore
好的状态拉起你的框架,返回 `StartResult{Upstream, PID}`,其中
`Upstream` 是 proxy 要转发的 localhost 明文 HTTP 地址(openclaw:
`http://127.0.0.1:3284`)。契约要点:

- **上游真正开始接受连接后才返回**(轮询端口,带超时——openclaw 用
  120s,含可能的 npm install)。*首次* Start 返回错误被当作致命配置
  问题:不重试。
- 监工每次 **重启** 和 `manager.Reload` 都会再调 Start,重放同一份
  `RuntimeContext`。昂贵/一次性的工作(安装、token 生成)要用"首次
  启动"标记挡住,且重启时绝不覆盖 agent 的自我修改——平台原则是
  sealed 只负责让 agent 活着,不干涉 agent 对自己做过的事。
- 框架凭据(dashboard token 等)**留在 adapter 私有状态里** ——只通过
  `AuthResponse` 暴露。

`Stop(ctx, gracefulTimeout)`:SIGTERM,等到超时,SIGKILL。还要清扫
你的框架可能 fork-exec 出的孤儿子进程(残留子进程占着上游端口会让
下一次 Start 失败)。

`Liveness` / `Readiness`:便宜的探针(TCP dial 就行),manager 每 5s
调用。Liveness 失败触发重启序列(退避 1s→60s,默认 5 次,然后
`PhaseFailed` + 向 attestor 报 error)。Readiness 决定 `/hello` 和
proxy 是否回 503;如果你的框架没有预热阶段,可以和 Liveness 用同一个
检查。

`MonitorExit`:见 §2.2。

### 5.6 Owner 鉴权:`AuthResponse`

`/_seal/auth` 的完整验证由 proxy 负责(owner 用 EIP-191 签
`0GSealAuth:0x<sealId>:<ts>`;proxy 校验恢复出的地址 == 链上 owner,
±300s 时间窗),验证通过才调 `AuthResponse(ctx)`。你返回一个可 JSON
编码的载荷,授予已验证的 owner 控制面访问权——openclaw 返回
`{"token": …, "dashboard_url": "/#token=…"}`。Start 还没准备好凭据时
返回错误(proxy 会转成 503)。绝不要在这里自己做鉴权;调用方已经做完了。

## 6. 生命周期时间线(每个方法何时被调)

```
开机(main.go Phase 3):
  Roles()                              枚举 + 去重检查(重复 role ⇒ 硬失败)
  A 轮  每个链上存在的声明 role:
    Restore(role, chainPlaintext)
    RestoreEntry(role, path, pt)…      manifest 子条目,由 sealed 下载解密
    SeedChainSnapshot(sha256(剥指针后的 plaintext))
  B 轮  每个链上缺席的声明 role:
    Restore(role, nil)                 落 Defaults
    SeedChainSnapshot(sha256(Defaults(role)))
  C 轮  每个不在 Roles() 里的链上条目:
    HandleLegacy(role, plaintext)
  播种 #1:对所有 role 跑 EvolutionFor  → currentSnapshot(Start 前)
  manager.Start:
    Start(ctx, RuntimeContext)         spawn;上游监听后才返回
    MonitorExit(cb)                    布置死亡监视
    Liveness(ctx) 每 5s                探针循环开始
  sleep 5s                             settle:让框架写完自己的默认值
  播种 #2:对所有 role 跑 EvolutionFor  → currentSnapshot(settle 后基线)

稳态:
  每 30s      watcher:对所有 role 跑 EvolutionFor;漂移 ⇒ OnDrift
  漂移时      handleDrift:
                若 "framework" 漂移:ReconcileFramework + manager.Reload
                                      (Reload = Stop + Start,参数重放)
                uploader.Apply:按需调 Defaults()/LoadEntry() → 一笔 chain.Update
  进程死亡    MonitorExit 触发:err 非 nil ⇒ 重启(带退避的 Stop+Start);
              nil ⇒ 等 Liveness 裁决
  /_seal/auth(验证通过) AuthResponse(ctx)
```

5 秒 settle 延迟的存在是因为框架通常会在首次启动时重写一遍自己的
配置补默认值。基线在那 *之后* 采集,框架自己补的默认值才不会被报成
漂移。你的框架 settle 更慢的话,实现 `SettleDelayer` 能力接口
(§2.2)——`main.go` 的 `defaultSettleDelay` 只是缺省值。

## 7. `RuntimeContext`:sealed 交给你 `Start` 的东西

| 字段 | 内容 | 说明 |
|---|---|---|
| `APIKey` | deploy envelope 里的推理 provider key | 翻译成你的框架期望的 env 变量 |
| `PublicURL` | `http://8080-<sandboxId>.<proxyDomain>` | 本地开发时为空;通过 env / 文件 / 配置暴露给 agent,让它知道自己的地址 |
| `SealSignSock` | `/run/seal-sign.sock` | agent 专用签名端点(§8);告诉你的 agent 它在哪 |
| `AgentSeal` | 从 `agent_seal_priv` 公钥派生的 0x 地址 | agent 的 TEE 身份地址 |
| `AgentID`、`Owner`、`ChainRPC`、`ContractAddr`、`AttestorURL` | 链上 bootstrap 输出 | 公开链上事实,不是秘密;注入 agent 的 context 让它能推理自己的身份 |
| `Provider`、`Model`、`ZGComputeRouted` | 解析后的推理路由 | 今天由 adapter 自己的 Start 路径填(openclaw `spawn.go`) |
| `SealedVersion` | sealed 二进制的 git hash | 用于 proof/元数据表面 |

拿这些做什么是 adapter 的策略,但 openclaw adapter 是参考实现:它往
agent 的 context 文件里注入 marker 包裹的段——身份事实(IDENTITY)、
拒签教义(SOUL)、签名 socket 用法 + public URL(TOOLS)——并给子进程
传一个小的 env allowlist(`AGENT_PUBLIC_URL`、provider API key、
`SEAL_SIGN_SOCK`)。无论你选哪种通道,记住 §5.3:注入的内容必须从
`EvolutionFor` 输出里剥回去。

## 8. sealed 在你的进程周围跑着什么

这些是白送的;设计你的框架的对外表面时按它们的存在来假设:

- **`:8080` 签名反向代理** ——每个响应(健康/日志端点除外)都带
  `X-Agent-Proof` 头:`agent_seal_priv` 对 canonical envelope 的
  EIP-191 签名,envelope 含每个 role 的 `content_hash` + `data_hash`。
  你的上游只需在 localhost 上提供明文 HTTP;WebSocket 升级不签名直通。
- **`GET /hello`** ——签名的自我介绍:agent 身份、当前 `data_hashes`、
  `public_url`,以及(如果 agent 通过 `POST $SEAL_SIGN_SOCK/services`
  注册过)agent 自声明的服务列表。
- **`POST /_seal/auth`** ——§5.6 的 owner 鉴权流程。
- **`unix:///run/seal-sign.sock`** ——`POST /sign/personal_sign`、
  `/sign/typed_data`、`/sign/transaction`;仅容器内可达。agent 就是
  靠它以 AgentSeal 身份签名而永远不持有私钥。socket 本身只是传输——
  *拒签政策活在 agent 的教义里*(见
  [AGENT_DOCTRINE.zh.md](AGENT_DOCTRINE.zh.md));你的 adapter 应该
  装一套等价于 openclaw SOUL 规则的东西,让来自外部 prompt 的签名
  请求被拒绝。
- **`/log`、`/log.html`、`/log/agent`(`.html`)** ——bootstrap 和
  子进程的实时日志。把框架的 stdout/stderr 落到文件并实现
  `framework.SubprocessLogProvider`,子进程日志页就会点亮
  (`/log/openclaw` 作为 legacy 别名保留)。

## 9. 不变量清单(a.k.a. 如何不 phantom-drift)

下面每一条都出过真实 bug;违反任何一条,watcher 都会把它变成无限
重传循环或无声的身份分叉。

- [ ] `EvolutionFor` 对相同状态字节级确定。
- [ ] `Restore(x)` 后 `EvolutionFor` == `x`(leaf)/ `StripStoragePtrs(x)`(manifest)。
- [ ] `Restore(role, nil)` 后 `EvolutionFor` == `Defaults(role)`。
- [ ] `Defaults(role)` 跨 adapter 版本字节稳定。
- [ ] Manifest 输出是 empty-ptr,条目按 path 排序,dir 条目走确定性 tar.gz。
- [ ] `LoadEntry` 的字节 hash 等于 `EvolutionFor` 声明的 `content_hash`。
- [ ] 平台/运行时注入进被管理文件的一切都有 marker 包裹并在 hash 前剥除。
- [ ] 被管理配置用键 allowlist;框架自有的运行时键永远进不了 plaintext。
- [ ] Restore 跨 role 可交换、单 role 幂等。
- [ ] `HandleLegacy` 幂等,对未知 role 永不报错。
- [ ] `Start` 在上游接受连接后才返回;重启不重做首启工作、不覆盖 agent 自我修改。
- [ ] `Stop` 不留占着上游端口的孤儿。
- [ ] `MonitorExit` 每个 spawn 的进程恰好触发一次;exit-0 不由你的代码当 crash 处理(manager 负责)。

## 10. 测试你的 adapter

从你的 adapter 包的测试里跑共享 conformance 套件
(`internal/framework/conformance`)。它把 §9 的不变量落成可执行断言
(role 结构检查、Defaults round-trip、fixture round-trip + 确定性 +
LoadEntry hash 一致性、Restore 交换律、未知 role 错误契约):

```go
func TestConformance(t *testing.T) {
    conformance.Run(t, conformance.Config{
        New: func(t *testing.T) framework.Framework {
            yourHome = t.TempDir()          // 重定向磁盘根
            probeVersion = stubbed          // 见下
            return New()
        },
        Fixtures: []conformance.Fixture{ /* 逐 role 的样例内容 */ },
    })
}
```

树内 adapter 在跑它(`openclaw/conformance_test.go`;已下线的
claudecode 移植当时也跑);它对 openclaw 的第一次运行就当场
抓出两个真实 bug(§12)——把 conformance 红灯当成白捡的生产事故看待。

套件结构性强制的两条血泪规则:

- **stub 掉外部探测。** `EvolutionFor` 里的任何 CLI 探测必须是可替换
  的包级 var——否则测试机 PATH 上真实存在的 `claude`/`openclaw` 会
  漏进 round-trip 结果。
- **fixture 必须是 canonical 字节。** leaf fixture 与 `EvolutionFor`
  输出做字节级比较,所以要按你的 adapter 的 canonical 编码写(紧凑
  JSON、键排序)。

conformance 之外,再补 adapter 特有的测试:注入剥除 round-trip(注入
后断言 `EvolutionFor` 和 `LoadEntry` 输出不变——见
`platform/markers_test.go` 与 openclaw 的 `evolution_paths_test.go`)、
密钥类键的 allowlist
过滤、异框架 binding 拒绝。

想在真实循环里接入你的 adapter:本地不设 `ATTESTOR_URL` 跑 sealed
(只服务 `/healthz` + `/log`,跳过 provision/bootstrap),或用 dev
沙箱对 0G testnet 跑——env 表面见
[ARCHITECTURE.zh.md](ARCHITECTURE.zh.md) §8。

## 11. 移植清单

1. 在 `internal/framework/<yourfw>/` 实现 `framework.Framework` +
   `MonitorExit`,在你的 `New()` 里 `framework.Register` 自注册;在
   `main.go` 加一行注册。CLI 型框架照 git 历史里已下线的
   `claudecode/`(内嵌 bridge 模式,另见 §12 的下线原因),服务型框架
   照 `openclaw/`。
2. 声明你的 role 集,包括保留的 `framework` leaf(含空版本 →
   whitelistMax 规则);逐 role 决定 Leaf 还是 DirectoryManifest。
3. 实现 `HandleLegacy["persona"]`——强制的协议种子翻译(§5.4)。
4. 实现适用的可选能力接口(§2.2)——框架能用包管理器安装的话至少
   实现 `VersionReconciler` + 版本 allowlist,并写编译期断言。CLI
   shim 用 `go:embed` 放进你的包、Start 时落盘——绝不烧进镜像。
5. 用每个 role 的 fixture 跑 conformance 套件(§10);补注入剥除、
   密钥过滤、persona 摄入、无版本 binding 测试。
6. 框架是 npm 可装的话,可选地往 `images/sealed/Dockerfile` 加一行
   热缓存;无论加不加,通用镜像重建后的 hash 都走 attestor 的
   allowlist 流程。只有新的运行时生态(Python、JVM)才会结构性地
   增大镜像。
7. 把你的框架名加进 attestor 的支持名单,部署时才能选中它——
   attestor 把名字当不透明字符串(mint 前校验、写进无版本 binding、
   UI 里列出),除此之外零改动(本仓库 `attestor/`)。
8. 装一套等价于 openclaw SOUL 段的拒签教义(见
   [AGENT_DOCTRINE.zh.md](AGENT_DOCTRINE.zh.md)),别让签名 socket
   变成 prompt 注入请求的开放签名器。有共享的 `platform.Build` 内容,
   这只是一个 delivery 函数(见 git 历史里已下线的
   `claudecode/claudemd.go`——整个 PlatformContext 作为单个 marker
   段落进 CLAUDE.md)。
9. 自己撰写你框架的上下文事实,和平台段落一起注入。`platform.Build`
   刻意只讲教条和平台机制——不出现任何框架的路径、升级命令、配置语义、
   工具名(有测试焊死)。以下必须由**你自己**的注入文本告诉 agent:
   哪些磁盘路径会上链、持久的东西该放哪、你的版本白名单/回正行为、
   配置 hash 语义。不写,你的 agent 就会把记忆写到不追踪的地方、下次
   重建就丢——向 agent 交代它自己框架的真相是 adapter 的责任,不是
   平台的。openclaw 的在 `openclaw/platformtext.go`。

## 12. 移植实录:接入 claude-code(2026-07)—— 已下线,保留为案例

> **状态:已下线。** claudecode adapter 已从出货树移除。它证明了 seam 是
> 真的,但一个"每次调用现拉起、挂在 bridge 后面的 CLI"托不住这里"干活
> agent"的核心能力——owner 委托、可对外调用的服务(openclaw 的常驻
> server 模型可以)。与其出一个"注入的平台 guidance 吹嘘了它并不具备的
> 服务能力"的半成品,不如撤掉。本实录保留,作为下一个 CLI 型框架的实战
> 指南;代码在 git 历史里。

claudecode adapter 是刻意当作接缝探针来写的:选一个结构上和 openclaw
截然不同的框架(bridge 背后的按次调用 CLI、单一 context 文件、没有
dashboard),严格按本文档的契约实现,坏什么修什么。发现按严重度递减
列在这里——让下一次移植知道哪些墙已经搬掉、哪些还在。

**发现并修复的协议级 bug:**

1. **marker 剥除是有损的**(`platform.UpsertMarkedSection` /
   `StripInjected`,当时还是 openclaw 私有)。旧 upsert 会归一化
   owner 内容("确保 section 前有空行"往后补换行),而这不可逆——
   strip 只能猜,把尾部换行全部吞掉,吃掉 owner 的最后一个 `\n`。
   生产后果:每个带注入的文件在 agent 生命周期里**必然** phantom
   drift 一次(首个 watcher tick 把裁剪后的字节传上链,然后收敛),
   浪费一笔 `chain.Update`,还悄悄改写了 owner 写的字节。claudecode
   的注入 round-trip 测试抓到了它;现在的 wire format 无损(分隔符归
   section 所有,绝不归一化 owner 字节)。
2. **`EvolutionFor` 里的 live CLI 探测不可测试且随环境漂移。**
   openclaw 的 `probeOpenclawVersion` 是普通函数;开发机上装着真实
   openclaw 时,探测结果覆盖 restore 的 binding,round-trip 直接崩。
   两个 adapter 的探测现在都是可替换的包级 var,测试里 stub。规则:
   任何喂进 canonical plaintext 的外部探测都必须可注入。

**发现并修复的接缝缺口(本次移植前的 §2.1 清单):**

3. adapter 选择硬编码(`main.go` 持有 `*openclaw.Adapter` 具体类型)
   → 现在按 `AGENT_FRAMEWORK` 走注册表。
4. `ReconcileFramework` 对具体类型直调 → 现在是可选接口
   `framework.VersionReconciler`,并为不能回正的 adapter 定义了降级
   语义(漂移原样上链)。
5. services 清单路径和子进程日志路径是 `main.go`/`proxy` 里的
   openclaw 字面量 → 现在是 `ServicesManifestProvider` /
   `SubprocessLogProvider`;`/log/openclaw` 作为 `/log/agent` 的别名
   保留。
6. settle 延迟是 `main.go` 里按 openclaw 调的常量 → 现在是
   `SettleDelayer`(claudecode 声明 1s;openclaw 保持 5s)。
7. marker 工具函数在 openclaw 包里,而**内容**生成器
   (`platform.Build`)早已共享 → delivery 原语移到
   `internal/platform/markers.go`。
8. §9 不变量只存在于文字里 → 可执行的
   `internal/framework/conformance` 套件,两个 adapter 都在跑。

**已知的毛边,刻意留下(欢迎开 issue):**

9. `Start` 的辅助函数(`waitForListen`、`randomTokenHex`、npm 安装)
   在两个 adapter 间重复——第三次移植时应该提取共享 spawn-util 包。
10. `RuntimeContext` 把 bootstrap 输入和 adapter 自己解析的字段
    (`Provider`/`Model`/`ZGComputeRouted`)混在一个结构里;拆成
    输入/输出两个类型会更干净。
11. `AuthResponse` 预设"有东西可以交给验证过的 owner"。对没有
    dashboard 的框架,载荷就是 shim 端点的 bearer token(claudecode
    返回 bridge admin token)——没问题,但目前只有文档在说这件事。
12. 推理路由是 adapter 各自的策略:claude-code 是 Anthropic 原生,
    0g-compute 路由(OpenAI 协议)在它身上不可用;`framework` role
    今天表达不了"provider 约束"。
13. `MonitorExit` 仍在 `framework.Framework` 之外(改为启动时
    assert)。更干净的修法——`Start` 返回 exit channel——会动到每个
    adapter 和 manager,留给下一次破坏性契约修订。

**后续一轮(2026-07-07)** ——对这次移植的设计评审把接缝又推进了一步;
上面的清单保留历史原貌,以下是被取代的部分:

14. 第 3 条的 env 驱动选择自己也被替换了:现在是 **binding 驱动**
    (§2.1)——二进制已注册所有 adapter,链上身份可以也应该来选,
    `AGENT_FRAMEWORK` 降级为本地 dev 的 fallback,attestor 不再注入。
15. `persona` 从"openclaw 的遗留怪癖"升格为强制的协议种子 role
    (§5.4),修掉了 claudecode 静默丢弃 mint 时 prompt/model 的缺口。
16. 无版本 binding 合法化(空 `package_version` → whitelistMax),
    消除了 attestor profile 和 adapter allowlist 之间重复的版本真源
    (它们当时已经漂移了:2026.5.6 vs 2026.5.7)。
17. 按框架分镜像被一个通用镜像取代(`images/sealed/`):框架安装是
    热缓存、claudecode bridge `go:embed` 进二进制、attestor allowlist
    只挂一个 hash。净效果:attestor 完全框架无关——它对框架的全部
    知识只剩一张不透明名字清单。
18. 第 12 条毛边被生态解决:0g-compute 上线了 Anthropic 兼容端点
    (含 Claude 系模型),claudecode 现在把
    `persona.inference.provider = "0g-compute"` 经 `settings.json` 的
    `env.ANTHROPIC_BASE_URL` 路由到 0G router——该框架的可验证推理
    信任层就此补全。base URL 通过 env 子键白名单上链(路由去向属于
    身份,可审计),凭据留在 sandbox env,永不进链上明文。
19. 第 18 条的生态变化随即在线上打爆了 openclaw adapter(它的 0g
    增强硬编码 OpenAI 线格式;claude-* 在 router 上只有 Anthropic
    格式 → 部署全绿、首次推理 400)。根因是分层:provider 知识按
    adapter 重复存放,必然漂移。现在收敛到 `internal/inference` 一处
    ——`ResolveZG` 读 router 公开模型目录(`supported_formats` +
    上下文/输出上限,目录不可达时启发式兜底),adapter 只把解析好的
    Route 翻译成自家配置方言。给未来 adapter 的规则:**永远不要编码
    "provider 提供什么",只编码"怎么告诉你的框架"**。
20. 部署 API 走向 WYSIWYS:第 14 条那个签名覆盖的 `framework` 参数只
    活了一轮——真实使用暴露了它的缺陷:用户自带的 i_data binding 可以
    与之不一致(并绕过它),因为存在两个真源。现在客户端交付完整
    iData,其中的 binding 是唯一选择器,owner 签的是上链的字节本体而
    不是服务端模板的输入。合成移到客户端(SDK `defaultIData()`)。
21. claudecode 加了浏览器聊天控制台(openclaw 有 dashboard,Claude
    Code 是 CLI 没有),bridge 在 `GET /` 提供。部分被 23–24 条取代:
    控制台是 owner 控制面(需鉴权),services-manifest 广播已撤(暂无
    public serve 面)。

**部署加固轮(2026-07 稍后)** ——线上 testnet 跑已部署二进制暴露的,
均已修复:

22. **framework binding 被从链上删 → 重建后身份丢失。** isDefault-omit
    优化(内容==Defaults 就从链上省略)命中了 `framework` role:无版本
    binding 解析成 whitelistMax 后恰好等于 Defaults("framework"),首次
    演化把它删了。容器重建时链上无 binding → resolveAdapter fallback
    默认框架,claude-code agent 静默变 openclaw。修复:`framework` 是
    身份锚,豁免 omit,永远留链上。(已收敛的旧 agent 无法自愈——
    binding 已丢,需重新部署。)
23. **聊天控制台加鉴权 + token 纯内存。** `/v1/query` 花 owner 的推理
    key、改 agent 状态,是 owner 控制面而非 public serve 端点——现在按
    owner token 门控(来自 /_seal/auth)。token 纯内存,经 `#token=`
    fragment 传入(openclaw dashboard 模式),不再有常驻可见框。真正的
    public serve 面(任何人调用+验证做声誉)需计费/限流,是独立特性;
    services-manifest 广播(第 21 条)相应撤销。
24. **身份/教义改经 `--append-system-prompt` 注入,不再进 CLAUDE.md。**
    CLAUDE.md 是 Claude Code 的*记忆*不是 system prompt,注入的身份被
    当 advisory,安全调优的模型拒绝采纳(线上拒认自己的 agentSeal 身份)。
    权威通道是 `claude -p --append-system-prompt`(openclaw 用
    SOUL/IDENTITY 拼 system prompt 的等价物)。CLAUDE.md 现在纯归 agent。
    通用教训:每个 adapter 必须把平台 context 注入到其框架的**权威**
    指令通道,不是记忆通道——且要**验证模型真的采纳了身份**,别假设
    注入就生效。
25. **SDK 加了 agent-runtime 面**(`agent.sayHi` + `stop`/`start`/
    `reset`),和运行中 agent 交互(serve-proof 验证、恢复/重载)成为
    一等公民并有回归(`sdk/typescript/scripts/agent-e2e.cjs`),不再是
    ad-hoc curl。
