# 前端改造工作分支(feat/web-revamp)

面向用户的控制台从"运维工具"升级为"产品入口"。本文件是这个分支的
工作清单与决策记录,随改造推进更新;全部完成后删除本文件。

背景:2026-07-17 的全量筛查(见 PR #42 描述)。已在底座分支完成:
innerHTML XSS 加固、部署页前置状态条、部署成功页演化 gas 引导、
三层同步 preflight。

## 待办(按优先级)

优先级调整(2026-07-17,wei):**先打磨已有功能**,新功能(transfer/
clone UI)往后排。

### P0 — 已有功能打磨
- [x] Google Fonts 外链 vendor 化(web/fonts/,4 个 latin 变量字体,
      ~370KB 嵌入二进制,immutable 缓存头)
- [ ] UI 状态收敛:消灭手拨 style.display,改单一 render(state);
      历史 bug(#11 失败态按钮、KMS 慢无反馈)都是这个根因。
      做法:按视图逐个收敛(deploy 进度 → 列表 → 详情),小步 PR
- [x] 异步失败可见性:failed/offline 行内直显原因短语(截断+完整版仍在 hover)
- [x] ack 意图锚定:进 Deploy 页(已连钱包且未 ack)自动弹一次 ack 模态;未 ack 时 Deploy 按钮禁用并说明原因。站点入口不弹(知情同意不是 cookie 横幅)
- [ ] ack 版本变更时解释"为什么又要 ack"(显示 app 更新版本号)

### P1(暂缓)— 功能空洞:transfer / clone 没有 UI
产品核心叙事("agent 是可转让/可克隆的资产")目前只能写代码调 SDK。
- agent 详情页加 Transfer 面板:输入接收地址 → `transferFrom` 钱包
  交易 → 等 indexer 同步 → 提示新 owner "Bring online" 的含义
- 详情页加 Clone 面板:目标 owner(默认自己)→ 签 CanonicalClone →
  POST /clone → 复用部署进度条
- 两处都要把"卖家容器会被拆 / 买家要自己 ack+充值+拉起"讲清楚

### P2 — 工程底子
- 单文件 ~5.1k 行(wc -l 现为 5053)拆分:先做无框架的物理拆分(css / 视图模板 / js 模块
  用构建时拼接或 ES modules),评估后再决定是否引入框架。度量约束:
  产物仍需是可审计的静态文件(TEE 镜像内),避免引入 npm 供应链 →
  倾向"无依赖构建"或 vendored 单一构建器

### P3 — 体验细节
- 两次部署签名合一(协议层,需 attestor 配合:owner canonical 内嵌
  sandbox envelope 摘要;单独立项)

(原列于此的"ack 版本变更解释"已并入 P0 唯一条目;"异步失败在列表页
的可见性"已完成,见 P0 的 [x] 项。)

## 决策记录
- (待填)
