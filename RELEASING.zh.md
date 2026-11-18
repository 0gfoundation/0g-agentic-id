# 发版

一个版本从 `dev` 发到测试网和主网的步骤。每一步都写明细节在哪份文档里；这里只管顺序。先发测试网，再发主网。

English: [RELEASING.md](RELEASING.md).

## 1. dev 上准备好

- 这个版本要带的东西都已合入 `dev`，并在 dev 的默认镜像上实测过：agent 是 reset 到 attestor 默认快照上测的，不是按 agent 指定的测试快照。

## 2. 发版 PR（合入 `dev`）

- **版本号**：所有写版本号的地方都要改：
  - `sdk/typescript/package.json` 和 `package-lock.json`；
  - `sdk/typescript/src/constants.ts` 里的 `SDK_VERSION`；
  - `sdk/typescript/compat/legacy/package.json`（它自己的版本，以及它对 `@0gfoundation/0g-agentdna` 的精确依赖）；
  - `attestor/Cargo.toml` 的 workspace 版本和 `attestor/Cargo.lock`。
- **发布说明**：写好 [`CHANGELOG.md`](CHANGELOG.md) 里这个版本的一节，并去掉标题里的 `(unreleased)`。第一行是 owner 在 CLI 里看到的一句话摘要。
- **各环境的日期和镜像**：在 `releases/testnet.json` 和 `releases/mainnet.json` 里给这个版本写上：
  - `published_at`：不早于它的镜像在该环境成为默认的时刻；
  - `migrate`：它替换掉的镜像（每个框架一条），以及每个镜像过渡期的结束时间 `until`。测试网至少 14 天，主网至少 30 天。

  见 attestor README 的[发布通知](attestor/README.zh.md#发布通知)。
- **合约**（这个版本改了合约时）：按 [`contracts/UPGRADING.md`](contracts/UPGRADING.md) §1 提高每个改过的实现的 `VERSION`。
- **提升到 main**：
  1. 合入后，用一个 squash 的 PR 把 `dev` 提升到 `main`，标题为 `release: AgentDNA <版本> — …`；
  2. 在 `main` 上打 `v<版本>` 标签；
  3. 再把 `main` 合回 `dev`。

## 3. 从标签构建

- **镜像**：从 `v<版本>` 的干净检出构建四个框架的镜像（`sealed/images/*`）和 attestor 镜像，推到镜像仓库。0g-harness 镜像带的是 `HARNESS_REF` 指定的那个 harness 提交（`sealed/images/harness/Dockerfile`）。
- **包**：把 sealed 程序和 harness 包发布为 `artifacts` 发布（release）的附件，各以自己的 sha256 命名（见 [`sealed/LAYERS.zh.md`](sealed/LAYERS.zh.md) 的"下载"）。harness 包按 Dockerfile 开头的说明，从构建镜像时的 `harness-package` 阶段取出。
- **记录**：把每个 digest 和哈希记进部署记录。

## 4. 逐个环境（先测试网，再主网）

1. **合约**（这个版本改了合约时）：通过该环境的 Timelock 排期并执行 beacon 升级（`contracts/UPGRADING.md` §2）。主网要等一天，要提前排期。新地址记进 `contracts/DEPLOYMENT.md` §6。
2. **信任列表**：在新镜像成为默认之前，通过 Timelock 把新镜像、sealed 和 harness 的哈希加进 TrustRegistry（`contracts/script/TrustRegistryCalls.s.sol`；[`contracts/README.md`](contracts/README.md)）。已经在列表上的哈希会让 `list` 回滚，所以一批里只放新的。
3. **快照**：把镜像导入为该环境的沙箱快照。
4. **attestor**：
   - 部署新的 attestor 镜像。
   - 把 `ATTESTOR_FRAMEWORKS` / `ATTESTOR_SANDBOX_SNAPSHOT` 指向新快照。
   - 生成发布记录文件，放到机器上：

     ```
     node attestor/scripts/release-entry.mjs --changelog CHANGELOG.md \
       --params releases/<testnet|mainnet>.json --min-days <14|30> \
       --out <部署目录>/releases/releases.json
     ```

     compose 会挂载 `./releases`，并设好 `ATTESTOR_RELEASES_FILE`。
   - 设好 `ATTESTOR_CLI_LATEST`，再写一行 `ATTESTOR_CLI_NOTES`，写明过渡期的结束日期和要 reset。发布通知出现之前的旧版 CLI 只显示这一行。
   - 重启 attestor，并重新确认信任根。
5. **CLI**：按[发布顺序](sdk/typescript/MIGRATION.zh.md)发布 `@0gfoundation/0g-agentdna` 和它的兼容包。还有网络在跑上一个版本时用 `next` 标签；所有网络都换到这个版本后，再把 `latest` 指过来。
6. **冒烟测试**：每个框架各 reset 一个 agent 到默认版本（不指定快照），然后跑 `attestor/scripts/verify-agent.sh`，看 `/hello`（它会列出已上架的哈希），再聊一句。

## 5. 过渡期

- 用被替换镜像的 agent 照常运行。
- owner 会在三个地方看到通知：
  - **CLI**：打开时的提醒（每周一次，最后 7 天每天一次），以及 `0g-agentdna releases`；
  - **owner 的 agent 列表**：要迁移的 agent 带 `migrate` 标记；
  - **邮件**：设置了 `ATTESTOR_NOTIFY_*` 的环境，发布时一封，最后 7 天一封。

## 6. `until` 之后

- 由 guardian 下架被替换镜像的哈希，立即生效（`contracts/README.md`）。还在用它的 agent 继续运行到容器下次启动；那次启动会被拒，直到 agent 被 reset。
- **紧急版本**：标了 `urgent` 的条目（安全修复）可以在 `until` 之前下架。提前下架时，另外给 owner 发通知。
- 没有 agent 再用旧快照之后，删掉旧快照。
