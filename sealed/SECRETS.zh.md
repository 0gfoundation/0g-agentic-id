# Owner 密钥 —— agent 能用,但看不到

英文版见 `SECRETS.md`,两者保持同步。

## 1. 问题

干活的 agent 需要 owner 持有的凭证:付费 API key、webhook secret、聊天平台 bot
token。现在它没有安全的地方放。`memories/`、`skills/`、人设文件都是上链的 iData
角色,写进去的凭证会加密上传 0g storage,**转让时还一并交给下一个 owner**。而且不
管放文件还是环境变量,agent 进程都读得到,被提示注入的 agent 就能把它外泄。四家框架
实测都如此:没有一个能让密钥脱离模型的触及范围。

目标是给密钥 agentSeal 私钥已有的待遇:**agent 能用一个密钥,但从不看到它的值。**

范围:本方案只管 **owner 交入的业务密钥**(Stripe、Telegram token 等),不涉及
**agentSeal 身份私钥**——后者由环境生成、经 `/provision` 注入、用于本地签名(不出
容器),且必须对所有人(包括 owner)保密,见 `TRUST_MODEL.md`。

## 2. 不变量(契约)

1. **真值只在 sealed 的内存里。** 加密下发,sealed(root)解开后持有;不落盘、不进
   agent 环境、不交给框架进程。
2. **agent 只见替身** —— `{{secret:NAME}}`。替身给不出任何东西:它不是值,也推不出值。
3. **每个密钥自带一张专属窄白名单**(允许发往的域名)。没有白名单的密钥不可用——这
   是"agent 被骗也泄不出去"的根。
4. **只在出口、且目标在该密钥白名单内时才替换。** 发往名单外 → 不替换(对端只收到
   没用的替身)。
5. **响应也脱敏** —— 响应体/头里出现真值,先换回替身再交给 agent。
6. **owner 绑定,随 owner 作废。** 加密给 agentSeal;打开时 sealed 校验"加密时 owner
   == 当前链上 owner",不符即弃(复用 `secretenv` 的规则)。转让时 attestor 清空已存
   密钥(与 settings 保留不同)。
7. **绝不上链。** 密钥是运营凭证,不是 agent 的身份或记忆;永不进任何 iData 角色。

## 3. 架构(复用现有通道)

```
owner(CLI)--加密给 agentSeal--> attestor 存 {密文, hosts[]}
                                   |
                       每次开机 /provision 下发(同 settings 那条路)
                                   v
                       sealed 解开 -> 内存 { NAME: {value, hosts[]} }
                                   |
agent 请求(密钥位 {{secret:NAME}})-> sealed loopback 出口代理
                                   -> 目标在 NAME.hosts 内? -> 换真值 -> 连上游
                                   <- 响应脱敏 <-
```

- **存**:复用 `secretenv` 的加密格式(`agent-seal-ecies-v1`,本就是 名字→值 的 map)。
  attestor 存密文 + 每个密钥的白名单(域名不是秘密);写入 owner 签名 + 比较并交换,
  同 settings。
- **下发**:`/provision` 响应在 `encrypted_settings` 旁带上加密密钥,每次开机/恢复都发。
- **用**:sealed 开一个仅 127.0.0.1 的出口代理;adapter 把它的地址交给框架。agent 把
  对外调用发给它。

## 4. 两种用法(都看不到真值)

- **agent 调工具**(第一版):agent 把请求发给 loopback 代理,头/字段里写
  `{{secret:NAME}}` 替身。curl 和任意 HTTP 库改一下 base 即可。
- **框架自用**(推理 key,以后的 bot token;第二步):把框架的上游地址指向 loopback
  代理、key 字段填替身。框架照常发,sealed 在出口换,于是推理 key 不再进框架进程
  (hermes 不再把它写进 `config.yaml`)。

## 5. 替换机制(显式代理;不冒充、不发证书)

- **显式代理(仅 https)**:agent/框架发给 `http://127.0.0.1:<port>/https/api.stripe.com/...`,
  头里带 `{{secret:STRIPE}}`;`http` scheme 被拒(v1),真值绝不走明文(v1 目标都是
  https)。目标域名在 URL 里,代理直读——**不解 TLS、不发证书**——换上真值,由代理
  自己去连真网站、回传响应。
  - 为什么够用:agent 没有真值,不走代理那次调用就用不了密钥(发出去是替身),功能
    失效但不泄露。"用密钥 ⇒ 必走代理"成立,不靠网络层强制。
  - 为什么不冒充(MITM):CONNECT/MITM 会让请求头 Host 与实际拨号目标分离,**破坏按
    密钥的白名单绑定**(§2.3/4,整个控制的根)。Fly Tokenizer 正因此拒绝 CONNECT。
    显式代理目标明确。
- **透明拦截(本方案不做)**:仅当负载必须零改动(照常发 `https://` 被拦)时才需要,
  代价是装 CA 证书 + 防 Host 分离。强制所有出站走代理属于网络层,sealed 做不到——留给
  sandbox 层(§8)。

## 6. 生命周期

- **reset(重建容器)**:密钥在 attestor,重建后重新下发,无需重输。
- **settings 推送 / 框架重启**:密钥在 sealed 内存,随进程重启重新下发;替换在 sealed
  做,改密钥不必重启框架。
- **转让**:attestor 的 `on_transfer` 目前不碰密钥——新增一步,转让时清空密钥(与
  settings 保留不同),叠加 §2.6 的 owner 校验。

## 7. CLI / SDK

- `secret set NAME --hosts a.com,b.com`(值星号输入;可识别的 key 前缀建议 hosts 让其
  回车确认;识别不出则手输;无 hosts 拒绝)。
- `secret ls` / `secret rm NAME`。
- SDK 方法类比 settings/secretEnv:加密给 agentSeal + owner 签名推送。

## 8. 刻意不做 / 留给 sandbox 层

- **强制所有出站走代理**,以及**通用出站白名单**(agent 到底能连哪些网,与密钥无关):
  需网络层强制,sealed 做不到(agent 能直连)。留给 sandbox 层(runner 侧);见
  0g-sandbox#137。
- sandbox 层终局:tapp 已有 **RA-TLS**(安全下发)+ **FDE**(加密存盘),传输/存储两个
  前提都省;同样用显式代理则证书也省,**只剩一个前提**——内层 agent 容器去特权(runner
  的特权是 DinD 必需,留着)。
- **签名类认证**(AWS SigV4、webhook HMAC):不能简单替换,第一版不支持;后续在代理里
  代算(Fly Tokenizer 的做法)。
- **非 HTTP 凭证**(数据库密码等):出口替换覆盖不到。

- **`/services` 端口守卫是尽力而为**(评审 #171 F5):它拦注册出口代理端口,
  但 agent 知道 `$SEAL_SECRET_PROXY`,可自建 loopback 转发器绕过。值仍不可见
  (脱敏 + 按密钥白名单),拦不住的是 agent 再导出**使用**权;彻底靠网络层
  (0g-sandbox#137)。

## 9. 参考

- Deno Sandbox:`secrets:{KEY:{hosts,value}}`,沙箱内见占位符、出口按 host 换——与
  §2/§3 同构。
- Fly.io Tokenizer(开源 Go):加密给代理、`allowed_hosts`、客户端永不见明文;显式代理,
  非 MITM。
- Daytona 无此能力(只有基础设施自用的 `secret`);四家框架均无——故须由平台
  (sealed / sandbox)提供。
