# dnsguard — 企业出口网关加密 DNS 识别与引导

在出口网关上识别 DoH / DoH3 / DoT / DoQ 等加密域名解析流量,阻断绕过内部管控的解析,
并将其引导回内部解析服务,恢复恶意域名拦截和上网审计能力。

## 原理总览

| 通道 | 特征 | 处置 |
|---|---|---|
| 明文 DNS (53) | 非内部解析器的 53 端口流量 | nftables DNAT 回内部解析器(引导,不阻断) |
| DoT (TCP 853) | 独立端口 | 直接 drop,客户端自动回退系统 DNS |
| DoQ (UDP 853) | 独立端口 | 同上 |
| DoH (TCP 443) | 与 HTTPS 同端口同协议 | NFQUEUE 抓连接初始报文 → 解析 TLS ClientHello SNI → 匹配 DoH 域名库 → drop + 动态封禁目标 IP |
| DoH3 (UDP 443) | QUIC | 被动解密 QUIC Initial(RFC 9001 密钥由 DCID 公开导出)→ 提取 SNI → 同上 |
| ECH / 无 SNI | SNI 不可见 | 已知 DoH 服务器 IP 集合兜底(清单自动刷新) |

配套机制:

- **清单自动刷新**:定时拉取 dibdot / curl 等公开 DoH 服务器清单,用内部解析器解析成 IP,
  同步进 nftables set,应对"公共解析地址经常变化"。
- **业务例外**:按源网段 + 目标域名/IP 白名单放行强制使用加密解析的业务软件,全程审计日志。
- **canary 检测**:统计每台终端的明文 DNS 使用,发现"零明文 DNS 却正常上网"的终端(可能
  是未识别的 DoH、VPN 或自带解析的恶意程序)。
- **引导回退**:阻断加密解析后,浏览器/系统会回退到系统 DNS(即内部解析器);同时在内部
  解析器上配置 canary 域名(见下),让 Firefox 等企业受管浏览器自动关闭 DoH。

## 部署

```bash
# 1. 编译(Linux 网关)
GOOS=linux go build -o dnsguard ./cmd/dnsguard

# 2. 加载 nftables 规则
nft -f deploy/dnsguard.nft

# 3. 配置
cp configs/dnsguard.yaml /etc/dnsguard/dnsguard.yaml
#   编辑: internal_resolvers、exceptions、log_only

# 4. 运行(需要 CAP_NET_ADMIN)
./dnsguard -config /etc/dnsguard/dnsguard.yaml
```

**上线建议:先 `log_only: true` 运行 1-2 周**,从审计日志确认命中都是真实 DoH 且例外
清单完整后,再改为 `false` 实际阻断。

## 内部解析器配套(引导回内部解析的关键)

1. **Mozilla canary 域名**:对 `use-application-dns.net` 返回 NXDOMAIN,Firefox 会认为
   网络要求关闭 DoH。unbound 示例:
   ```
   local-zone: "use-application-dns.net" always_nxdomain
   ```
2. **禁止终端直连外部 53**:nft 规则已把外发 53 DNAT 回内部,无需终端配置。
3. **企业自己的 DoH 服务**(可选):在内部解析器上启用 DoH(如 dnsdist),把
   `dns.公司内部域` 加入浏览器企业策略,既满足应用加密解析需求又保留审计。

## 业务例外处理流程

部分业务软件硬编码公共 DoH,直接阻断会导致业务中断:

1. `log_only` 阶段从审计日志中发现这类流量(`AUDIT proto=tls src=... sni=cloudflare-dns.com`);
2. 确认业务归属后,在 `dnsguard.yaml` 的 `exceptions` 中加白(源网段 + 目标域名/IP);
3. 例外流量**仍然记录审计日志**(目标、SNI、时间),满足上网审计要求;
4. 长期方案:与厂商沟通改用企业 DoH 服务,或通过 MDM/组策略下发浏览器 DoH 配置。

## 性能与可用性

- NFQUEUE 只接收每个连接的前 ~3KB(`ct original bytes` 限制),SNI 检出后目标 IP 进入
  `blocked4` 集合,后续包由内核直接 drop,不再进用户态;
- nft 规则带 `queue bypass`:dnsguard 进程异常退出时报文自动放行,不影响业务连续性;
- 清单刷新失败时沿用旧清单,不会因为上游清单站不可用导致管控失效。

## 局限与说明

- **ECH (Encrypted Client Hello)**:SNI 被加密时只能依赖 IP 集合兜底;这也是清单自动
  刷新存在的意义。可在网关策略上直接拒绝 ECH 的公网回退(高级话题,需评估兼容性)。
- **非清单内私有 DoH 服务器**(如攻击者自建):SNI 不在清单中无法命中,依赖 canary
  检测发现异常终端后人工排查;可叠加流量特征检测(长连接、固定小包节奏)作为二期。
- **QUIC 版本**:支持 QUIC v1 (RFC 9000) 和 v2 (RFC 9369);新版本出现时需在
  `quicsni` 中补充对应 salt。
- 本工具用于企业自有网络的防御性管控,请确保有适当的内部告知与授权流程。

## 离线验证

```bash
# 用现网抓的 pcap 验证识别逻辑,不影响生产
./dnsguard -config dnsguard.yaml -pcap sample.pcap
```
