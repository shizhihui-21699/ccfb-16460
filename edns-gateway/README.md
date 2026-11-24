# edns-gateway — 企业出口加密 DNS 识别与导流网关

在企业出口网关上识别 **DoH / DoT / DoQ** 等加密域名解析流量，把绕过内部 DNS 的查询
引导回企业内部递归，使既有的恶意域名拦截与上网审计策略对加密解析同样生效。

## 为什么需要它

浏览器、App 和部分恶意程序越来越多地直接向公共解析服务发起加密 DNS 查询：

- 与普通网页访问**共用 443/853 等端口和 TLS/QUIC 协议**，传统基于端口/五元组的管控失效；
- 公共解析服务 **IP 地址经常变化**（任播、新节点、CDN 前置），静态 IP 黑名单不可维护；
- 部分业务软件**强制使用加密解析，直接阻断会导致业务中断**。

本系统的三个设计支点分别对应这三个难点。

## 架构

```
                        ┌─────────────────────────────────────────────┐
 内网主机  ─ 出口流量 ─▶│ capture (pcap 镜像 / NFQUEUE 在线)            │
                       │    ↓ 统一 flowtrack.Meta                      │
                        │ flowtrack  TCP 重组 / QUIC 包关联 / 行为聚合  │
                       │    ↓                                         │
                        │ protocol  TLS ClientHello / HTTP2 / QUIC     │
                       │    ↓ 明文特征（无需会话密钥）                  │
                        │ classify  信号加权评分 + 情报 + 白名单          │
                       │    ↓ verdict(observe/redirect/block)          │
                        │ action    NFQUEUE verdict / connmark          │
                        └───────────────┬─────────────────────────────┘
                                         │ tproxy 命中标记的流
                        ┌───────────────▼─────────────────────────────┐
                        │ dnsserver  DoH(RFC8484) / DoT(RFC7858) /     │
                        │            DoQ(RFC9250) 兼容前端 + 动态证书    │
                        │    ↓ 还原为明文 DNS wire                      │
                        │ resolver → 企业内部递归(53) → 既有拦截/审计    │
                        └─────────────────────────────────────────────┘
```

## 识别原理（不依赖端口，也不需要解密应用数据）

| 协议 | 决定性信号 | 辅助信号 |
|------|-----------|----------|
| DoT  | ClientHello `ALPN=dot` | SNI 命中解析器情报、TCP/853、JA4 |
| DoQ  | QUIC Initial 解密后 `ALPN=doq` | QUIC 无 `h3`、SNI 情报、JA4(q 前缀) |
| DoH  | HTTP/2 `:path=/dns-query` | SNI 情报、`ALPN=h2`、`application/dns-message` |
| 未知 | 行为模式：短连接反复握手、多 SNI、小 record | ECH、目的 IP 情报 |

1. **TLS ClientHello 明文解析**：SNI、ALPN、密码套件、扩展，输出 JA3/JA4 指纹，
   GREASE 值按 RFC 8701 过滤。
2. **QUIC Initial 解密（核心能力）**：QUIC Initial 的密钥由公开 salt + 客户端 DCID
   经 HKDF 派生（RFC 9001），任何中间设备都可还原出内层 ClientHello，**无需服务器
   私钥、不触碰 1-RTT 应用数据**。实现经 RFC 9001 附录 A.2 权威向量和 quic-go 真实
   客户端双重验证，支持大 ClientHello 跨数据包的 CRYPTO 流重组。
3. **HTTP/2 帧解析**：在能拿到明文的导流终止点或解密取证场景，直接坐实 `/dns-query`。
4. **多信号加权评分**：协议自声明（ALPN/path）权重最高，SNI 情报为稳定锚点，
   IP 情报仅辅助。三档阈值映射 observe / redirect / block。

### 应对"解析器地址常变"

- 判定主要依据 **SNI/ALPN/URI 等不随 IP 变化的协议特征**；
- 情报库分**域名（稳定锚点）**与 **IP/CIDR（辅助加权）**两类，IP 命中权重低；
- 外部 feed 支持 URL/本地文件定时热更新与本地缓存，重启不空窗。

### 应对"业务软件不能断"

- 动作分级：`observe`（只审计）、`redirect`（导流，不中断）、`block`；
- SNI 与 CIDR **白名单优先于一切判定**，强制加密解析的业务直接豁免；
- 导流而非重置连接，配合企业 CA 动态签发证书，客户端无感知。

## 目录结构

```
cmd/edns-gateway/     run / analyze / cert 三个子命令
internal/
  config/             YAML 配置、默认值、校验、原子热更新
  core/               共享类型与枚举
  protocol/           TLS / HTTP2 / QUIC 线协议解析、JA3/JA4、CRYPTO 重组
  intel/              内置解析器情报 + 外部 feed 热更新
  flowtrack/          流表、TCP 重组、QUIC 关联、行为聚合
  classify/           加权评分、阈值、白名单、动作映射
  capture/            pcap(跨平台) 与 NFQUEUE(Linux) 采集
  engine/             处理管线接线、nfqueue 同步判定入口
  dnsserver/          DoH/DoT/DoQ 兼容前端
  resolver/           到企业内部递归的明文转发（UDP/TCP 回退）
  pki/                企业 CA 加载与按 SNI 动态签发
  audit/              异步 JSON 审计日志与轮转
  metrics/            Prometheus 文本格式指标
deploy/               nftables 规则、systemd 单元
configs/              配置示例
```

## 快速开始

```bash
make build

# 1) 生成企业 CA（生产建议接入企业 PKI；CA 通过组策略/MDM 下发到终端信任库）
./bin/edns-gateway cert -out certs/

# 2) 离线分析 pcap（无需 root，便于调参与取证）
./bin/edns-gateway analyze -f trace.pcap -o events.jsonl

# 3) 在线守护（Linux 网关）
cp configs/config.example.yaml /etc/edns-gateway/config.yaml
# 配置 nftables（见 deploy/nftables.rules）与策略路由后：
./bin/edns-gateway run -c /etc/edns-gateway/config.yaml

# 热更新策略（不中断流量）
kill -HUP $(pidof edns-gateway)
```

## 部署要点

1. **采集模式**
   - 镜像口/虚拟化环境用 `pcap`，只能 observe，适合先做可见性盘点；
   - 物理网关用 `nfqueue`，队列配置了 `fail-open`，进程异常时内核放行，不会断网。
2. **导流三模式**
   - `tproxy`（推荐）：保留原始五元组透明接管，配合 connmark 与策略路由；
   - `nat`：DNAT 重定向，部署简单但 SNI 不匹配时依赖企业 CA；
   - `answer`：由内部 DNS 对解析器域名返回服务 IP 做引导，最温和。
3. **证书信任**：DoT/DoQ/DoH 动态叶子证书由企业 CA 签发，根 CA 必须下发到终端
   受信任根存储，否则客户端证书校验失败。
4. **策略一致性**：所有加密查询最终都转发给 `resolver.upstream`（内部递归），
   恶意域名拦截仍在原系统完成，本系统不复制一套拦截规则。

## 测试

```bash
make test       # 单元 + 端到端
make race       # 竞态检测
```

关键测试覆盖：

- RFC 9001 附录 A.2 权威 QUIC 报文解密向量；
- quic-go 真实客户端（含跨包 ClientHello 重组）；
- Go 标准库真实 TLS 1.2/1.3 ClientHello 解析；
- DoH/DoT/DoQ 三个前端的真实 DNS 查询往返；
- 分类评分、白名单豁免、普通 HTTPS 不误判；
- 内部递归转发与上游 NXDOMAIN 拦截透传。

## 安全与合规边界

- 只解析握手与头部中的**明文字段**，不解析也无法解析 1-RTT 加密应用数据；
- ECH（加密 ClientHello）启用时真实 SNI 不可见，系统退而依赖 IP/ALPN/行为信号，
  并在审计中明确标注 `ech_enabled`，不做臆断；
- CA 私钥应离线保管，网关上建议只持有中间 CA；叶子证书 24h 短期有效；
- 审计日志包含源/目的、SNI、ALPN、判定依据，请按企业数据合规要求限定访问权限。

## 已知限制

- 纯旁路 pcap 模式无法执行导流/阻断，只能 observe；
- IP 分片重组依赖部署侧（nftables/网卡 offload）；
- JA4 实现为适合内部聚类的简化口径，与官方工具的跨工具比对存在已知差异
  （签名算法段处理不同），代码注释已说明；
- DoQ 仅处理 Initial 阶段识别，握手后的连接复用不再重复解析（流表首包判定即缓存）。
