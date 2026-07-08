# net-quality

本机网络质量全面检测工具 — 一键体检，量化评分。

> 本工具使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手开发完成。

## 功能

- **综合评分**：A/B/C/D 四级评分，加权计算
- **关键指标仪表盘**：平均延迟、丢包率、下载速率、DNS 延迟四象限
- **延迟矩阵**：多目标 ping 测试 + CSS 柱状图可视化
- **连通性检测**：5 个国内外站点可达性 + 连接耗时
- **DNS 性能**：5 个域名的解析延迟对比
- **丢包率测试**：50 次 ping 统计丢包率 + 抖动
- **带宽估算**：从 CDN 下载 10MB 文件测速
- **IPv4/IPv6 双栈检测**：公网出口 IP + 双栈支持状态

## 评分体系

| 维度 | 权重 | 满分条件 | 零分条件 |
|------|------|---------|---------|
| 连通性 | 20% | 5/5 站点可达 | 0 站点可达 |
| 延迟 | 25% | 平均 ≤100ms | 平均 ≥500ms |
| 丢包率 | 20% | 0% | ≥5% |
| DNS 性能 | 15% | 平均 ≤50ms | 平均 ≥300ms |
| 带宽 | 15% | ≥100Mbps | ≤10Mbps |
| 双栈 | 5% | IPv4+IPv6 双栈可用 | 无公网 |

**等级**：A(≥90) B(≥75) C(≥60) D(<60)

## 单独部署

```bash
cd toolbox/net-quality
python3 -m venv venv
source venv/bin/activate
pip install flask
python server.py
# 访问 http://localhost:5098
```

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Python 3 / Flask (SSR + SSE) |
| 前端 | HTML / CSS / JavaScript 原生 |
| 可视化 | CSS 柱状图 |
| 系统命令 | ifconfig, ping, curl, dig, networksetup |
