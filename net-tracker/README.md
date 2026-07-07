# net-tracker

网络链路检测工具 — 通过网页执行端到端的网络路径检测，可视化展示从本机到目标域名的完整链路拓扑。

> 本工具使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手开发完成。

## 功能概览

- **网络拓扑可视化**：SVG 动态渲染本机 → 网关 → DNS → CDN/WAF → 目标服务器的完整链路拓扑图
- **域名解析链路表**：合并展示 CNAME 链、A 记录、IP 归属（whois）、路由方式（直连/隧道）为一张表格
- **路由跳转列表**：重建逻辑跳转路径，标注每跳延迟、节点类型、连接状态（直连/代理/代理直连）
- **实时检测进度**：SSE 流式推送 8 步检测进度，弹出式卡片 + 完成后渐隐
- **分步详情卡片**：本机出口、DNS 配置、TLS 连接、代理隧道的可折叠详情

## 检测步骤

| 步骤 | 检测内容 | 使用命令 |
|------|---------|---------|
| 1 | 本机出口 / 默认路由 | `netstat`, `ifconfig` |
| 2 | DNS 配置 | `scutil --dns`, `dig` |
| 3 | 域名解析 | `dig +short` |
| 4 | IP 归属 (whois) | `whois` |
| 5 | 路由路径 | `route -n get` |
| 6 | TLS / HTTPS 连接 | `curl -svw` |
| 7 | 代理 & 隧道 | `scutil --proxy`, 环境变量, `ifconfig` |
| 8 | 跳转路径重建 | 逻辑路径 + `ping` 延迟 |

## 技术栈

| 层 | 技术 | 说明 |
|----|------|------|
| 后端 | Python 3 / Flask | SSR 渲染 + SSE 流式推送 |
| 前端 | HTML / CSS / JavaScript | 原生 JS，无框架依赖 |
| 可视化 | SVG | 动态生成拓扑图，贝塞尔曲线连线 |
| 模板引擎 | Jinja2 | Flask 内置模板引擎 |
| 网络检测 | macOS 系统命令 | netstat, ifconfig, scutil, dig, whois, route, curl, ping |

## 单独部署

### 环境要求

- macOS（依赖系统网络命令：`scutil`, `route`, `dig`, `whois` 等）
- Python 3.9+

### 步骤

```bash
# 1. 克隆仓库
git clone https://github.com/yingshu0218/toolbox.git
cd toolbox/net-tracker

# 2. 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 3. 安装依赖
pip install flask

# 4. 启动服务
python server.py

# 5. 打开浏览器访问
# http://localhost:5099
```

### Docker 部署（可选）

> 注意：由于工具依赖 macOS 系统命令（`scutil`, `route` 等），Docker 部署仅适用于 macOS 宿主机上的容器。

```bash
cd net-tracker
docker build -t net-tracker .
docker run -p 5099:5099 --host network=host net-tracker
```

## 目录结构

```
net-tracker/
├── server.py              # Flask 后端（检测逻辑 + SSE + 路由）
├── templates/
│   └── index.html         # 前端页面（拓扑图 + 表格 + 进度面板 + 分步卡片）
├── requirements.txt       # Python 依赖
└── README.md
```

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 空表单页面 |
| `/` | POST | 表单提交，SSR 返回检测结果 |
| `/api/health` | GET | 健康检查 |
| `/api/detect` | POST | JSON API，接收 `{"domain": "..."}` 返回检测结果 |
| `/api/detect/stream` | GET | SSE 流式检测，参数 `?domain=xxx` |

## 整合部署

本工具是 `toolbox` 工具箱中的一个独立模块，可单独部署，也可与其他工具整合部署在同一仓库中。各模块之间互不依赖，按需启动即可。

## 开发说明

本工具由 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手辅助开发，从需求分析、代码编写、调试到迭代优化全程通过 WorkBuddy 完成。
