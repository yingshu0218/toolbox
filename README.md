# Toolbox

个人工具箱集合 — 每个工具可独立部署，也可通过首页服务整合部署。

## 工具列表

| 工具 | 目录 | 说明 |
|------|------|------|
| **home** | [home/](./home/) | 首页管理服务 — 模块发现 / 版本检测 / 整合入口 |
| net-tracker | [net-tracker/](./net-tracker/) | 网络链路检测工具 — 拓扑可视化 + 跳转路径表格 + 实时检测进度 |
| net-quality | [net-quality/](./net-quality/) | 网络质量检测工具 — 一键全面体检 + A/B/C/D 量化评分 + 延迟矩阵 |
| doc-convert | [doc-convert/](./doc-convert/) | 文档格式转换工具 — 基于 pandoc，支持 md/docx/html/epub/pdf 等 12 种格式互转，拖拽上传 + SSE 进度 |
| epub-convert | [epub-convert/](./epub-convert/) | EPUB 电子书工具 — 格式转换 / 元数据提取 / 图片压缩 / Git 推送 |

## 技术栈

所有工具统一使用：
- **Python Flask** SSR + SSE 实时进度流
- **暗色 GitHub 主题** 设计语言（`#0d1117` / `#161b22`）
- 拖拽上传 + 卡片式文件队列 + 进度遮罩面板
- 单文件 `server.py` + `templates/index.html`

## 安装

### macOS (Homebrew)

```bash
brew tap yingshu0218/toolbox
brew install toolbox
toolbox          # 启动 → 自动打开浏览器 http://localhost:9053
```

### Windows (Scoop)

```powershell
scoop bucket add toolbox https://github.com/yingshu0218/scoop-toolbox
scoop install toolbox
toolbox          # 启动 → 自动打开浏览器
```

依赖说明：pandoc（doc/epub 转换必需，brew/scoop 会自动安装）、git（epub 推送，系统自带或 `scoop install git`）、LaTeX（PDF 输出可选）。

### 源码部署

clone 仓库后 `./start-all.sh` 启动，详见下方「整合部署」。

## 整合部署

首页服务 `home/` 作为整合入口，单端口（`:9053`，避开 macOS AirPlay 占用的 5000）承载所有子模块：

```bash
./start-all.sh
# 访问 http://localhost:9053
```

home 启动时自动扫描仓库中含 `module.json` 的子目录，通过 `DispatcherMiddleware` 挂载到 `/<模块id>/` 子路径。新增模块只需创建含 `module.json` 的目录，重启即自动识别。

各子模块仍可独立部署：

```bash
cd doc-convert && python server.py   # http://localhost:5100
```

### module.json 规范

每个子模块根目录放一个 `module.json`：

```json
{
  "id": "doc-convert",
  "name": "文档格式转换",
  "description": "基于 pandoc 的 12 种格式互转",
  "version": "1.0.0",
  "category": "文档工具",
  "port": 5100,
  "entry": "server.py"
}
```

| 字段 | 说明 |
|------|------|
| id | 唯一标识，用作挂载路径和更新对比 |
| name | 首页卡片标题 |
| description | 卡片一句话介绍 |
| version | 语义化版本（x.y.z），更新检测依据 |
| category | 分类（网络工具 / 文档工具等） |
| port | 独立部署端口 |
| entry | 入口文件 |

### 版本检测

home 服务提供两项远程检测能力（基于 GitHub 仓库）：

- **版本对比**：拉取 `raw.githubusercontent.com` 上各模块的 `module.json`，与本地版本号比较，有更新时卡片显示橙色角标。
- **新模块发现**：调用 GitHub Contents API 获取仓库根目录列表，远程有而本地无的模块目录会在首页顶部提示。

检测结果缓存 5 分钟，可点击「检测更新」按钮强制刷新。

## 开发说明

本仓库中的工具均使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手辅助开发。
