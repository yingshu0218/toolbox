# Toolbox

个人工具箱集合 — 每个工具可独立部署，也可整合部署。

## 工具列表

| 工具 | 目录 | 说明 |
|------|------|------|
| net-tracker | [net-tracker/](./net-tracker/) | 网络链路检测工具 — 拓扑可视化 + 跳转路径表格 + 实时检测进度 |
| doc-convert | [doc-convert/](./doc-convert/) | 文档格式转换工具 — 基于 pandoc，支持 md/docx/html/epub/pdf 等 12 种格式互转，拖拽上传 + SSE 进度 |
| epub-convert | [epub-convert/](./epub-convert/) | EPUB 电子书工具 — 格式转换 / 元数据提取 / 图片压缩 / Git 推送 |

## 技术栈

所有工具统一使用：
- **Python Flask** SSR + SSE 实时进度流
- **暗色 GitHub 主题** 设计语言（`#0d1117` / `#161b22`）
- 拖拽上传 + 卡片式文件队列 + 进度遮罩面板
- 单文件 `server.py` + `templates/index.html`

## 整合部署

各工具位于独立子目录，互不依赖。整合部署时可将多个工具挂载到同一域名下的不同路径，或通过反向代理分发。

## 开发说明

本仓库中的工具均使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手辅助开发。
