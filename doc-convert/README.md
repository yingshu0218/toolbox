# doc-convert

文档格式转换工具 — 基于 pandoc 的轻量本地转换服务。

> 本工具使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手开发完成。

## 功能

- **12 种格式互转**：md / html / docx / epub / pdf / latex / rtf / odt / txt / org / rst / json
- **拖拽上传**：多文件批量转换，卡片式队列
- **SSE 实时进度**：转换进度流式推送
- **跨平台环境检测**：macOS / Windows / Linux 自动检测 pandoc + LaTeX，附安装提示
- **PDF 中文支持**：按平台选用中文字体（PingFang SC / Microsoft YaHei / Noto Sans CJK SC）

## 部署

```bash
# 整合部署（推荐）：从仓库根目录 ./start-all.sh，访问 http://localhost:5001/doc-convert/

# 独立部署
cd doc-convert
pip install flask
python server.py
# 访问 http://localhost:5100
```

依赖：pandoc（必需）、LaTeX（仅 PDF 输出需要）。

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Python 3 / Flask (SSR + SSE) |
| 转换引擎 | pandoc 3.x |
| PDF 引擎 | xelatex / pdflatex / lualatex |
| 前端 | HTML / CSS / JavaScript 原生 |
