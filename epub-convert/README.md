# epub-convert

EPUB 电子书工具 — 格式转换 / 元数据提取 / 图片压缩 / Git 推送。

> 本工具使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手开发完成。

## 功能

- **格式转换**：epub → md / html / docx / txt / pdf / latex / rtf / epub（基于 pandoc，SSE 进度流）
- **元数据提取**：纯 stdlib 解析 EPUB 内 OPF（zipfile + xml.etree），提取标题、作者、ISBN、出版社等
- **元数据导出**：一键生成结构化 Markdown 文件
- **图片压缩**：Pillow 重压内部图片，多轮迭代压缩到 50MB 目标
- **推送 Git**：支持 GitHub / Gitea（HTTPS + Token），配置持久化 localStorage

## 部署

```bash
# 整合部署（推荐）：从仓库根目录 ./start-all.sh，访问 http://localhost:5001/epub-convert/

# 独立部署
cd epub-convert
pip install flask pillow
python server.py
# 访问 http://localhost:5200
```

依赖：pandoc（转换）、Pillow（压缩）、git（推送）。

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Python 3 / Flask (SSR + SSE) |
| 转换引擎 | pandoc |
| 图片压缩 | Pillow |
| EPUB 解析 | stdlib (zipfile + xml.etree) |
| 前端 | HTML / CSS / JavaScript 原生 |
