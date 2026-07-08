#!/usr/bin/env bash
# EPUB 电子书工具启动脚本
set -e
cd "$(dirname "$0")"

PY=/Users/infinity/.workbuddy/binaries/python/envs/default/bin/python3

if ! command -v pandoc &>/dev/null; then
  echo "⚠️  未检测到 pandoc，请先安装: brew install pandoc" >&2
fi

echo "📚 EPUB 电子书工具 → http://localhost:5200"
exec "$PY" server.py
