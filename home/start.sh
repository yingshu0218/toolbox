#!/usr/bin/env bash
# Toolbox 首页服务启动脚本 (整合部署入口)
set -e
cd "$(dirname "$0")"

PY=/Users/infinity/.workbuddy/binaries/python/envs/default/bin/python3

echo "🏠 Toolbox 首页服务启动中..."
exec "$PY" server.py
