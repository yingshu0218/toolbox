#!/usr/bin/env bash
# Toolbox 一键启动 — 整合部署 (单端口 :5000 承载所有模块)
set -e
cd "$(dirname "$0")"

PY=/Users/infinity/.workbuddy/binaries/python/envs/default/bin/python3

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Toolbox 整合部署启动"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exec "$PY" home/server.py
