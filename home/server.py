#!/usr/bin/env python3
"""Toolbox 首页管理服务 — 整合部署入口。

单端口 (:5000) 承载所有子模块:
- 各子模块通过 DispatcherMiddleware 挂载到 /<module_id>/ 子路径
- 子模块模板通过 config['URL_PREFIX'] 获取前缀, 适配单端口

功能:
- 扫描 module.json 自动发现并挂载模块
- 首页卡片展示 (标题 + 一句话介绍 + 版本号 + 更新角标)
- 版本检测: 拉取 GitHub raw module.json 对比语义化版本
- 远程新模块发现: 调用 Contents API 检测远程有而本地无的模块目录
"""

import os
import sys
import json
import time
import importlib.util
import urllib.request
import urllib.error
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

app = Flask(__name__)
app.config['URL_PREFIX'] = ''

PORT = int(os.environ.get('TOOLBOX_PORT', '5001'))
ROOT = Path(__file__).resolve().parent.parent  # toolbox/
GITHUB_REPO = os.environ.get('TOOLBOX_REPO', 'yingshu0218/toolbox')
GITHUB_BRANCH = os.environ.get('TOOLBOX_BRANCH', 'main')

_remote_cache = {}  # key -> (timestamp, data)
CACHE_TTL = 300  # 5 分钟


# ── 模块扫描与加载 ───────────────────────────────────────────────

def scan_modules():
    """扫描根目录下所有含 module.json + server.py 的子目录。"""
    modules = []
    skip = {'home', '__pycache__', 'node_modules', 'venv', '.git'}
    for d in sorted(ROOT.iterdir()):
        if not d.is_dir() or d.name.startswith('.') or d.name in skip:
            continue
        mf = d / 'module.json'
        sf = d / module_entry(d)
        if not mf.exists() or not sf.exists():
            continue
        try:
            info = json.loads(mf.read_text(encoding='utf-8'))
        except Exception:
            continue
        if not info.get('id'):
            continue
        info['_dir'] = d.name
        info['_path'] = str(d)
        modules.append(info)
    return modules


def module_entry(module_dir):
    """读取 module.json 的 entry 字段, 默认 server.py。"""
    mf = module_dir / 'module.json'
    if mf.exists():
        try:
            return json.loads(mf.read_text(encoding='utf-8')).get('entry', 'server.py')
        except Exception:
            pass
    return 'server.py'


def load_subapp(module_info):
    """动态加载子模块的 Flask app 并设置 URL_PREFIX。"""
    module_dir = Path(module_info['_path'])
    entry = module_info.get('entry', 'server.py')
    mod_path = module_dir / entry
    mod_name = f"toolbox_{module_info['id'].replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(mod_name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # 注册到 sys.modules, 让 Flask 正确推断 root_path
    sys.path.insert(0, str(module_dir))
    try:
        spec.loader.exec_module(mod)
    finally:
        if str(module_dir) in sys.path:
            sys.path.remove(str(module_dir))
    sub_app = getattr(mod, 'app', None)
    if sub_app is None:
        return None
    prefix = f"/{module_info['id']}"
    sub_app.config['URL_PREFIX'] = prefix
    return sub_app, prefix


# 启动时扫描并挂载
modules = scan_modules()
_mounted = {}
for m in modules:
    m['_mounted'] = False
    try:
        result = load_subapp(m)
        if result:
            sub_app, prefix = result
            _mounted[prefix] = sub_app
            m['_mounted'] = True
            m['_prefix'] = prefix
    except Exception as e:
        m['_error'] = str(e)


# ── 版本检测 ────────────────────────────────────────────────────

def parse_version(v):
    try:
        return tuple(int(x) for x in str(v).split('.')[:3])
    except Exception:
        return (0,)


def fetch_remote_json(path):
    """从 GitHub raw 拉取 JSON 文件。"""
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{path}"
    req = urllib.request.Request(url, headers={'User-Agent': 'toolbox-home'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))


def fetch_github_root_dirs():
    """调用 GitHub Contents API 获取仓库根目录的目录列表。"""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/?ref={GITHUB_BRANCH}"
    req = urllib.request.Request(url, headers={
        'User-Agent': 'toolbox-home',
        'Accept': 'application/vnd.github+json',
    })
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    return [item['name'] for item in data if item.get('type') == 'dir']


def get_cached(key, fetcher):
    now = time.time()
    if key in _remote_cache:
        ts, data = _remote_cache[key]
        if now - ts < CACHE_TTL:
            return data
    try:
        data = fetcher()
        _remote_cache[key] = (now, data)
        return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'error': 'not_found'}
        if key in _remote_cache:
            return _remote_cache[key][1]
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        if key in _remote_cache:
            return _remote_cache[key][1]
        return {'error': str(e)}


# ── 路由 ────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', modules=modules)


@app.route('/api/modules')
def api_modules():
    """返回本地模块列表 (含挂载状态)。"""
    result = []
    for m in modules:
        d = {k: v for k, v in m.items() if not k.startswith('_')}
        d['url'] = f"/{m['id']}/"
        d['mounted'] = m.get('_mounted', False)
        if not d['mounted']:
            d['error'] = m.get('_error', '未知错误')
        result.append(d)
    return jsonify({'modules': result})


@app.route('/api/check-updates')
def api_check_updates():
    """对比本地与远程版本号。?force=1 跳过缓存。"""
    force = request.args.get('force') == '1'
    results = []
    for m in modules:
        local_ver = m.get('version', '0.0.0')
        cache_key = f"remote_ver_{m['id']}"
        if force:
            _remote_cache.pop(cache_key, None)

        def make_fetcher(mid):
            def fetcher():
                return fetch_remote_json(f"{mid}/module.json")
            return fetcher

        remote = get_cached(cache_key, make_fetcher(m['id']))
        remote_ver = None
        error = None
        if isinstance(remote, dict):
            if 'error' in remote:
                error = remote['error']
            else:
                remote_ver = remote.get('version')
        has_update = bool(remote_ver) and parse_version(remote_ver) > parse_version(local_ver)
        results.append({
            'id': m['id'],
            'name': m.get('name', m['id']),
            'local_version': local_ver,
            'remote_version': remote_ver,
            'has_update': has_update,
            'error': error,
        })
    return jsonify({'modules': results, 'checked_at': time.time()})


@app.route('/api/check-remote')
def api_check_remote():
    """检测远程仓库有而本地无的模块目录。?force=1 跳过缓存。"""
    force = request.args.get('force') == '1'
    local_ids = {m['id'] for m in modules}
    if force:
        _remote_cache.pop('remote_dirs', None)

    def fetcher():
        return fetch_github_root_dirs()

    dirs = get_cached('remote_dirs', fetcher)
    if isinstance(dirs, dict) and 'error' in dirs:
        return jsonify(dirs)
    skip = {'home', '.git', '.github', '.workbuddy', 'node_modules', '__pycache__'}
    remote_only = [d for d in dirs if d not in local_ids
                   and d not in skip and not d.startswith('.')]
    return jsonify({
        'remote_dirs': remote_only,
        'local_ids': sorted(local_ids),
        'checked_at': time.time(),
    })


# ── WSGI 挂载 ───────────────────────────────────────────────────

mounts = dict(_mounted)
if mounts:
    application = DispatcherMiddleware(app, mounts)
else:
    application = app.wsgi_app


if __name__ == '__main__':
    print(f'\n🏠 Toolbox 首页 → http://localhost:{PORT}')
    for m in modules:
        status = '✓' if m.get('_mounted') else '✗'
        print(f'   {status} {m["id"]:<16} v{m.get("version", "?"):<8} → /{m["id"]}/')
    if not modules:
        print('   (未发现任何模块)')
    print()
    run_simple('127.0.0.1', PORT, application, use_reloader=False, use_debugger=False)
