#!/usr/bin/env python3
"""Toolbox 首页管理服务 — 整合部署入口。

单端口承载所有子模块:
- 各子模块通过 DispatcherMiddleware 挂载到 /<module_id>/ 子路径
- 子模块模板通过 config['URL_PREFIX'] 获取前缀, 适配单端口

功能:
- 扫描 module.json 自动发现并挂载模块
- 首页卡片展示 (标题 + 一句话介绍 + 版本号 + 更新角标)
- 版本检测: 拉取远程 module.json 对比语义化版本 (支持 github/gitee/gitea)
- 远程新模块发现: 调用 Contents API 检测远程有而本地无的模块目录
- 全局导航栏: /api/navbar.js 子模块页面注入左上角导航
- 设置: /api/settings 切换 git 仓库源
"""

import os
import sys
import json
import time
import importlib.util
import urllib.request
import urllib.error
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, Response
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

app = Flask(__name__)
app.config['URL_PREFIX'] = ''

PORT = int(os.environ.get('TOOLBOX_PORT', '9053'))
ROOT = Path(__file__).resolve().parent.parent  # toolbox/
GITHUB_REPO = os.environ.get('TOOLBOX_REPO', 'yingshu0218/toolbox')
GITHUB_BRANCH = os.environ.get('TOOLBOX_BRANCH', 'main')

_remote_cache = {}  # key -> (timestamp, data)
CACHE_TTL = 300  # 5 分钟

SETTINGS_FILE = ROOT / 'toolbox-settings.json'
DEFAULT_SETTINGS = {
    'repo_type': 'github',
    'repo': GITHUB_REPO,
    'branch': GITHUB_BRANCH,
    'gitea_base': '',
}


def load_settings():
    if SETTINGS_FILE.exists():
        try:
            s = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
            for k, v in DEFAULT_SETTINGS.items():
                s.setdefault(k, v)
            return s
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def save_settings(s):
    SETTINGS_FILE.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding='utf-8')


def get_repo_urls():
    """根据设置返回 raw/api URL 基础。"""
    s = load_settings()
    rtype = s.get('repo_type', 'github')
    repo = s.get('repo', GITHUB_REPO)
    branch = s.get('branch', GITHUB_BRANCH)
    if rtype == 'gitee':
        return {'raw': f'https://gitee.com/{repo}/raw/{branch}',
                'api': f'https://gitee.com/api/v5/repos/{repo}/contents',
                'branch': branch}
    if rtype == 'gitea':
        base = s.get('gitea_base', '').rstrip('/')
        return {'raw': f'{base}/{repo}/raw/branch/{branch}',
                'api': f'{base}/api/v1/repos/{repo}/contents',
                'branch': branch}
    return {'raw': f'https://raw.githubusercontent.com/{repo}/{branch}',
            'api': f'https://api.github.com/repos/{repo}/contents',
            'branch': branch}


# ── 模块扫描与加载 ───────────────────────────────────────────────

def scan_modules():
    """扫描根目录下所有含 module.json + server.py 的子目录。"""
    modules = []
    skip = {'home', '__pycache__', 'node_modules', 'venv', '.git', 'site-packages'}
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
    mf = module_dir / 'module.json'
    if mf.exists():
        try:
            return json.loads(mf.read_text(encoding='utf-8')).get('entry', 'server.py')
        except Exception:
            pass
    return 'server.py'


def load_subapp(module_info):
    module_dir = Path(module_info['_path'])
    entry = module_info.get('entry', 'server.py')
    mod_path = module_dir / entry
    mod_name = f"toolbox_{module_info['id'].replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(mod_name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
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
    urls = get_repo_urls()
    url = f"{urls['raw']}/{path}"
    req = urllib.request.Request(url, headers={'User-Agent': 'toolbox-home'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))


def fetch_remote_root_dirs():
    urls = get_repo_urls()
    url = f"{urls['api']}/?ref={urls['branch']}"
    req = urllib.request.Request(url, headers={
        'User-Agent': 'toolbox-home',
        'Accept': 'application/vnd.github+json, application/json',
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
    force = request.args.get('force') == '1'
    local_ids = {m['id'] for m in modules}
    if force:
        _remote_cache.pop('remote_dirs', None)

    def fetcher():
        return fetch_remote_root_dirs()

    dirs = get_cached('remote_dirs', fetcher)
    if isinstance(dirs, dict) and 'error' in dirs:
        return jsonify(dirs)
    # 黑名单快速过滤（已知非模块目录）
    skip = {'home', '.git', '.github', '.workbuddy', 'node_modules',
            '__pycache__', 'site-packages', 'bin', 'assets', 'docs', 'scripts', 'tests'}
    candidates = [d for d in dirs if d not in local_ids
                  and d not in skip and not d.startswith('.')]
    # 校验候选目录是否真为模块（含 module.json），避免把 bin/assets 等非模块目录误报
    remote_only = []
    for d in candidates:
        ck = f"remote_mod_{d}"
        if force:
            _remote_cache.pop(ck, None)
        r = get_cached(ck, lambda d=d: fetch_remote_json(f"{d}/module.json"))
        if isinstance(r, dict) and 'error' not in r and r.get('id'):
            remote_only.append(d)
    return jsonify({
        'remote_dirs': remote_only,
        'local_ids': sorted(local_ids),
        'checked_at': time.time(),
    })


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """GET 返回当前设置; POST 更新设置 (repo_type/repo/branch/gitea_base)。"""
    if request.method == 'POST':
        data = request.get_json(force=True)
        s = load_settings()
        for k in ('repo_type', 'repo', 'branch', 'gitea_base'):
            if k in data:
                s[k] = data[k]
        save_settings(s)
        _remote_cache.clear()
        return jsonify({'ok': True, 'settings': s})
    return jsonify(load_settings())


@app.route('/api/navbar.js')
def api_navbar_js():
    """返回导航栏 JS, 子模块页面注入左上角导航 (返回首页 + 模块切换下拉)。"""
    return Response(NAVBAR_JS, mimetype='application/javascript')


NAVBAR_JS = r"""(function(){
  if(document.getElementById('tb-nav'))return;
  var st=document.createElement('style');
  st.textContent='#tb-nav{position:fixed;left:20px;top:66px;z-index:99999;font-family:-apple-system,BlinkMacSystemFont,sans-serif}#tb-nav .tb-btn{display:inline-flex;align-items:center;gap:6px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:9px 14px;color:#c9d1d9;text-decoration:none;font-size:13px;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.3);transition:border-color .15s,color .15s}#tb-nav .tb-btn:hover{border-color:#58a6ff;color:#58a6ff}#tb-nav .tb-menu{display:none;position:absolute;top:calc(100% + 6px);left:0;min-width:200px;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,.4)}#tb-nav.open .tb-menu{display:block}#tb-nav .tb-item{display:flex;align-items:center;gap:8px;padding:10px 14px;font-size:13px;color:#c9d1d9;text-decoration:none;cursor:pointer}#tb-nav .tb-item:hover{background:rgba(88,166,255,.1);color:#58a6ff}#tb-nav .tb-st{margin-left:auto;font-size:11px}#tb-nav .tb-st.on{color:#3fb950}#tb-nav .tb-st.off{color:#f85149}#tb-nav .tb-div{height:1px;background:#30363d}';
  document.head.appendChild(st);
  var nav=document.createElement('div');
  nav.id='tb-nav';
  nav.innerHTML='<a class="tb-btn" href="/"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M7.78 1.22a.75.75 0 0 0-1.06 0L1.22 6.72a.75.75 0 0 0 0 1.06l5.5 5.5a.75.75 0 0 0 1.06-1.06L3.06 8H12.5A1.5 1.5 0 0 1 14 9.5v3.75a.75.75 0 0 0 1.5 0V9.5a3 3 0 0 0-3-3H3.06l4.72-4.72a.75.75 0 0 0 0-1.06z"/></svg>首页</a><button class="tb-btn" id="tb-sw">模块切换 <span style="font-size:10px">▾</span></button><div class="tb-menu" id="tb-menu"></div>';
  document.body.appendChild(nav);
  fetch('/api/modules').then(function(r){return r.json()}).then(function(d){
    var h='<a class="tb-item" href="/"><span style="width:8px;height:8px;border-radius:50%;background:#58a6ff"></span>首页</a><div class="tb-div"></div>';
    d.modules.forEach(function(m){
      var c={'网络工具':'#58a6ff','文档工具':'#3fb950','系统工具':'#f0883e','开发工具':'#bc8cff'}[m.category]||'#bc8cff';
      h+='<a class="tb-item" href="'+m.url+'"><span style="width:8px;height:8px;border-radius:50%;background:'+c+'"></span>'+m.name+'<span class="tb-st '+(m.mounted?'on':'off')+'">'+(m.mounted?'已安装':'未安装')+'</span></a>';
    });
    document.getElementById('tb-menu').innerHTML=h;
  }).catch(function(){});
  document.getElementById('tb-sw').onclick=function(e){e.stopPropagation();nav.classList.toggle('open')};
  document.addEventListener('click',function(e){if(!e.target.closest('#tb-nav'))nav.classList.remove('open')});
})();
"""


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
