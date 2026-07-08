#!/usr/bin/env python3
"""文档格式转换工具 — 基于 pandoc 的轻量本地转换服务。

架构: Flask SSR + SSE 实时进度，与 network-detect 同一设计语言。
- GET /            主页面
- GET /api/status  pandoc / LaTeX 检测
- POST /api/upload 文件上传（multipart），返回 file_id 列表
- GET /api/convert SSE 转换进度流（ids=a,b&to=docx）
- GET /api/download/<id>  下载结果
- GET /api/open/<id>      在 Finder 中显示
"""

import os
import sys
import json
import uuid
import shutil
import platform
import tempfile
import subprocess
from pathlib import Path
from flask import (
    Flask, request, jsonify, render_template,
    send_file, Response, stream_with_context,
)

app = Flask(__name__)

PORT = 5100
UPLOAD_DIR = Path(tempfile.gettempdir()) / "doc-convert-uploads"
OUTPUT_DIR = Path(tempfile.gettempdir()) / "doc-convert-output"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# 输入扩展名 -> pandoc 格式名
EXT_TO_FORMAT = {
    'md': 'markdown', 'markdown': 'markdown',
    'html': 'html', 'htm': 'html',
    'docx': 'docx', 'odt': 'odt', 'rtf': 'rtf',
    'epub': 'epub',
    'tex': 'latex', 'latex': 'latex',
    'org': 'org', 'rst': 'rst',
    'txt': 'plain', 'text': 'plain',
    'csv': 'csv', 'tsv': 'tsv',
    'json': 'json',
    'wiki': 'mediawiki', 'mediawiki': 'mediawiki',
}

# 输出格式: (pandoc格式, 扩展名, 显示名, 需要LaTeX)
OUTPUT_FORMATS = {
    'docx':  ('docx',     'docx', 'Word 文档',         False),
    'pdf':   ('pdf',      'pdf',  'PDF',               True),
    'html':  ('html',     'html', 'HTML 网页',         False),
    'md':    ('markdown', 'md',   'Markdown',          False),
    'epub':  ('epub',     'epub', 'EPUB 电子书',       False),
    'rtf':   ('rtf',      'rtf',  'RTF 富文本',        False),
    'latex': ('latex',    'tex',  'LaTeX',             False),
    'odt':   ('odt',      'odt',  'OpenDocument',      False),
    'txt':   ('plain',    'txt',  '纯文本',            False),
    'org':   ('org',      'org',  'Org',               False),
    'rst':   ('rst',      'rst',  'reStructuredText',  False),
    'json':  ('json',     'json', 'JSON',              False),
}


def detect_pandoc():
    path = shutil.which('pandoc')
    if not path:
        return None, None
    try:
        r = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=5)
        first = r.stdout.split('\n')[0] if r.stdout else ''
        ver = first.replace('pandoc', '').strip()
        return path, ver or 'unknown'
    except Exception:
        return path, 'unknown'


def detect_latex():
    for eng in ['xelatex', 'pdflatex', 'lualatex']:
        if shutil.which(eng):
            return eng
    return None


# 跨平台配置
PLATFORM_NAMES = {
    'darwin': 'macOS',
    'win32': 'Windows',
    'linux': 'Linux',
}

# 各平台安装提示: { platform: { dep: [(label, command), ...] } }
INSTALL_HINTS = {
    'darwin': {
        'pandoc': [
            ('Homebrew (推荐)', 'brew install pandoc'),
            ('MacPorts', 'sudo port install pandoc'),
            ('官网下载', 'https://pandoc.org/installing.html'),
        ],
        'latex': [
            ('Homebrew — MacTeX 完整版 (推荐)', 'brew install --cask mactex-no-gui'),
            ('Homebrew — BasicTeX 精简版', 'brew install basictex'),
            ('官网下载', 'https://www.tug.org/mactex/'),
        ],
    },
    'win32': {
        'pandoc': [
            ('winget (推荐)', 'winget install JohnMacFarlane.Pandoc'),
            ('Chocolatey', 'choco install pandoc'),
            ('Scoop', 'scoop install pandoc'),
            ('官网下载', 'https://pandoc.org/installing.html'),
        ],
        'latex': [
            ('winget — MiKTeX (推荐)', 'winget install MiKTeX.MiKTeX'),
            ('Chocolatey', 'choco install miktex'),
            ('官网下载 TeX Live', 'https://tug.org/texlive/'),
        ],
    },
    'linux': {
        'pandoc': [
            ('Debian/Ubuntu (推荐)', 'sudo apt install pandoc'),
            ('Fedora/RHEL', 'sudo dnf install pandoc'),
            ('Arch Linux', 'sudo pacman -S pandoc'),
            ('官网下载', 'https://pandoc.org/installing.html'),
        ],
        'latex': [
            ('Debian/Ubuntu (推荐)', 'sudo apt install texlive-xetex texlive-lang-chinese'),
            ('Fedora/RHEL', 'sudo dnf install texlive-xetex'),
            ('Arch Linux', 'sudo pacman -S texlive'),
        ],
    },
}

# PDF 中文引擎字体（按平台）
CJK_FONTS = {
    'darwin': 'PingFang SC',
    'win32': 'Microsoft YaHei',
    'linux': 'Noto Sans CJK SC',
}


def get_platform_key():
    """返回平台标识: darwin / win32 / linux"""
    return sys.platform if sys.platform in PLATFORM_NAMES else 'linux'


def get_install_hints(dep):
    """返回当前平台的安装提示列表"""
    return INSTALL_HINTS.get(get_platform_key(), {}).get(dep, [])


PANDOC_PATH, PANDOC_VERSION = detect_pandoc()
LATEX_ENGINE = detect_latex()


def get_format_from_ext(filename):
    ext = Path(filename).suffix.lower().lstrip('.')
    return EXT_TO_FORMAT.get(ext), ext


def fmt_size(n):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != 'B' else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@app.route('/')
def index():
    pf = get_platform_key()
    return render_template(
        'index.html',
        pandoc_path=PANDOC_PATH,
        pandoc_version=PANDOC_VERSION,
        latex_engine=LATEX_ENGINE,
        output_formats=OUTPUT_FORMATS,
        platform_key=pf,
        platform_name=PLATFORM_NAMES.get(pf, pf),
    )


@app.route('/api/status')
def api_status():
    return jsonify({
        'pandoc': {'path': PANDOC_PATH, 'version': PANDOC_VERSION, 'available': bool(PANDOC_PATH)},
        'latex': {'engine': LATEX_ENGINE, 'available': bool(LATEX_ENGINE)},
    })


@app.route('/api/env-check')
def api_env_check():
    """完整环境检测：平台、pandoc、LaTeX，含安装提示"""
    pf = get_platform_key()
    return jsonify({
        'platform': pf,
        'platform_name': PLATFORM_NAMES.get(pf, pf),
        'python_version': platform.python_version(),
        'pandoc': {
            'available': bool(PANDOC_PATH),
            'path': PANDOC_PATH,
            'version': PANDOC_VERSION,
            'install_hints': get_install_hints('pandoc'),
        },
        'latex': {
            'available': bool(LATEX_ENGINE),
            'engine': LATEX_ENGINE,
            'install_hints': get_install_hints('latex'),
        },
    })


@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'files' not in request.files:
        return jsonify({'error': '没有文件'}), 400
    files = request.files.getlist('files')
    results = []
    for f in files:
        if not f.filename:
            continue
        file_id = uuid.uuid4().hex[:12]
        # 安全文件名：只保留文件名部分，去掉路径
        safe_name = os.path.basename(f.filename)
        fmt, ext = get_format_from_ext(safe_name)
        saved = UPLOAD_DIR / f"{file_id}_{safe_name}"
        f.save(str(saved))
        results.append({
            'id': file_id,
            'name': safe_name,
            'size': saved.stat().st_size,
            'input_format': fmt,
            'input_ext': ext,
            'supported': fmt is not None,
        })
    return jsonify({'files': results})


@app.route('/api/convert')
def api_convert():
    """SSE 转换流。GET /api/convert?ids=a,b&to=docx"""
    ids = request.args.get('ids', '')
    to_format = request.args.get('to', '')
    file_ids = [x.strip() for x in ids.split(',') if x.strip()]

    def sse(event, data):
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    def generate():
        if not PANDOC_PATH:
            yield sse('fatal', {'message': 'pandoc 未安装'})
            return
        if to_format not in OUTPUT_FORMATS:
            yield sse('fatal', {'message': f'不支持的输出格式: {to_format}'})
            return

        pandoc_fmt, out_ext, out_name, need_latex = OUTPUT_FORMATS[to_format]
        if need_latex and not LATEX_ENGINE:
            yield sse('fatal', {'message': 'PDF 输出需要 LaTeX 引擎（xelatex/pdflatex），未检测到'})
            return

        total = len(file_ids)
        success = 0
        for i, fid in enumerate(file_ids):
            matched = list(UPLOAD_DIR.glob(f"{fid}_*"))
            if not matched:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': fid, 'message': '文件不存在'})
                continue
            src = matched[0]
            src_name = src.name[len(fid) + 1:]
            in_fmt, in_ext = get_format_from_ext(src_name)

            if not in_fmt:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': f'不支持的输入格式: .{in_ext}'})
                continue
            if in_fmt == pandoc_fmt and out_ext == in_ext:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': '输入输出格式相同'})
                continue

            out_stem = Path(src_name).stem
            out_name_file = f"{out_stem}.{out_ext}"
            result_id = uuid.uuid4().hex[:12]
            out_path = OUTPUT_DIR / f"{result_id}_{out_name_file}"

            yield sse('item', {'index': i, 'total': total, 'status': 'converting',
                               'file': src_name, 'from': in_fmt, 'to': pandoc_fmt,
                               'output': out_name_file})

            cmd = [PANDOC_PATH, str(src), '-f', in_fmt, '-t', pandoc_fmt, '-o', str(out_path)]
            if need_latex and LATEX_ENGINE:
                cmd.extend(['--pdf-engine', LATEX_ENGINE])
                if LATEX_ENGINE == 'xelatex':
                    font = CJK_FONTS.get(get_platform_key(), 'Noto Sans CJK SC')
                    cmd.extend(['-V', f'mainfont={font}',
                                '-V', f'CJKmainfont={font}'])

            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if r.returncode != 0:
                    err = (r.stderr or '').strip()[:500] or '未知错误'
                    yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                       'file': src_name, 'message': err})
                    if out_path.exists():
                        out_path.unlink()
                    continue
                success += 1
                yield sse('item', {'index': i, 'total': total, 'status': 'done',
                                   'file': src_name, 'output': out_name_file,
                                   'result_id': result_id, 'size': out_path.stat().st_size})
            except subprocess.TimeoutExpired:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': '转换超时（120s）'})
            except Exception as e:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': str(e)})

        yield sse('done', {'total': total, 'success': success})

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/download/<result_id>')
def api_download(result_id):
    matched = list(OUTPUT_DIR.glob(f"{result_id}_*"))
    if not matched:
        return jsonify({'error': '文件不存在'}), 404
    path = matched[0]
    filename = path.name[len(result_id) + 1:]
    return send_file(str(path), as_attachment=True, download_name=filename)


@app.route('/api/open/<result_id>')
def api_open(result_id):
    matched = list(OUTPUT_DIR.glob(f"{result_id}_*"))
    if not matched:
        return jsonify({'error': '文件不存在'}), 404
    path = str(matched[0])
    pf = get_platform_key()
    if pf == 'darwin':
        subprocess.run(['open', '-R', path])
    elif pf == 'win32':
        subprocess.run(['explorer', '/select,', path])
    else:
        subprocess.run(['xdg-open', str(matched[0].parent)])
    return jsonify({'ok': True})


@app.route('/api/cleanup', methods=['POST'])
def api_cleanup():
    """清理上传和输出目录"""
    count = 0
    for d in (UPLOAD_DIR, OUTPUT_DIR):
        for p in d.iterdir():
            if p.is_file():
                p.unlink()
                count += 1
    return jsonify({'cleaned': count})


if __name__ == '__main__':
    pf = get_platform_key()
    pf_name = PLATFORM_NAMES.get(pf, pf)
    print(f'📄 文档格式转换工具 ({pf_name}) → http://localhost:{PORT}')
    if not PANDOC_PATH:
        hints = get_install_hints('pandoc')
        hint_cmd = hints[0][1] if hints else 'brew install pandoc'
        print(f'⚠️  未检测到 pandoc，请先安装: {hint_cmd}', file=sys.stderr)
    if not LATEX_ENGINE:
        print('ℹ️  未检测到 LaTeX 引擎，PDF 输出不可用（其余格式正常）', file=sys.stderr)
    app.run(host='127.0.0.1', port=PORT, debug=False)
