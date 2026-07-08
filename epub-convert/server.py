#!/usr/bin/env python3
"""EPUB 电子书工具 —— 转换 / 元数据 / 压缩 / 推送 Git。

架构: Flask SSR + SSE 实时进度，与 doc-convert / network-detect 同一设计语言。

路由:
- GET  /                     主页面
- GET  /api/status           检测 pandoc / git 环境
- POST /api/upload           上传 epub（multipart），返回 file_id 列表 + 元数据
- GET  /api/metadata/<id>    重新提取元数据
- GET  /api/convert          SSE 转换进度流（ids=a,b&to=md）
- GET  /api/compress/<id>    压缩 epub 到 50MB（SSE 或同步 JSON）
- GET  /api/markdown/<id>    导出元数据为 markdown 文件
- GET  /api/download/<id>    下载结果
- GET  /api/open/<id>        在 Finder 中显示
- POST /api/push             推送结果到 git 仓库
- POST /api/cleanup          清理临时目录
"""

import os
import io
import re
import sys
import json
import uuid
import shutil
import zipfile
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from flask import (
    Flask, request, jsonify, render_template,
    send_file, Response, stream_with_context,
)

app = Flask(__name__)

PORT = 5200
TARGET_MB = 50  # 压缩目标体积
UPLOAD_DIR = Path(tempfile.gettempdir()) / "epub-convert-uploads"
OUTPUT_DIR = Path(tempfile.gettempdir()) / "epub-convert-output"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ---------- 环境检测 ----------
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

def detect_git():
    path = shutil.which('git')
    if not path:
        return None, None
    try:
        r = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=5)
        ver = r.stdout.strip().split()[-1] if r.stdout else 'unknown'
        return path, ver
    except Exception:
        return path, 'unknown'

PANDOC_PATH, PANDOC_VERSION = detect_pandoc()
LATEX_ENGINE = detect_latex()
GIT_PATH, GIT_VERSION = detect_git()

# ---------- 输出格式 ----------
# key: (pandoc格式, 扩展名, 显示名, 需要LaTeX)
OUTPUT_FORMATS = {
    'md':    ('markdown', 'md',   'Markdown',          False),
    'html':  ('html',     'html', 'HTML 网页',         False),
    'docx':  ('docx',     'docx', 'Word 文档',         False),
    'txt':   ('plain',    'txt',  '纯文本',            False),
    'pdf':   ('pdf',      'pdf',  'PDF',               True),
    'latex': ('latex',    'tex',  'LaTeX',             False),
    'rtf':   ('rtf',      'rtf',  'RTF 富文本',        False),
    'epub':  ('epub',     'epub', 'EPUB（重打包）',    False),
}

# ---------- 工具函数 ----------
def fmt_size(n):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != 'B' else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def safe_filename(name):
    """清理文件名，保留可读性。"""
    name = os.path.basename(name)
    # 去掉路径分隔符等危险字符
    name = re.sub(r'[\\/:*?"<>|]', '_', name)
    return name.strip().strip('.') or 'untitled'

# ---------- EPUB 元数据解析 ----------
# 命名空间
NS = {
    'opf': 'http://www.idpf.org/2007/opf',
    'dc':  'http://purl.org/dc/elements/1.1/',
    'container': 'urn:oasis:names:tc:opendocument:xmlns:container',
    'xhtml': 'http://www.w3.org/1999/xhtml',
}

def _find_opf_path(epub_zip):
    """从 META-INF/container.xml 找到 OPF 文件路径。"""
    try:
        container_xml = epub_zip.read('META-INF/container.xml')
    except KeyError:
        return None
    root = ET.fromstring(container_xml)
    rootfile = root.find('.//container:rootfile', NS)
    if rootfile is not None:
        return rootfile.get('full-path')
    return None

def _text(el):
    return (el.text or '').strip() if el is not None else ''

def parse_epub_metadata(epub_path):
    """解析 epub 元数据，返回 dict。失败返回最小信息。"""
    info = {
        'title': '', 'creators': [], 'identifier': '', 'language': '',
        'publisher': '', 'date': '', 'description': '', 'subjects': [],
        'rights': '', 'cover_href': '', 'manifest_count': 0, 'spine_count': 0,
        'epub_version': '', 'opf_path': '', 'parse_ok': False, 'error': '',
    }
    try:
        with zipfile.ZipFile(epub_path, 'r') as zf:
            info['epub_version'] = zf.comment.decode('utf-8', 'ignore') if zf.comment else ''
            opf_path = _find_opf_path(zf)
            if not opf_path:
                info['error'] = '找不到 OPF 文件（container.xml 缺失）'
                return info
            info['opf_path'] = opf_path
            opf_xml = zf.read(opf_path)
            root = ET.fromstring(opf_xml)

            # 版本
            info['epub_version'] = root.get('version', info['epub_version'] or '2.0')

            metadata = root.find('opf:metadata', NS)
            if metadata is None:
                # 兼容无命名空间前缀的写法
                metadata = root.find('{http://www.idpf.org/2007/opf}metadata')
            if metadata is None:
                info['error'] = 'OPF 中无 metadata 节点'
                return info

            # dc 元素
            for tag, key in [
                ('title', 'title'), ('identifier', 'identifier'),
                ('language', 'language'), ('publisher', 'publisher'),
                ('date', 'date'), ('description', 'description'),
                ('rights', 'rights'),
            ]:
                el = metadata.find(f'dc:{tag}', NS)
                if el is None:
                    el = metadata.find(f'{{http://purl.org/dc/elements/1.1/}}{tag}')
                if el is not None:
                    info[key] = _text(el)

            # creators（可多个，含 role / file-as）
            for creator in metadata.findall('dc:creator', NS):
                if creator is None:
                    creator = metadata.find('{http://purl.org/dc/elements/1.1/}creator')
                if creator is not None:
                    name = _text(creator)
                    if name:
                        role = creator.get('{http://www.idpf.org/2007/opf}role', '')
                        info['creators'].append({'name': name, 'role': role} if role else {'name': name})

            # 兼容：若无 dc:creator 命名空间查找
            if not info['creators']:
                for creator in metadata.iter('{http://purl.org/dc/elements/1.1/}creator'):
                    name = _text(creator)
                    if name:
                        info['creators'].append({'name': name})

            # subjects（可多个）
            for subj in metadata.iter('{http://purl.org/dc/elements/1.1/}subject'):
                s = _text(subj)
                if s:
                    info['subjects'].append(s)

            # cover image（EPUB2: meta name="cover"; EPUB3: properties="cover-image"）
            cover_id = None
            for meta in metadata.iter('{http://www.idpf.org/2007/opf}meta'):
                if meta.get('name') == 'cover':
                    cover_id = meta.get('content', '')
                    break
            # manifest
            manifest = root.find('opf:manifest', NS)
            if manifest is None:
                manifest = root.find('{http://www.idpf.org/2007/opf}manifest')
            manifest_items = []
            if manifest is not None:
                for item in manifest.iter('{http://www.idpf.org/2007/opf}item'):
                    item_id = item.get('id', '')
                    href = item.get('href', '')
                    mtype = item.get('media-type', '')
                    props = item.get('properties', '')
                    manifest_items.append({'id': item_id, 'href': href, 'type': mtype, 'properties': props})
                    if props == 'cover-image':
                        cover_id = item_id
            info['manifest_count'] = len(manifest_items)

            # 找封面 href
            if cover_id:
                for it in manifest_items:
                    if it['id'] == cover_id:
                        info['cover_href'] = it['href']
                        break

            # spine
            spine = root.find('opf:spine', NS)
            if spine is None:
                spine = root.find('{http://www.idpf.org/2007/opf}spine')
            if spine is not None:
                info['spine_count'] = len(list(spine.iter('{http://www.idpf.org/2007/opf}itemref')))

            info['parse_ok'] = True
    except zipfile.BadZipFile:
        info['error'] = '不是有效的 EPUB（ZIP 损坏）'
    except ET.ParseError as e:
        info['error'] = f'OPF XML 解析失败: {e}'
    except Exception as e:
        info['error'] = f'{type(e).__name__}: {e}'
    return info

def extract_cover_bytes(epub_path, cover_href, opf_path):
    """提取封面图片字节，返回 (bytes, mime) 或 (None, None)。"""
    if not cover_href:
        return None, None
    try:
        opf_dir = str(Path(opf_path).parent) if opf_path else ''
        # 拼接相对路径
        if opf_dir:
            full = f"{opf_dir}/{cover_href}" if not cover_href.startswith('/') else cover_href.lstrip('/')
        else:
            full = cover_href
        full = full.lstrip('/')
        with zipfile.ZipFile(epub_path, 'r') as zf:
            names = zf.namelist()
            # 精确匹配
            if full in names:
                data = zf.read(full)
            else:
                # 模糊匹配文件名
                base = Path(cover_href).name
                match = [n for n in names if n.endswith(base)]
                if not match:
                    return None, None
                data = zf.read(match[0])
        ext = Path(cover_href).suffix.lower()
        mime = {'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
                'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml'}.get(ext.lstrip('.'), 'image/jpeg')
        return data, mime
    except Exception:
        return None, None

# ---------- EPUB 压缩 ----------
def _is_image(name):
    return name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))

def _compress_image_bytes(data, quality, max_dim=2000):
    """用 Pillow 压缩图片字节，返回 bytes。jpeg 降质量；png 转 jpeg（如有 alpha 则保留 png 但优化）。"""
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return data  # 无法解码则原样返回
    # 大图缩放
    if max_dim and (img.width > max_dim or img.height > max_dim):
        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
    fmt = img.format.upper() if img.format else ''
    out = io.BytesIO()
    if fmt in ('JPEG', 'JPG') or img.mode == 'RGB':
        img = img.convert('RGB')
        img.save(out, format='JPEG', quality=quality, optimize=True)
    elif fmt == 'PNG':
        # 有 alpha 保留 PNG，优化；无 alpha 转 JPEG 更省
        if img.mode in ('RGBA', 'LA', 'P'):
            img.save(out, format='PNG', optimize=True)
        else:
            img = img.convert('RGB')
            img.save(out, format='JPEG', quality=quality, optimize=True)
    else:
        img = img.convert('RGB')
        img.save(out, format='JPEG', quality=quality, optimize=True)
    result = out.getvalue()
    # 如果压缩后反而更大，返回原始
    return result if len(result) < len(data) else data

def compress_epub(src_path, dst_path, target_mb=TARGET_MB):
    """压缩 epub 到目标体积。返回 (新路径, 原大小, 新大小, 消息)。"""
    from PIL import Image  # noqa: F401
    target_bytes = target_mb * 1024 * 1024
    src_size = os.path.getsize(src_path)

    if src_size <= target_bytes:
        shutil.copy2(src_path, dst_path)
        return dst_path, src_size, src_size, f'原始 {fmt_size(src_size)} 已在 {target_mb}MB 以内，无需压缩'

    # 多轮压缩：质量从 80 逐步降到 30
    qualities = [80, 65, 50, 35, 25]
    max_dims = [2000, 1600, 1200, 900, 700]
    best_path = None
    best_size = src_size

    for q, dim in zip(qualities, max_dims):
        tmp = dst_path.with_suffix('.tmp.epub')
        with zipfile.ZipFile(src_path, 'r') as zin, \
             zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if _is_image(item.filename):
                    data = _compress_image_bytes(data, q, dim)
                # 保留文件名与时间，重写压缩
                new_info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                new_info.compress_type = zipfile.ZIP_DEFLATED
                new_info.external_attr = item.external_attr
                zout.writestr(new_info, data)
        new_size = os.path.getsize(tmp)
        if new_size < best_size:
            best_size = new_size
            if best_path and best_path.exists():
                best_path.unlink()
            best_path = tmp
        else:
            tmp.unlink()
        if best_size <= target_bytes:
            break

    if best_path is None:
        shutil.copy2(src_path, dst_path)
        return dst_path, src_size, src_size, '压缩失败，保留原始文件'

    best_path.replace(dst_path)
    ratio = (1 - best_size / src_size) * 100
    msg = f'已压缩: {fmt_size(src_size)} → {fmt_size(best_size)}（减小 {ratio:.1f}%）'
    if best_size > target_bytes:
        msg += f' · 仍超过 {target_mb}MB（图片已极致压缩，建议手动裁切内容）'
    return dst_path, src_size, best_size, msg

# ---------- 元数据导出 Markdown ----------
def metadata_to_markdown(meta, source_name):
    lines = []
    lines.append(f'# {meta.get("title") or source_name}')
    lines.append('')
    creators = meta.get('creators', [])
    if creators:
        author_str = ', '.join(c['name'] for c in creators)
        lines.append(f'**作者:** {author_str}')
        lines.append('')
    fields = [
        ('identifier', 'ISBN / 标识符'),
        ('publisher', '出版社'),
        ('date', '出版日期'),
        ('language', '语言'),
    ]
    for key, label in fields:
        val = meta.get(key, '')
        if val:
            lines.append(f'- **{label}:** {val}')
    subjects = meta.get('subjects', [])
    if subjects:
        lines.append(f'- **主题/标签:** {", ".join(subjects)}')
    if meta.get('rights'):
        lines.append(f'- **版权:** {meta["rights"]}')
    lines.append('')
    desc = meta.get('description', '')
    if desc:
        lines.append('## 内容简介')
        lines.append('')
        # 清理 HTML 标签
        clean = re.sub(r'<[^>]+>', '', desc)
        lines.append(clean.strip())
        lines.append('')
    # 技术信息
    lines.append('## 技术信息')
    lines.append('')
    lines.append(f'- **源文件:** {source_name}')
    lines.append(f'- **EPUB 版本:** {meta.get("epub_version", "未知")}')
    lines.append(f'- **OPF 路径:** `{meta.get("opf_path", "")}`')
    lines.append(f'- **Manifest 条目数:** {meta.get("manifest_count", 0)}')
    lines.append(f'- **Spine 章节数:** {meta.get("spine_count", 0)}')
    lines.append(f'- **封面资源:** `{meta.get("cover_href", "无")}`')
    if meta.get('error'):
        lines.append(f'- **解析告警:** {meta["error"]}')
    lines.append('')
    lines.append('---')
    lines.append(f'> 由 EPUB 工具自动生成 · {source_name}')
    return '\n'.join(lines)

# ---------- 路由 ----------
@app.route('/')
def index():
    return render_template(
        'index.html',
        pandoc_path=PANDOC_PATH, pandoc_version=PANDOC_VERSION,
        latex_engine=LATEX_ENGINE,
        git_path=GIT_PATH, git_version=GIT_VERSION,
        output_formats=OUTPUT_FORMATS,
        target_mb=TARGET_MB, port=PORT,
    )

@app.route('/api/status')
def api_status():
    return jsonify({
        'pandoc': {'path': PANDOC_PATH, 'version': PANDOC_VERSION, 'available': bool(PANDOC_PATH)},
        'latex': {'engine': LATEX_ENGINE, 'available': bool(LATEX_ENGINE)},
        'git': {'path': GIT_PATH, 'version': GIT_VERSION, 'available': bool(GIT_PATH)},
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
        safe_name = safe_filename(f.filename)
        # 仅接受 epub
        ext = Path(safe_name).suffix.lower()
        if ext != '.epub':
            results.append({'id': file_id, 'name': safe_name, 'supported': False,
                            'input_ext': ext.lstrip('.'), 'error': '仅支持 .epub'})
            continue
        saved = UPLOAD_DIR / f"{file_id}_{safe_name}"
        f.save(str(saved))
        size = saved.stat().st_size
        meta = parse_epub_metadata(str(saved))
        results.append({
            'id': file_id, 'name': safe_name, 'size': size,
            'supported': True, 'input_ext': 'epub',
            'metadata': meta, 'needs_compress': size > TARGET_MB * 1024 * 1024,
        })
    return jsonify({'files': results})

@app.route('/api/metadata/<file_id>')
def api_metadata(file_id):
    matched = list(UPLOAD_DIR.glob(f"{file_id}_*"))
    if not matched:
        return jsonify({'error': '文件不存在'}), 404
    meta = parse_epub_metadata(str(matched[0]))
    return jsonify({'metadata': meta, 'source': matched[0].name[len(file_id)+1:]})

@app.route('/api/cover/<file_id>')
def api_cover(file_id):
    matched = list(UPLOAD_DIR.glob(f"{file_id}_*"))
    if not matched:
        return jsonify({'error': '文件不存在'}), 404
    meta = parse_epub_metadata(str(matched[0]))
    data, mime = extract_cover_bytes(str(matched[0]), meta.get('cover_href', ''), meta.get('opf_path', ''))
    if not data:
        return jsonify({'error': '无封面'}), 404
    return send_file(io.BytesIO(data), mimetype=mime)

@app.route('/api/convert')
def api_convert():
    """SSE 转换流。GET /api/convert?ids=a,b&to=md"""
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
            if Path(src_name).suffix.lower() != '.epub':
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': '仅支持 epub 输入'})
                continue

            out_stem = Path(src_name).stem
            out_name_file = f"{out_stem}.{out_ext}"
            result_id = uuid.uuid4().hex[:12]
            out_path = OUTPUT_DIR / f"{result_id}_{out_name_file}"

            yield sse('item', {'index': i, 'total': total, 'status': 'converting',
                               'file': src_name, 'from': 'epub', 'to': pandoc_fmt,
                               'output': out_name_file})

            cmd = [PANDOC_PATH, str(src), '-f', 'epub', '-t', pandoc_fmt, '-o', str(out_path)]
            if need_latex and LATEX_ENGINE:
                cmd.extend(['--pdf-engine', LATEX_ENGINE])
                if LATEX_ENGINE == 'xelatex':
                    cmd.extend(['-V', 'mainfont=PingFang SC', '-V', 'CJKmainfont=PingFang SC'])

            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
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
                                   'file': src_name, 'message': '转换超时（300s）'})
            except Exception as e:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': str(e)})

        yield sse('done', {'total': total, 'success': success})

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/compress')
def api_compress():
    """SSE 压缩流。GET /api/compress?ids=a,b"""
    ids = request.args.get('ids', '')
    file_ids = [x.strip() for x in ids.split(',') if x.strip()]

    def sse(event, data):
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    def generate():
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
            src_size = src.stat().st_size
            yield sse('item', {'index': i, 'total': total, 'status': 'converting',
                               'file': src_name, 'message': f'压缩中（{fmt_size(src_size)}）'})

            result_id = uuid.uuid4().hex[:12]
            out_name_file = f"{Path(src_name).stem}_compressed.epub"
            out_path = OUTPUT_DIR / f"{result_id}_{out_name_file}"
            try:
                _, old_s, new_s, msg = compress_epub(src, out_path, TARGET_MB)
                success += 1
                yield sse('item', {'index': i, 'total': total, 'status': 'done',
                                   'file': src_name, 'output': out_name_file,
                                   'result_id': result_id, 'size': new_s,
                                   'orig_size': old_s, 'message': msg})
            except Exception as e:
                yield sse('item', {'index': i, 'total': total, 'status': 'error',
                                   'file': src_name, 'message': str(e)})
        yield sse('done', {'total': total, 'success': success})

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/markdown/<file_id>')
def api_markdown(file_id):
    """导出元数据为 markdown 文件并下载。"""
    matched = list(UPLOAD_DIR.glob(f"{file_id}_*"))
    if not matched:
        # 也可能是 output 目录的结果
        matched = list(OUTPUT_DIR.glob(f"{file_id}_*"))
    if not matched:
        return jsonify({'error': '文件不存在'}), 404
    src = matched[0]
    src_name = src.name[len(file_id) + 1:]
    meta = parse_epub_metadata(str(src)) if src_name.lower().endswith('.epub') else {}
    md = metadata_to_markdown(meta, src_name)
    result_id = uuid.uuid4().hex[:12]
    out_name = f"{Path(src_name).stem}_metadata.md"
    out_path = OUTPUT_DIR / f"{result_id}_{out_name}"
    out_path.write_text(md, encoding='utf-8')
    return jsonify({'result_id': result_id, 'output': out_name, 'size': out_path.stat().st_size,
                    'preview': md[:600]})

@app.route('/api/download/<result_id>')
def api_download(result_id):
    matched = list(OUTPUT_DIR.glob(f"{result_id}_*")) + list(UPLOAD_DIR.glob(f"{result_id}_*"))
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
    subprocess.run(['open', '-R', str(matched[0])])
    return jsonify({'ok': True})

# ---------- Git 推送 ----------
@app.route('/api/push', methods=['POST'])
def api_push():
    """推送结果文件到 git 仓库。
    body: { repo_url, branch, token, commit_msg, result_ids: [..], author_name, author_email }
    支持 github / gitea（均为 https + token）。
    """
    if not GIT_PATH:
        return jsonify({'error': 'git 未安装'}), 400
    data = request.get_json(force=True)
    repo_url = (data.get('repo_url') or '').strip()
    branch = (data.get('branch') or 'main').strip()
    token = (data.get('token') or '').strip()
    commit_msg = (data.get('commit_msg') or 'chore: 推送 EPUB 转换结果').strip()
    result_ids = data.get('result_ids') or []
    author_name = (data.get('author_name') or 'epub-convert').strip()
    author_email = (data.get('author_email') or 'epub-convert@local').strip()

    if not repo_url:
        return jsonify({'error': '缺少仓库地址'}), 400
    if not result_ids:
        return jsonify({'error': '未选择要推送的文件'}), 400

    # 注入 token：https://github.com/user/repo[.git] → https://x-access-token:<token>@github.com/...
    push_url = repo_url
    if token and push_url.startswith('https://'):
        # github: x-access-token; gitea: token 直接作用户名
        host = push_url[len('https://'):]
        # 判断是否 github
        if host.startswith('github.com'):
            push_url = f"https://x-access-token:{token}@{host}"
        else:
            # gitea / 其他：用 token 作为用户名
            push_url = f"https://{token}@{host}"

    # 收集要推送的文件
    files_to_push = []
    for rid in result_ids:
        matched = list(OUTPUT_DIR.glob(f"{rid}_*"))
        if matched:
            files_to_push.append(matched[0])
    if not files_to_push:
        return jsonify({'error': '所选文件在结果目录中不存在'}), 400

    work_dir = Path(tempfile.mkdtemp(prefix='epub-git-'))
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_AUTHOR_NAME=author_name,
               GIT_AUTHOR_EMAIL=author_email, GIT_COMMITTER_NAME=author_name,
               GIT_COMMITTER_EMAIL=author_email)

    def run_git(args, cwd=None):
        return subprocess.run([GIT_PATH] + args, cwd=cwd or work_dir,
                              capture_output=True, text=True, timeout=60, env=env)

    log = []
    try:
        # 初始化仓库
        r = run_git(['init', '-b', branch])
        log.append(f"init: {r.stdout.strip() or r.stderr.strip()}")
        run_git(['config', 'user.name', author_name])
        run_git(['config', 'user.email', author_email])

        # 复制文件
        for fp in files_to_push:
            shutil.copy2(str(fp), str(work_dir / fp.name.split('_', 1)[-1] if '_' in fp.name else fp.name))

        r = run_git(['add', '-A'])
        log.append(f"add: rc={r.returncode}")
        r = run_git(['commit', '-m', commit_msg, '--allow-empty'])
        log.append(f"commit: rc={r.returncode} {(r.stdout or r.stderr).strip()[:200]}")

        # 推送
        run_git(['remote', 'add', 'origin', repo_url])
        r = run_git(['push', push_url, f'HEAD:{branch}', '--force'])
        out = (r.stdout + r.stderr).strip()
        log.append(f"push: rc={r.returncode} {out[:300]}")
        if r.returncode != 0:
            # 隐藏 token
            safe = '\n'.join(l.replace(token, '***') for l in log) if token else '\n'.join(log)
            return jsonify({'error': '推送失败', 'log': safe}), 200
        safe = '\n'.join(l.replace(token, '***') for l in log) if token else '\n'.join(log)
        return jsonify({'ok': True, 'log': safe, 'pushed': len(files_to_push)})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'git 操作超时', 'log': '\n'.join(log)}), 200
    except Exception as e:
        return jsonify({'error': f'{type(e).__name__}: {e}', 'log': '\n'.join(log)}), 200
    finally:
        try:
            shutil.rmtree(str(work_dir), ignore_errors=True)
        except Exception:
            pass

@app.route('/api/cleanup', methods=['POST'])
def api_cleanup():
    count = 0
    for d in (UPLOAD_DIR, OUTPUT_DIR):
        for p in d.iterdir():
            if p.is_file():
                p.unlink()
                count += 1
    return jsonify({'cleaned': count})

if __name__ == '__main__':
    if not PANDOC_PATH:
        print('⚠️  未检测到 pandoc，请先安装: brew install pandoc', file=sys.stderr)
    print(f'📚 EPUB 工具 → http://localhost:{PORT}')
    app.run(host='127.0.0.1', port=PORT, debug=False)
