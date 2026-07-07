#!/usr/bin/env python3
"""
网络链路检测工具 — Flask 后端 (SSR 版)
GET  /  → 空表单页面
POST /  → 运行七步检测，返回结果页面（数据嵌入 HTML，无需 fetch）
"""

import subprocess
import re
import json
import socket
from flask import Flask, request, render_template, Response, stream_with_context
import time

app = Flask(__name__)

# ── helpers ──────────────────────────────────────────────────────────

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def _dns_label(ip):
    """返回 DNS IP 的可读标签"""
    clean = ip.split("%")[0]
    if clean in ("8.8.8.8", "8.8.4.4"): return "Google DNS"
    if clean in ("1.1.1.1", "1.0.0.1"): return "Cloudflare"
    if clean in ("223.5.5.5", "223.6.6.6"): return "阿里 DNS"
    if clean in ("119.29.29.29",): return "DNSPod"
    if clean in ("114.114.114.114",): return "114 DNS"
    if clean == "127.0.0.1": return "本地 DNS"
    if clean.startswith("fe80:"): return "本地"
    # ISP 识别
    if any(k in clean for k in ["218.85", "202.101", "61.131"]): return "福建电信 DNS"
    return "ISP DNS"


# ── 步骤 1：本机出口 ────────────────────────────────────────────────

def step_local_egress():
    result = {"default_interface": None, "default_gateway": None,
              "local_ip": None, "is_vpn": False, "vpn_type": None}
    out, _, _ = run("netstat -rn -f inet | grep default")
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default":
            result["default_gateway"] = parts[1]
            result["default_interface"] = parts[-1]
            break
    iface = result["default_interface"] or ""
    if iface.startswith("utun") or iface.startswith("tun") or iface.startswith("ppp"):
        result["is_vpn"] = True
        result["vpn_type"] = "VPN/隧道"
    target_iface = result["default_interface"] if result["default_interface"] != "lo0" else "en0"
    out, _, _ = run(f"ifconfig {target_iface} | grep 'inet '")
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    if m:
        result["local_ip"] = m.group(1)
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            result["local_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass
    return result


# ── 步骤 2：DNS 配置 ─────────────────────────────────────────────────

def step_dns_config():
    servers = []
    details = []
    out, _, _ = run("scutil --dns | grep -E 'nameserver|if_index'")
    current_iface = None
    for line in out.split("\n"):
        m_ns = re.search(r"nameserver\[(\d+)\]\s*:\s*(\S+)", line)
        m_if = re.search(r"if_index\s*:\s*\d+\s*\((\w+)\)", line)
        if m_if:
            current_iface = m_if.group(1)
        if m_ns:
            ip = m_ns.group(2)
            if ip not in servers:
                servers.append(ip)
            details.append({"ip": ip, "interface": current_iface or "unknown"})
    if not servers:
        out, _, _ = run("cat /etc/resolv.conf | grep nameserver")
        for line in out.split("\n"):
            m = re.search(r"nameserver\s+(\S+)", line)
            if m and m.group(1) not in servers:
                servers.append(m.group(1))
                details.append({"ip": m.group(1), "interface": "resolv.conf"})
    dns_labels = []
    for ip in servers:
        if ip in ("8.8.8.8", "8.8.4.4"):
            dns_labels.append(f"{ip} (Google Public DNS)")
        elif ip in ("1.1.1.1", "1.0.0.1"):
            dns_labels.append(f"{ip} (Cloudflare)")
        elif ip in ("223.5.5.5", "223.6.6.6"):
            dns_labels.append(f"{ip} (阿里 DNS)")
        elif ip in ("119.29.29.29",):
            dns_labels.append(f"{ip} (腾讯 DNSPod)")
        elif ip in ("114.114.114.114",):
            dns_labels.append(f"{ip} (114 DNS)")
        elif ip == "127.0.0.1":
            dns_labels.append(f"{ip} (本地)")
        else:
            dns_labels.append(f"{ip} (ISP/其他)")
    return {"servers": servers, "details": details, "labels": dns_labels}


# ── 步骤 3：域名解析 ─────────────────────────────────────────────────

def step_dns_resolve(domain):
    cname_chain = []
    a_records = []
    out, _, _ = run(f"dig +short {domain} A")
    for line in out.split("\n"):
        line = line.strip()
        if line and re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            a_records.append(line)
    current = domain
    for _ in range(5):
        out, _, _ = run(f"dig +short {current} CNAME")
        cname = out.strip().rstrip(".")
        if not cname:
            break
        cname_chain.append(cname)
        current = cname
    return {"domain": domain, "cname_chain": cname_chain, "a_records": a_records}


# ── 步骤 4：IP 归属 ──────────────────────────────────────────────────

def step_ip_whois(ips):
    result = {}
    # 最多查 3 个 IP，避免大量 A 记录导致超时
    for ip in ips[:3]:
        info = {"netname": "", "descr": "", "country": "", "org": "", "isp": ""}
        out, _, _ = run(f"whois {ip}", timeout=5)
        for line in out.split("\n"):
            ll = line.lower()
            if re.match(r"^netname:", ll):
                info["netname"] = line.split(":", 1)[1].strip()
            elif re.match(r"^descr:", ll) and not info["descr"]:
                info["descr"] = line.split(":", 1)[1].strip()
            elif re.match(r"^country:", ll):
                info["country"] = line.split(":", 1)[1].strip()
            elif re.match(r"^org-name:|^organisation:", ll):
                info["org"] = line.split(":", 1)[1].strip()
        raw_lower = out.lower()
        for kw, label in [
            ("tencent", "腾讯云"), ("alibaba", "阿里云"), ("aliyun", "阿里云"),
            ("aws", "AWS"), ("amazon", "AWS"), ("google", "GCP"),
            ("azure", "Azure"), ("microsoft", "Azure"), ("cloudflare", "Cloudflare"),
            ("chinanet", "中国电信"), ("unicom", "中国联通"), ("chinamobile", "中国移动"),
        ]:
            if kw in raw_lower:
                info["isp"] = label
                break
        result[ip] = info
    return result


# ── 步骤 5：路由路径 ─────────────────────────────────────────────────

def step_routing(ips):
    result = {}
    for ip in ips:
        info = {"interface": None, "gateway": None, "is_direct": True, "is_tunnel": False}
        out, _, _ = run(f"route -n get {ip}")
        m_if = re.search(r"interface:\s*(\S+)", out)
        m_gw = re.search(r"gateway:\s*(\S+)", out)
        if m_if:
            info["interface"] = m_if.group(1)
            if m_if.group(1).startswith(("utun", "tun", "ppp")):
                info["is_tunnel"] = True
                info["is_direct"] = False
        if m_gw:
            info["gateway"] = m_gw.group(1)
        result[ip] = info
    return result


# ── 步骤 6：TLS / 连接测试 ───────────────────────────────────────────

def step_tls_check(domain):
    result = {"connect_time": None, "tls_version": None, "cert_cn": None,
              "cert_expire": None, "cert_valid": False, "using_proxy": False,
              "proxy_address": None, "remote_ip": None, "http_code": None,
              "proxy_mode": "direct"}

    # 检查系统代理是否开启
    proxy_out, _, _ = run("scutil --proxy")
    has_sys_proxy = bool(re.search(r"ProxyEnabled\s*:\s*1", proxy_out))

    # 先尝试直连（绕过系统代理），判断该域名是否实际需要代理
    out, err, rc = run(
        f"curl -svw '\\ntime_connect: %{{time_connect}}\\n' --noproxy '*' --connect-timeout 4 --max-time 10 -o /dev/null https://{domain} 2>&1",
        timeout=15
    )
    combined = out + "\n" + err
    direct_ok = (rc == 0)

    if not direct_ok:
        # 直连失败，走系统代理重试
        result["using_proxy"] = True
        result["proxy_mode"] = "proxy"
        out, err, rc = run(
            f"curl -svw '\\ntime_connect: %{{time_connect}}\\n' --connect-timeout 5 --max-time 12 -o /dev/null https://{domain} 2>&1",
            timeout=15
        )
        combined = out + "\n" + err
        m = re.search(r"Trying\s+(\S+?):(\d+)\.\.\.", combined)
        if m:
            proxy_ip, proxy_port = m.group(1), m.group(2)
            if proxy_ip in ("127.0.0.1", "::1") or proxy_port in (
                "1087","7890","7891","8118","8888","9090","56996","6152","10808","7897","56201"
            ):
                result["proxy_address"] = f"{proxy_ip}:{proxy_port}"
            result["remote_ip"] = m.group(1)
    else:
        # 直连成功
        if has_sys_proxy:
            result["proxy_mode"] = "proxy_direct"  # 系统有代理，但该域名走直连规则
        m = re.search(r"Trying\s+(\S+?):(\d+)\.\.\.", combined)
        if m:
            result["remote_ip"] = m.group(1)

    # 解析 TLS 信息
    m = re.search(r"SSL connection using (\S+)", combined)
    if m:
        result["tls_version"] = m.group(1)
    m = re.search(r"subject:\s*(.+)", combined)
    if m:
        cn_m = re.search(r"CN\s*=\s*([^,;\n]+)", m.group(1))
        if cn_m:
            result["cert_cn"] = cn_m.group(1).strip()
        else:
            result["cert_cn"] = m.group(1).strip()[:80]
    m = re.search(r"expire date:\s*([^\n]+)", combined)
    if m:
        result["cert_expire"] = m.group(1).strip()
    m = re.search(r"time_connect:\s*(\S+)", combined)
    if m:
        result["connect_time"] = m.group(1)
    m = re.search(r"< HTTP/\d\.?\d?\s+(\d+)", combined)
    if m:
        result["http_code"] = m.group(1)
    if rc == 0 and result["cert_cn"]:
        result["cert_valid"] = True
    return result


# ── 步骤 7：代理 & 隧道 ─────────────────────────────────────────────

def step_proxy_tunnel():
    result = {"system_proxy": {}, "env_proxy": {}, "tunnel_interfaces": []}
    out, _, _ = run("scutil --proxy")
    for line in out.split("\n"):
        m = re.search(r"(\w+ProxyEnabled)\s*:\s*(\d)", line)
        if m and m.group(2) == "1":
            result["system_proxy"][m.group(1)] = True
        m2 = re.search(r"(HTTPProxy|HTTPSProxy|SOCKSProxy)\s*:\s*(\S+)", line)
        if m2:
            result["system_proxy"][m2.group(1)] = m2.group(2)
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"]:
        out, _, _ = run(f"echo ${var}")
        val = out.strip()
        if val and val != "${var}":
            result["env_proxy"][var] = val
    out, _, _ = run("ifconfig | grep -E '^(utun|tun|ppp)'")
    for line in out.split("\n"):
        m = re.search(r"^(utun\d+|tun\d+|ppp\d+)", line)
        if m:
            result["tunnel_interfaces"].append(m.group(1))
    return result


def _fmt_ms(val):
    """将秒或毫秒字符串统一格式化为 'Xms' 字符串"""
    if val is None or val == "—" or val == "":
        return "—"
    try:
        t = float(val)
        if t < 1:  # 秒（curl 的 time_connect）
            return f"{t * 1000:.2f}ms"
        else:  # 已经是毫秒
            return f"{t:.2f}ms"
    except (ValueError, TypeError):
        return str(val)


def ping_once(target):
    """对目标 IP/域名发送一次 ping，返回延迟字符串"""
    if not target:
        return "—"
    out, _, _ = run(f"ping -c 1 -W 1500 {target} 2>&1", timeout=5)
    m = re.search(r"time=(\d+\.?\d*)\s*ms", out)
    if m:
        return f"{m.group(1)}ms"
    return "—"


# ── 步骤 8：网络跳转路径 ─────────────────────────────────────────────

def step_traceroute(domain):
    """从检测数据重建逻辑跳转路径表

    比原始 traceroute 更有信息量，展示完整的逻辑链路：
    本机 → 网关 → DNS → CDN/WAF → 目标服务器
    """
    result = {"hops": [], "total_hops": 0}
    
    # ── 按顺序收集数据 ──
    local = step_local_egress()
    dns = step_dns_config()
    resolution = step_dns_resolve(domain)
    ips = resolution.get("a_records", [])
    ip_info = step_ip_whois(ips[:3])
    routing = step_routing(ips[:3])
    tls = step_tls_check(domain)
    proxy = step_proxy_tunnel()

    hops = []
    
    # Hop 1: 本机
    vpn_tag = "·VPN" if local.get("is_vpn") else ""
    hops.append({
        "hop": 1, "type": "local",
        "name": "本机",
        "detail": f"{local.get('local_ip','?')} ({local.get('default_interface','?')}{vpn_tag})",
        "label": "本机出口" if not local.get("is_vpn") else "VPN 出口",
        "label_class": "local" if not local.get("is_vpn") else "vpn",
        "tms": "0ms"
    })
    
    # Hop 2: 默认网关
    gw_ip = local.get("default_gateway", "")
    hops.append({
        "hop": 2, "type": "gateway",
        "name": "默认网关",
        "detail": gw_ip or "?",
        "label": "家庭/企业网关",
        "label_class": "local",
        "tms": ping_once(gw_ip) if gw_ip else "—"
    })
    
    # Hop 3: DNS 服务器（显示前 2 个）
    dns_servers = dns.get("servers", [])
    dns_details = dns.get("details", [])
    # 去重 IP
    seen = set()
    dns_unique = []
    for s in dns_servers:
        if s not in seen and not s.startswith("fe80:"):
            seen.add(s)
            dns_unique.append(s)
    
    dns_labels = []
    for d in dns_details:
        ip = d.get("ip", "")
        if ip in dns_unique:
            dns_labels.append(f"{ip} ({d.get('interface','?')})")
    
    dns_first = dns_unique[0] if dns_unique else None
    hops.append({
        "hop": 3, "type": "dns",
        "name": "DNS 解析",
        "detail": " → ".join(dns_unique[:2]) if dns_unique else "?",
        "label": " · ".join([_dns_label(s) for s in dns_unique[:2]]),
        "label_class": "dns",
        "tms": ping_once(dns_first) if dns_first else "—"
    })
    
    # Hop 4~N: CNAME 链 / CDN / WAF
    cnames = resolution.get("cname_chain", [])
    hop_num = 4
    for cn in cnames:
        sub_type = "cdn"
        if "icloudwaf" in cn or "waf" in cn:
            sub_type = "waf"
        elif "dsa.dnsv1" in cn:
            sub_type = "dsa"
        elif any(k in cn for k in ["cdn", "kunlun", "lxdns", "edgekey", "akamai"]):
            sub_type = "cdn"
        type_labels = {"cdn": "CDN 节点", "waf": "WAF 防护", "dsa": "DSA 加速"}
        hops.append({
            "hop": hop_num, "type": "cname",
            "name": type_labels.get(sub_type, "CNAME"),
            "detail": cn,
            "label": type_labels.get(sub_type, "CNAME 解析"),
            "label_class": "cloud" if sub_type == "cdn" else ("vpn" if sub_type == "waf" else "isp"),
            "tms": ping_once(cn)
        })
        hop_num += 1
    
    # Hop N+1: 目标服务器
    for i, ip in enumerate(ips[:5]):
        info = ip_info.get(ip, {})
        ri = routing.get(ip, {})
        isp_label = info.get("isp", info.get("netname", ""))
        route_type = "隧道" if not ri.get("is_direct", True) else "直连"
        if i == 0:
            # 第一个目标 IP 用 curl 的 connect_time（TLS 握手时间更精确）
            tms = _fmt_ms(tls.get("connect_time"))
        else:
            # 后续目标 IP 用 ping
            tms = ping_once(ip)
        hops.append({
            "hop": hop_num + i, "type": "target",
            "name": "目标服务器" if i == 0 else f"目标 #{i+1}",
            "detail": f"{ip} ({ri.get('interface','?')}, {route_type})",
            "label": isp_label or info.get("country", "") or "目标 IP",
            "label_class": "cloud" if any(k in (isp_label or "").lower() for k in ["腾讯","阿里","aws","google","azure","cloudflare"]) else "isp",
            "tms": tms
        })
    
    # 如果有代理，插入代理跳
    if tls.get("using_proxy") or proxy.get("system_proxy") or proxy.get("env_proxy"):
        # 在 Hop 2 之后插入代理跳
        proxy_addr = tls.get("proxy_address", "")
        env_proxy = proxy.get("env_proxy", {})
        sys_proxy = proxy.get("system_proxy", {})
        proxy_desc = proxy_addr or env_proxy.get("HTTPS_PROXY", env_proxy.get("HTTP_PROXY", sys_proxy.get("HTTPSProxy", sys_proxy.get("HTTPProxy", "检测到代理"))))
        hops.insert(3, {
            "hop": "·", "type": "proxy",
            "name": "代理/隧道",
            "detail": str(proxy_desc),
            "label": "代理转发",
            "label_class": "vpn",
            "tms": "—"
        })
        # 修正后续跳号
        for j in range(4, len(hops)):
            hops[j]["hop"] = j + 1 if isinstance(hops[j]["hop"], int) else hops[j]["hop"]
    
    result["hops"] = hops
    result["total_hops"] = len(hops)
    result["has_proxy"] = tls.get("using_proxy", False)
    result["proxy_mode"] = tls.get("proxy_mode", "direct")
    return result


# ── 全集检测 ─────────────────────────────────────────────────────────

def run_all_checks(domain):
    domain = re.sub(r"^https?://", "", domain.strip()).split("/")[0]
    report = {"domain": domain}
    report["local"] = step_local_egress()
    report["dns"] = step_dns_config()
    report["resolution"] = step_dns_resolve(domain)
    ips = report["resolution"].get("a_records", [])
    report["ip_info"] = step_ip_whois(ips)
    report["routing"] = step_routing(ips)
    report["tls"] = step_tls_check(domain)
    report["proxy_tunnel"] = step_proxy_tunnel()
    report["traceroute"] = step_traceroute(domain)
    return report


# ── 路由 ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if not domain:
            return render_template("index.html", result=None, error="请输入域名")
        try:
            data = run_all_checks(domain)
            result_json = json.dumps(data, ensure_ascii=False)
            return render_template("index.html", result=result_json, domain=domain, error=None)
        except Exception as e:
            return render_template("index.html", result=None, error=str(e))
    return render_template("index.html", result=None, error=None)


@app.route("/api/health")
def health():
    return {"status": "ok"}


@app.route("/api/detect", methods=["POST"])
def detect_api():
    """保留 API 端点供 CLI / 外部调用"""
    data = request.get_json()
    if not data or "domain" not in data:
        return {"error": "请提供 domain 参数"}, 400
    domain = data["domain"].strip()
    try:
        return {"success": True, "data": run_all_checks(domain)}
    except Exception as e:
        return {"success": False, "error": str(e)}, 500


# ── SSE 流式检测（实时进度）─────────────────────────────────────────

@app.route("/api/detect/stream")
def detect_stream():
    """SSE 端点：逐步推送检测进度，最后推送完整结果"""
    domain = request.args.get("domain", "").strip()
    if not domain:
        def err_gen():
            yield f"event: error\ndata: {json.dumps({'message': '请输入域名'}, ensure_ascii=False)}\n\n"
        return Response(stream_with_context(err_gen()), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    steps_meta = [
        ("local", "本机出口/默认路由"),
        ("dns", "DNS 配置"),
        ("resolution", "域名解析 (dig)"),
        ("ip_info", "IP 归属 (whois)"),
        ("routing", "路由路径 (route)"),
        ("tls", "TLS/HTTPS 连接"),
        ("proxy_tunnel", "代理 & 隧道"),
        ("traceroute", "跳转路径重建"),
    ]
    total = len(steps_meta)

    def generate():
        report = {"domain": domain}
        ips = []

        for i, (key, title) in enumerate(steps_meta):
            payload = {"step": i + 1, "total": total, "title": title, "key": key}
            yield f"event: progress\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

            try:
                if key == "local":
                    report["local"] = step_local_egress()
                elif key == "dns":
                    report["dns"] = step_dns_config()
                elif key == "resolution":
                    report["resolution"] = step_dns_resolve(domain)
                    ips = report["resolution"].get("a_records", [])
                elif key == "ip_info":
                    report["ip_info"] = step_ip_whois(ips)
                elif key == "routing":
                    report["routing"] = step_routing(ips)
                elif key == "tls":
                    report["tls"] = step_tls_check(domain)
                elif key == "proxy_tunnel":
                    report["proxy_tunnel"] = step_proxy_tunnel()
                elif key == "traceroute":
                    report["traceroute"] = step_traceroute(domain)

                done_payload = {**payload, "status": "ok"}
                yield f"event: step_done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"
            except Exception as e:
                done_payload = {**payload, "status": "error", "error": str(e)}
                yield f"event: step_done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"

        yield f"event: complete\ndata: {json.dumps(report, ensure_ascii=False)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    print("🔍 网络链路检测服务启动: http://localhost:5099")
    app.run(host="127.0.0.1", port=5099, debug=False)
