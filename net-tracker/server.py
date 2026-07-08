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
import math
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



# ═══════════════════════════════════════════════════════════════
# 网络质量检测（net-quality 8 步）
# ═══════════════════════════════════════════════════════════════

def q_step_interfaces():
    """步骤 1：网络接口扫描"""
    interfaces = []
    out, _, _ = run("ifconfig -l")
    iface_names = out.split()
    hw_out, _, _ = run("networksetup -listallhardwareports")

    port_map = {}
    current_name = None
    for line in hw_out.split("\n"):
        m_name = re.match(r"Hardware Port:\s*(.+)", line)
        m_dev = re.match(r"Device:\s*(\w+)", line)
        if m_name:
            current_name = m_name.group(1).strip()
        elif m_dev and current_name:
            port_map[m_dev.group(1)] = current_name
            current_name = None

    for name in iface_names:
        info = {
            "name": name, "display_name": port_map.get(name, name),
            "ipv4": None, "ipv6": None, "netmask": None,
            "mac": None, "mtu": None, "active": False, "type": "other"
        }
        if name.startswith("en") and not name.startswith("en"):
            info["type"] = "eth"
        elif name.startswith("wl"):
            info["type"] = "wifi"
        elif name.startswith("awdl"):
            info["type"] = "awdl"
        elif any(name.startswith(p) for p in ("utun","tun","ppp")):
            info["type"] = "vpn"
        elif name.startswith("lo"):
            info["type"] = "loopback"
        elif name.startswith("bridge"):
            info["type"] = "bridge"

        out2, _, _ = run(f"ifconfig {name}")
        m_ip4 = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out2)
        m_mask = re.search(r"netmask\s+(0x[0-9a-f]+)", out2)
        m_ip6 = re.search(r"inet6\s+([\da-f:]+)", out2)
        m_mac = re.search(r"ether\s+([\da-f:]+)", out2)
        m_mtu = re.search(r"mtu\s+(\d+)", out2)
        m_status = re.search(r"status:\s*(\w+)", out2)

        if m_ip4: info["ipv4"] = m_ip4.group(1)
        if m_ip6: info["ipv6"] = m_ip6.group(1)
        if m_mac: info["mac"] = m_mac.group(1)
        if m_mtu: info["mtu"] = int(m_mtu.group(1))
        if m_status: info["active"] = m_status.group(1) == "active"
        if m_mask:
            hex_mask = m_mask.group(1)[2:]
            info["netmask"] = ".".join(str(int(hex_mask[i:i+2], 16)) for i in range(0, 8, 2))

        if info["ipv4"] or info["ipv6"]:
            interfaces.append(info)
    return {"interfaces": interfaces, "total": len(interfaces)}


def q_step_connectivity():
    """步骤 2：互联网连通性"""
    sites = [
        ("baidu.com", "百度"), ("qq.com", "腾讯"),
        ("taobao.com", "淘宝"), ("github.com", "GitHub"), ("google.com", "Google"),
    ]
    results = []
    for domain, label in sites:
        out, _, rc = run(
            f"curl -sI --connect-timeout 5 --max-time 8 -o /dev/null -w '%{{http_code}} %{{time_connect}} %{{time_total}}' {domain}",
            timeout=10
        )
        parts = out.split()
        http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
        connect_time = float(parts[1]) * 1000 if len(parts) > 1 else 0
        total_time = float(parts[2]) * 1000 if len(parts) > 2 else 0
        reachable = 200 <= http_code < 400
        results.append({
            "domain": domain, "label": label,
            "reachable": reachable, "http_code": http_code,
            "connect_ms": round(connect_time, 1),
            "total_ms": round(total_time, 1)
        })
    return {"sites": results, "reachable_count": sum(1 for r in results if r["reachable"])}


def q_step_dns_perf():
    """步骤 3：DNS 解析性能"""
    domains = [
        ("baidu.com", "百度"), ("qcloud.com", "腾讯云"),
        ("github.com", "GitHub"), ("bilibili.com", "B站"), ("douyin.com", "抖音"),
    ]
    results = []
    for domain, label in domains:
        out, _, _ = run(f"dig {domain} +stats", timeout=10)
        m_time = re.search(r"Query time:\s*(\d+)\s*msec", out)
        m_server = re.search(r"SERVER:\s*(\S+)", out)
        query_ms = int(m_time.group(1)) if m_time else -1
        results.append({
            "domain": domain, "label": label,
            "query_ms": query_ms,
            "dns_server": m_server.group(1) if m_server else "?",
        })
    valid = [r["query_ms"] for r in results if r["query_ms"] > 0]
    avg_ms = round(sum(valid) / len(valid), 1) if valid else 0
    return {"results": results, "avg_ms": avg_ms}


def q_step_latency_matrix():
    """步骤 4：延迟矩阵"""
    targets = [
        ("114.114.114.114", "114 DNS", "北京"),
        ("101.226.4.6", "上海电信", "上海"),
        ("202.96.128.86", "广东电信", "广州"),
        ("1.1.1.1", "Cloudflare", "海外"),
        ("8.8.8.8", "Google DNS", "海外"),
    ]
    gw_out, _, _ = run("netstat -rn -f inet | grep default | head -1 | awk '{print $2}'")
    gw = gw_out.strip()
    if gw:
        targets.insert(0, (gw, "默认网关", "本地"))

    results = []
    for target, label, region in targets:
        out, _, _ = run(f"ping -c 5 -W 2000 {target}", timeout=12)
        m_rtt = re.search(r"round-trip min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
        m_loss = re.search(r"(\d+)\s+packets? transmitted.*?(\d+)\s+packets? received.*?([\d.]+)%\s+packet loss", out, re.DOTALL)
        sent, recv, loss_pct = 5, 0, 100.0
        if m_loss:
            sent, recv = int(m_loss.group(1)), int(m_loss.group(2))
            loss_pct = round(float(m_loss.group(3)), 1)
        if m_rtt:
            r = {
                "target": target, "label": label, "region": region,
                "avg_ms": round(float(m_rtt.group(2)), 1),
                "min_ms": round(float(m_rtt.group(1)), 1),
                "max_ms": round(float(m_rtt.group(3)), 1),
                "stddev_ms": round(float(m_rtt.group(4)), 1),
                "loss_pct": loss_pct, "sent": sent, "received": recv
            }
        else:
            r = {"target": target, "label": label, "region": region,
                 "avg_ms": 0, "min_ms": 0, "max_ms": 0, "stddev_ms": 0,
                 "loss_pct": 100.0, "sent": sent, "received": recv}
        results.append(r)

    reachable = [r for r in results if r["received"] > 0]
    overall_avg = round(sum(r["avg_ms"] for r in reachable) / len(reachable), 1) if reachable else 0
    return {"targets": results, "overall_avg_ms": overall_avg}


def q_step_packet_loss():
    """步骤 5：丢包率 & 抖动"""
    target = "223.5.5.5"
    out, _, _ = run(f"ping -c 50 -W 1000 {target}", timeout=55)
    m_loss = re.search(r"(\d+)\s+packets? transmitted.*?(\d+)\s+packets? received.*?([\d.]+)%\s+packet loss", out, re.DOTALL)
    m_rtt = re.search(r"round-trip min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m_loss and m_rtt:
        return {
            "target": target, "label": "阿里 DNS",
            "sent": int(m_loss.group(1)), "received": int(m_loss.group(2)),
            "loss_pct": round(float(m_loss.group(3)), 1),
            "avg_ms": round(float(m_rtt.group(2)), 1),
            "min_ms": round(float(m_rtt.group(1)), 1),
            "max_ms": round(float(m_rtt.group(3)), 1),
            "jitter_ms": round(float(m_rtt.group(4)), 1),
        }
    return {"target": target, "label": "阿里 DNS",
            "sent": 50, "received": 0, "loss_pct": 100.0,
            "avg_ms": 0, "min_ms": 0, "max_ms": 0, "jitter_ms": 0}


def q_step_bandwidth():
    """步骤 6：带宽估算"""
    urls = [
        "http://speedtest.tele2.net/10MB.zip",
        "http://ipv4.download.thinkbroadband.com/10MB.zip",
        "http://speedtest.ftp.otenet.gr/files/test10Mb.db",
    ]
    result = {"download_speed_mbps": 0, "bytes_downloaded": 0, "time_seconds": 0, "url": "", "error": None}
    for url in urls:
        out, _, _ = run(
            f"curl -s -o /dev/null -w '%{{speed_download}} %{{time_total}} %{{size_download}}' --max-time 10 '{url}'",
            timeout=15
        )
        parts = out.split()
        if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) > 1000:
            speed_bps = float(parts[0])
            time_s = float(parts[1])
            size_bytes = int(parts[2])
            mbps = round(speed_bps * 8 / 1_000_000, 2)
            result = {"download_speed_mbps": mbps, "bytes_downloaded": size_bytes,
                      "time_seconds": round(time_s, 1), "url": url, "error": None}
            break
        else:
            result["error"] = out
    return result


def q_step_ipv6():
    """步骤 7：IPv4/IPv6 双栈"""
    result = {"ipv4_public": None, "ipv6_public": None,
              "ipv4_available": False, "ipv6_available": False, "dual_stack": False}
    out, _, rc = run("curl -4 -s --connect-timeout 3 https://api-ipv4.ip.sb/ip", timeout=5)
    if rc == 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", out.strip()):
        result["ipv4_public"] = out.strip()
        result["ipv4_available"] = True
    out, _, rc = run("curl -6 -s --connect-timeout 3 https://api-ipv6.ip.sb/ip", timeout=5)
    if rc == 0 and ":" in out.strip():
        result["ipv6_public"] = out.strip()
        result["ipv6_available"] = True
    if not result["ipv6_available"]:
        try:
            socket.getaddrinfo("ip.sb", 443, socket.AF_INET6)
            result["ipv6_available"] = True
        except Exception:
            pass
    result["dual_stack"] = result["ipv4_available"] and result["ipv6_available"]
    return result


def q_step_score(data):
    """步骤 8：综合评分"""
    scores = {}
    details = []

    conn = data.get("connectivity", {})
    reached = conn.get("reachable_count", 0)
    conn_score = (reached / 5) * 20
    scores["connectivity"] = conn_score
    details.append(f"连通 {reached}/5 站点 → {conn_score:.1f}/20")

    matrix = data.get("latency_matrix", {})
    overall_avg = matrix.get("overall_avg_ms", 0)
    latency_score = max(0, (500 - overall_avg) / 400) * 25 if overall_avg > 0 else 0
    scores["latency"] = latency_score
    details.append(f"平均延迟 {overall_avg}ms → {latency_score:.1f}/25")

    pl = data.get("packet_loss", {})
    loss_pct = pl.get("loss_pct", 100)
    loss_score = max(0, (5 - loss_pct) / 5) * 20
    scores["packet_loss"] = loss_score
    details.append(f"丢包率 {loss_pct}% → {loss_score:.1f}/20")

    dns = data.get("dns_perf", {})
    dns_avg = dns.get("avg_ms", 0)
    dns_score = max(0, (300 - dns_avg) / 250) * 15 if dns_avg > 0 else 0
    scores["dns"] = dns_score
    details.append(f"DNS 平均 {dns_avg}ms → {dns_score:.1f}/15")

    bw = data.get("bandwidth", {})
    bw_mbps = bw.get("download_speed_mbps", 0)
    bw_score = min(bw_mbps / 100, 1) * 15
    scores["bandwidth"] = bw_score
    details.append(f"下载速率 {bw_mbps}Mbps → {bw_score:.1f}/15")

    ipv6 = data.get("ipv6", {})
    ipv4_ok = ipv6.get("ipv4_available", False)
    ipv6_ok = ipv6.get("ipv6_available", False)
    dual_score = (2.5 if ipv4_ok else 0) + (2.5 if ipv6_ok else 0)
    scores["dual_stack"] = dual_score
    ip_txt = "IPv4" if ipv4_ok else ""
    if ipv6_ok: ip_txt += ("+IPv6" if ip_txt else "IPv6")
    details.append(f"{ip_txt or '无公网IP'} → {dual_score:.1f}/5")

    total = sum(scores.values())
    if total >= 90: grade, desc = "A", "网络状况优秀，延迟低且稳定"
    elif total >= 75: grade, desc = "B", "网络状况良好，日常使用无压力"
    elif total >= 60: grade, desc = "C", "网络一般，部分指标有待改善"
    else: grade, desc = "D", "网络较差，建议排查问题"

    tips = []
    if conn_score < 15: tips.append("部分站点不可达，检查防火墙或代理设置")
    if latency_score < 15: tips.append("网络延迟偏高，检查路由器负载或更换 DNS")
    if loss_score < 15: tips.append(f"丢包率 {loss_pct}%，可能存在线路问题或无线干扰")
    if dns_score < 10: tips.append(f"DNS 解析缓慢 ({dns_avg}ms)，建议更换为 223.5.5.5")
    if bw_score < 10: tips.append(f"带宽不足 ({bw_mbps}Mbps)，检查网络套餐或网线/无线信道")
    if dual_score < 5: tips.append("仅支持 IPv4，IPv6 不可用")

    return {"total": round(total, 1), "grade": grade, "desc": desc,
            "scores": scores, "details": details, "tips": tips}


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


# ── SSE 流式：网络质量检测 ──────────────────────────────────────────

Q_STEPS = [
    ("interfaces", "网络接口扫描"),
    ("connectivity", "互联网连通性"),
    ("dns_perf", "DNS 解析性能"),
    ("latency_matrix", "延迟矩阵"),
    ("packet_loss", "丢包率 & 抖动"),
    ("bandwidth", "带宽估算"),
    ("ipv6", "IPv4/IPv6 双栈"),
    ("score", "综合评分"),
]


@app.route("/api/quality/stream")
def quality_stream():
    def generate():
        report = {}
        for i, (key, title) in enumerate(Q_STEPS):
            payload = {"step": i + 1, "total": len(Q_STEPS), "title": title, "key": key}
            yield f"event: progress\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            try:
                if key == "interfaces":
                    report["interfaces"] = q_step_interfaces()
                elif key == "connectivity":
                    report["connectivity"] = q_step_connectivity()
                elif key == "dns_perf":
                    report["dns_perf"] = q_step_dns_perf()
                elif key == "latency_matrix":
                    report["latency_matrix"] = q_step_latency_matrix()
                elif key == "packet_loss":
                    report["packet_loss"] = q_step_packet_loss()
                elif key == "bandwidth":
                    report["bandwidth"] = q_step_bandwidth()
                elif key == "ipv6":
                    report["ipv6"] = q_step_ipv6()
                elif key == "score":
                    report["score"] = q_step_score(report)
                yield f"event: step_done\ndata: {json.dumps({**payload, 'status': 'ok'}, ensure_ascii=False)}\n\n"
            except Exception as e:
                yield f"event: step_done\ndata: {json.dumps({**payload, 'status': 'error', 'error': str(e)}, ensure_ascii=False)}\n\n"
        yield f"event: complete\ndata: {json.dumps(report, ensure_ascii=False)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    print("🔍 网络链路检测服务启动: http://localhost:5099")
    app.run(host="127.0.0.1", port=5099, debug=False)
