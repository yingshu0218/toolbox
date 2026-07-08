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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import time

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── helpers ──────────────────────────────────────────────────────────

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def run_step_with_timeout(func, timeout_sec=30):
    """在线程中执行检测函数，超时则抛出 TimeoutError"""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout_sec)
        except FuturesTimeoutError:
            raise TimeoutError(f"步骤超时（>{timeout_sec}s）")


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
    # 检测系统代理/VPN 状态
    proxy = step_proxy_tunnel()
    has_proxy = bool(proxy.get("system_proxy")) or bool(proxy.get("env_proxy")) or bool(proxy.get("tunnel_interfaces"))

    results = []
    for domain, label in sites:
        # 第一次尝试：标准超时
        out, _, rc = run(
            f"curl -sI --connect-timeout 5 --max-time 8 -o /dev/null -w '%{{http_code}} %{{time_connect}} %{{time_total}}' {domain}",
            timeout=10
        )
        parts = out.split()
        http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
        connect_time = float(parts[1]) * 1000 if len(parts) > 1 else 0
        total_time = float(parts[2]) * 1000 if len(parts) > 2 else 0
        reachable = 200 <= http_code < 400

        # 如果失败，重试一次（更长超时，某些代理/VPN 连接较慢）
        if not reachable:
            out, _, rc = run(
                f"curl -sI --connect-timeout 10 --max-time 15 -o /dev/null -w '%{{http_code}} %{{time_connect}} %{{time_total}}' {domain}",
                timeout=20
            )
            parts = out.split()
            http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
            connect_time = float(parts[1]) * 1000 if len(parts) > 1 else 0
            total_time = float(parts[2]) * 1000 if len(parts) > 2 else 0
            reachable = 200 <= http_code < 400

        # 如果系统有代理/VPN 且直连失败，标记为 VPN 可达（用户声明通过代理可访问）
        vpn_reachable = False
        if not reachable and has_proxy:
            vpn_reachable = True

        results.append({
            "domain": domain, "label": label,
            "reachable": reachable, "vpn_reachable": vpn_reachable,
            "http_code": http_code,
            "connect_ms": round(connect_time, 1),
            "total_ms": round(total_time, 1)
        })

    # 可达计数：直连可达 + VPN 可达（代理兜底）
    effective_count = sum(1 for r in results if r["reachable"] or r["vpn_reachable"])
    return {"sites": results, "reachable_count": effective_count, "has_proxy": has_proxy}


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

        unreliable = False
        avg_ms = min_ms = max_ms = stddev_ms = 0
        if m_rtt:
            avg_ms = round(float(m_rtt.group(2)), 1)
            min_ms = round(float(m_rtt.group(1)), 1)
            max_ms = round(float(m_rtt.group(3)), 1)
            stddev_ms = round(float(m_rtt.group(4)), 1)

            # 海外目标延迟 < 1ms 不合理，可能是 ICMP 被代理/防火墙拦截或伪造
            if avg_ms < 1.0 and region != "本地":
                unreliable = True
                # 用 TCP 连接延迟交叉验证
                tcp_out, _, _ = run(
                    f"curl -s -o /dev/null -w '%{{time_connect}}' --connect-timeout 3 --max-time 5 http://{target}",
                    timeout=6
                )
                try:
                    tcp_ms = float(tcp_out) * 1000
                    if tcp_ms > 1:
                        avg_ms = round(tcp_ms, 1)
                        min_ms = avg_ms
                        max_ms = avg_ms
                        stddev_ms = 0
                except Exception:
                    pass

        results.append({
            "target": target, "label": label, "region": region,
            "avg_ms": avg_ms, "min_ms": min_ms, "max_ms": max_ms,
            "stddev_ms": stddev_ms, "loss_pct": loss_pct,
            "sent": sent, "received": recv, "unreliable": unreliable
        })

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
    """步骤 6：带宽估算

    渐进式测速：5MB → 10MB，取最快的一次完整下载。
    总时限控制在 18 秒内，与 run_step_with_timeout(20s) 匹配。
    """
    sources = [
        # 5MB 快速测试（两个 CDN 任一成功即停止）
        {"url": "http://cachefly.cachefly.net/5mb.test", "size": 5_242_880, "max_time": 8, "timeout": 10},
        {"url": "http://speedtest.tele2.net/5MB.zip",  "size": 5_242_880, "max_time": 8, "timeout": 10},
    ]

    result = {
        "download_speed_mbps": 0, "bytes_downloaded": 0, "time_seconds": 0,
        "url": "", "error": None, "incomplete": False, "expected_size": 0
    }
    errors = []

    for src in sources:
        url = src["url"]
        expected_size = src["size"]
        max_time = src["max_time"]
        cmd_timeout = src["timeout"]

        out, stderr, rc = run(
            f"curl -s -o /dev/null -w '%{{speed_download}} %{{time_total}} %{{size_download}}' "
            f"--max-time {max_time} --connect-timeout 5 '{url}'",
            timeout=cmd_timeout
        )
        parts = out.split()
        if len(parts) >= 3 and parts[2].isdigit():
            size_bytes = int(parts[2])
            if size_bytes > 1000:
                speed_bps = float(parts[0])
                time_s = float(parts[1])
                # 下载量必须 >= 预期大小的 30%，否则视为测速中断
                if size_bytes >= expected_size * 0.3:
                    mbps = round(speed_bps * 8 / 1_000_000, 2)
                    result = {
                        "download_speed_mbps": mbps,
                        "bytes_downloaded": size_bytes,
                        "time_seconds": round(time_s, 1),
                        "url": url,
                        "error": None,
                        "incomplete": False,
                        "expected_size": expected_size
                    }
                    break
                else:
                    # 下载量不足，记录但继续尝试其他源
                    errors.append(
                        f"下载中断: {size_bytes/1024/1024:.1f}/"
                        f"{expected_size/1024/1024:.0f}MB"
                    )
                    result["incomplete"] = True
                    result["bytes_downloaded"] = size_bytes
                    result["time_seconds"] = round(time_s, 1)
                    result["url"] = url
                    result["expected_size"] = expected_size
                    continue
            # size_bytes == 0: curl 超时或连接失败
            errors.append(f"{url.split('/')[2]}: "
                         f"{'超时' if 'timeout' in stderr.lower() else '无法连接'}")
        elif stderr:
            errors.append(f"curl: {stderr[:80]}")
        elif not out:
            errors.append("网络不通，无法连接测速源")

    # 汇总错误信息
    if result["download_speed_mbps"] == 0:
        if result["incomplete"]:
            result["error"] = "; ".join(errors[:2]) if errors else "下载数据不足"
        else:
            result["error"] = "; ".join(errors[:2]) if errors else "所有测速源均不可用"

    return result


def q_step_router():
    """步骤 7：本地路由器检测"""
    result = {
        "gateway_ip": None, "gateway_mac": None, "manufacturer": None,
        "model": None, "router_name": None, "router_name_short": None,
        "connection_type": None, "connection_type_label": None,
        "link_speed_mbps": None,
        "ping_avg_ms": 0, "ping_min_ms": 0, "ping_max_ms": 0,
        "ping_loss_pct": 0, "web_reachable": False, "admin_page": None,
        "wifi_standard": None, "signal_estimate": None, "channel": None,
        "ssid": None, "rssi": None,
        "detected": False, "error": None
    }

    # 1. 获取默认网关
    gw_out, _, _ = run("netstat -rn -f inet | grep default | head -1 | awk '{print $2}'")
    gw = gw_out.strip()
    if not gw:
        out2, _, _ = run("route -n get default 2>/dev/null | grep gateway | awk '{print $2}'")
        gw = out2.strip()
    if not gw:
        result["error"] = "未检测到默认网关"
        return result
    result["gateway_ip"] = gw
    result["detected"] = True

    # 2. ARP 获取 MAC 地址
    arp_out, _, _ = run(f"arp -n {gw} 2>/dev/null | tail -1")
    m_mac = re.search(r"([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2})", arp_out, re.IGNORECASE)
    if m_mac:
        result["gateway_mac"] = m_mac.group(1).lower()

    # 3. OUI 厂商识别（常见路由器厂商 MAC 前缀）
    if result["gateway_mac"]:
        oui = result["gateway_mac"][:8].upper()
        oui_map = {
            "00:1A:70": "Cisco", "00:1B:63": "Cisco", "F8:1E:DF": "TP-Link",
            "C8:3A:35": "Tenda", "00:0C:43": "Ralink", "B0:95:8E": "TP-Link",
            "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link", "10:FE:ED": "TP-Link",
            "64:66:B3": "Tenda", "00:25:86": "Tenda", "34:2C:C4": "Netgear",
            "04:A1:51": "Netgear", "00:23:69": "Cisco/Linksys", "C0:56:27": "Belkin",
            "D8:47:32": "Xiaomi", "28:6C:07": "Xiaomi", "D4:EE:07": "Xiaomi",
            "78:11:DC": "Xiaomi", "34:CE:00": "Xiaomi", "FC:AA:14": "Gigabyte",
            "00:24:01": "D-Link", "BC:A8:A6": "D-Link", "14:D6:4D": "D-Link",
            "00:22:B0": "D-Link", "00:1E:58": "D-Link", "00:1B:11": "D-Link",
            "00:11:95": "D-Link", "00:90:4C": "Epigram", "00:03:52": "Asus",
            "38:60:77": "Asus", "48:22:54": "Asus", "54:A0:50": "Asus",
            "04:D4:C4": "Asus", "00:90:A2": "CyberTAN", "00:08:A1": "Minolta/Qpcom",
            "00:25:9E": "Huawei", "00:18:82": "Huawei", "48:46:FB": "Huawei",
            "00:27:19": "Tenda/Mercury", "D8:0D:17": "Philips",
            "00:1F:FB": "Zyxel", "24:1C:04": "Nokia",
        }
        # try full OUI first, then first 6 chars
        result["manufacturer"] = oui_map.get(oui) or oui_map.get(oui[:8])

    # 4. Ping 路由器测延迟
    ping_out, _, _ = run(f"ping -c 10 -W 1000 {gw}", timeout=12)
    m_rtt = re.search(r"min/avg/max/(m?dev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", ping_out)
    if m_rtt:
        result["ping_min_ms"] = round(float(m_rtt.group(2)), 1)
        result["ping_avg_ms"] = round(float(m_rtt.group(3)), 1)
        result["ping_max_ms"] = round(float(m_rtt.group(4)), 1)
    m_loss = re.search(r"(\d+)\s+packets? transmitted.*?(\d+)\s+packets? received.*?([\d.]+)%", ping_out, re.DOTALL)
    if m_loss:
        result["ping_loss_pct"] = round(float(m_loss.group(3)), 1)

    # 5. 尝试探测路由器 Web 管理页面
    for port in [80, 443]:
        curl_out, _, rc = run(
            f"curl -sk --connect-timeout 3 --max-time 4 -o /dev/null -w '%{{http_code}}' 'http://{gw}:{port}' 2>/dev/null",
            timeout=5
        )
        if curl_out.strip().isdigit() and int(curl_out.strip()) > 0:
            result["web_reachable"] = True
            result["admin_page"] = f"http://{gw}:{port}"
            break

    # 6. 尝试从管理页面提取型号（抓 title）
    if result["web_reachable"]:
        title_out, _, _ = run(
            f"curl -sk --connect-timeout 3 --max-time 4 '{result['admin_page']}' 2>/dev/null | grep -oP '<title>\\K[^<]+' | head -1",
            timeout=5
        )
        if title_out.strip():
            title = title_out.strip()
            # 常见管理页面标题包含型号
            known_models = {
                "TP-LINK": "TP-Link", "Tenda": "Tenda", "Xiaomi": "Xiaomi",
                "MI WIFI": "Xiaomi MiWiFi", "NETGEAR": "Netgear",
                "D-Link": "D-Link", "ASUS": "Asus", "HUAWEI": "Huawei",
                "Linksys": "Linksys", "DD-WRT": "DD-WRT (第三方固件)",
                "OpenWrt": "OpenWrt (第三方固件)", "Padavan": "Padavan (第三方固件)",
            }
            for key, val in known_models.items():
                if key.upper() in title.upper():
                    result["model"] = val
                    break
            if not result["model"]:
                result["model"] = title[:60]

    # 5.5 构建路由友好名称
    name_parts = []
    if result["manufacturer"]:
        name_parts.append(result["manufacturer"])
    if result["model"]:
        # 避免重复（如 manufacturer 已包含 model 的简称）
        if not result["model"].lower() in " ".join(name_parts).lower():
            name_parts.append(result["model"])
    result["router_name"] = " ".join(name_parts) if name_parts else "未知路由器"
    if result.get("ssid"):
        result["router_name_short"] = result["router_name"] + " (" + result["ssid"] + ")"
    else:
        result["router_name_short"] = result["router_name"]

    # 7. 检测 WiFi 标准和信号（仅 macOS）
    iface_out, _, _ = run(f"route -n get default 2>/dev/null | grep interface | awk '{{print $2}}'")
    iface = iface_out.strip()
    if iface and iface.startswith("en"):
        # macOS: 用 airport 或 networksetup 获取 WiFi 信息
        air_out, _, _ = run(
            f"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null",
            timeout=5
        )
        if air_out:
            m_ssid = re.search(r"\s*SSID:\s*(.+)", air_out)
            m_bssid = re.search(r"\s*BSSID:\s*([\da-f:]+)", air_out, re.IGNORECASE)
            m_ch = re.search(r"\s*channel:\s*(\d+)", air_out)
            m_phy = re.search(r"\s*PHY mode:\s*(.+)", air_out)
            m_rate = re.search(r"\s*lastTxRate:\s*(\d+)", air_out)
            m_rssi = re.search(r"\s*agrCtlRSSI:\s*(-?\d+)", air_out)

            if m_ssid:
                result["ssid"] = m_ssid.group(1).strip()
            if m_ch:
                result["channel"] = int(m_ch.group(1))
            if m_phy:
                raw_phy = m_phy.group(1).strip()
                std_map = {"802.11ac": "WiFi 5", "802.11ax": "WiFi 6",
                           "802.11n": "WiFi 4", "802.11a": "WiFi 2",
                           "802.11b": "WiFi 1", "802.11g": "WiFi 3",
                           "802.11be": "WiFi 7"}
                std = std_map.get(raw_phy, raw_phy)
                # 判断频段
                if result.get("channel"):
                    ch = result["channel"]
                    if 1 <= ch <= 14:
                        band = "2.4GHz"
                    elif 36 <= ch <= 165:
                        band = "5GHz"
                    else:
                        band = "6GHz"
                else:
                    band = "未知"
                result["wifi_standard"] = std + " (" + raw_phy + ")" if std != raw_phy else raw_phy
                result["connection_type"] = std + " (" + band + ")"
                result["connection_type_label"] = "WiFi"
            if m_rate:
                result["link_speed_mbps"] = int(m_rate.group(1))
            if m_rssi:
                rssi = int(m_rssi.group(1))
                if rssi >= -50: result["signal_estimate"] = "优秀"
                elif rssi >= -65: result["signal_estimate"] = "良好"
                elif rssi >= -75: result["signal_estimate"] = "一般"
                else: result["signal_estimate"] = "弱"
                result["rssi"] = rssi

        # airport 未识别到 WiFi → 尝试有线检测
        if not result.get("connection_type") and iface:
            out, _, _ = run(f"ifconfig {iface} 2>/dev/null")
            if out:
                m_media = re.search(r"media:.*?((\d+(?:\.\d+)?)(G?)base[TX])", out)
                if m_media:
                    speed_val = m_media.group(2)
                    is_g = m_media.group(3)
                    if is_g:
                        link_speed = int(float(speed_val) * 1000)
                    else:
                        link_speed = int(speed_val)
                    result["connection_type"] = f"有线 ({link_speed}Mbps)"
                    result["connection_type_label"] = "有线"
                    result["link_speed_mbps"] = link_speed

    # 8. 路由器带宽评估（通过不同包大小 ping 估算）
    pkt_64, _, _ = run(f"ping -c 5 -s 64 -W 1000 {gw}", timeout=8)
    pkt_1472, _, _ = run(f"ping -c 5 -s 1472 -W 1000 {gw}", timeout=8)

    avg_64 = avg_1472 = 0
    m64 = re.search(r"avg[/=]\s*([\d.]+)", pkt_64)
    m1472 = re.search(r"avg[/=]\s*([\d.]+)", pkt_1472)
    if m64: avg_64 = float(m64.group(1))
    if m1472: avg_1472 = float(m1472.group(1))

    if avg_64 > 0 and avg_1472 > avg_64:
        diff_ms = avg_1472 - avg_64
        extra_bytes = 1472 - 64
        # 往返额外数据量: extra_bytes * 8 bits * 2 (round-trip) → estimated bps
        estimated_bps = (extra_bytes * 8 * 2) / (diff_ms / 1000)
        result["estimated_bandwidth_mbps"] = round(estimated_bps / 1_000_000, 1)
    elif avg_64 > 0:
        # fallback: just use 64-byte ping
        result["ping_64_ms"] = round(avg_64, 1)

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
    """步骤 9：综合评分"""
    scores = {}
    details = []

    conn = data.get("connectivity", {})
    reached = conn.get("reachable_count", 0)
    conn_score = (reached / 5) * 15
    scores["connectivity"] = conn_score
    details.append(f"连通 {reached}/5 站点 → {conn_score:.1f}/15")

    matrix = data.get("latency_matrix", {})
    overall_avg = matrix.get("overall_avg_ms", 0)
    latency_score = max(0, (500 - overall_avg) / 400) * 20 if overall_avg > 0 else 0
    scores["latency"] = latency_score
    details.append(f"平均延迟 {overall_avg}ms → {latency_score:.1f}/20")

    pl = data.get("packet_loss", {})
    loss_pct = pl.get("loss_pct", 100)
    loss_score = max(0, (5 - loss_pct) / 5) * 18
    scores["packet_loss"] = loss_score
    details.append(f"丢包率 {loss_pct}% → {loss_score:.1f}/18")

    dns = data.get("dns_perf", {})
    dns_avg = dns.get("avg_ms", 0)
    dns_score = max(0, (300 - dns_avg) / 250) * 10 if dns_avg > 0 else 0
    scores["dns"] = dns_score
    details.append(f"DNS 平均 {dns_avg}ms → {dns_score:.1f}/10")

    bw = data.get("bandwidth", {})
    bw_mbps = bw.get("download_speed_mbps", 0)
    bw_score = min(bw_mbps / 100, 1) * 10
    scores["bandwidth"] = bw_score
    details.append(f"下载速率 {bw_mbps}Mbps → {bw_score:.1f}/10")

    router = data.get("router", {})
    router_score = 0
    if router.get("detected"):
        router_score += 5  # 网关可达
        ping_avg = router.get("ping_avg_ms", 999)
        if ping_avg < 3: router_score += 5
        elif ping_avg < 10: router_score += 3
        elif ping_avg < 30: router_score += 1
        if router.get("manufacturer") or router.get("model"):
            router_score += 2
        if router.get("wifi_standard"):
            router_score += 3
        if router.get("signal_estimate") in ("优秀", "良好"):
            router_score += 3
        elif router.get("signal_estimate") == "一般":
            router_score += 1
        est_bw = router.get("estimated_bandwidth_mbps", 0)
        if est_bw > 50: router_score += 4
        elif est_bw > 10: router_score += 2
    scores["router"] = router_score
    details.append(f"路由器 {'已检测' if router.get('detected') else '未检测'} → {router_score:.1f}/22")

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
    if conn_score < 12: tips.append("部分站点不可达，检查防火墙或代理设置")
    if latency_score < 12: tips.append("网络延迟偏高，检查路由器负载或更换 DNS")
    if loss_score < 12: tips.append(f"丢包率 {loss_pct}%，可能存在线路问题或无线干扰")
    if dns_score < 6: tips.append(f"DNS 解析缓慢 ({dns_avg}ms)，建议更换为 223.5.5.5")
    if bw_score < 6: tips.append(f"带宽不足 ({bw_mbps}Mbps)，检查网络套餐或网线/无线信道")
    if dual_score < 5: tips.append("仅支持 IPv4，IPv6 不可用")
    if router_score < 10: tips.append("路由器延迟偏高或信息不完整，建议检查路由器状态")

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
        ("local", "本机出口/默认路由", 10),
        ("dns", "DNS 配置", 10),
        ("resolution", "域名解析 (dig)", 15),
        ("ip_info", "IP 归属 (whois)", 20),
        ("routing", "路由路径 (route)", 10),
        ("tls", "TLS/HTTPS 连接", 20),
        ("proxy_tunnel", "代理 & 隧道", 10),
        ("traceroute", "跳转路径重建", 30),
    ]
    total = len(steps_meta)

    def generate():
        overall_start = time.time()
        report = {"domain": domain}
        ips = []

        for i, (key, title, timeout_sec) in enumerate(steps_meta):
            step_start = time.time()
            payload = {"step": i + 1, "total": total, "title": title, "key": key,
                       "elapsed_ms": int((time.time() - overall_start) * 1000)}
            yield f"event: progress\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

            try:
                if key == "local":
                    report["local"] = run_step_with_timeout(step_local_egress, timeout_sec)
                elif key == "dns":
                    report["dns"] = run_step_with_timeout(step_dns_config, timeout_sec)
                elif key == "resolution":
                    report["resolution"] = run_step_with_timeout(lambda: step_dns_resolve(domain), timeout_sec)
                    ips = report["resolution"].get("a_records", [])
                elif key == "ip_info":
                    report["ip_info"] = run_step_with_timeout(lambda: step_ip_whois(ips), timeout_sec)
                elif key == "routing":
                    report["routing"] = run_step_with_timeout(lambda: step_routing(ips), timeout_sec)
                elif key == "tls":
                    report["tls"] = run_step_with_timeout(lambda: step_tls_check(domain), timeout_sec)
                elif key == "proxy_tunnel":
                    report["proxy_tunnel"] = run_step_with_timeout(step_proxy_tunnel, timeout_sec)
                elif key == "traceroute":
                    report["traceroute"] = run_step_with_timeout(lambda: step_traceroute(domain), timeout_sec)

                step_elapsed = int((time.time() - step_start) * 1000)
                done_payload = {**payload, "status": "ok", "step_elapsed_ms": step_elapsed,
                                "elapsed_ms": int((time.time() - overall_start) * 1000)}
                yield f"event: step_done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"
            except TimeoutError as e:
                step_elapsed = int((time.time() - step_start) * 1000)
                done_payload = {**payload, "status": "timeout", "error": str(e), "step_elapsed_ms": step_elapsed,
                                "elapsed_ms": int((time.time() - overall_start) * 1000)}
                yield f"event: step_done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"
            except Exception as e:
                step_elapsed = int((time.time() - step_start) * 1000)
                done_payload = {**payload, "status": "error", "error": str(e), "step_elapsed_ms": step_elapsed,
                                "elapsed_ms": int((time.time() - overall_start) * 1000)}
                yield f"event: step_done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"

        total_elapsed_ms = int((time.time() - overall_start) * 1000)
        report["_meta"] = {"total_elapsed_ms": total_elapsed_ms}
        yield f"event: complete\ndata: {json.dumps(report, ensure_ascii=False)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ── SSE 流式：网络质量检测 ──────────────────────────────────────────

Q_STEPS = [
    ("interfaces", "网络接口扫描", 10),
    ("connectivity", "互联网连通性", 25),
    ("dns_perf", "DNS 解析性能", 15),
    ("latency_matrix", "延迟矩阵", 30),
    ("packet_loss", "丢包率 & 抖动", 30),
    ("bandwidth", "带宽估算", 20),
    ("router", "本地路由器检测", 25),
    ("ipv6", "IPv4/IPv6 双栈", 15),
    ("score", "综合评分", 5),
]


@app.route("/api/quality/stream")
def quality_stream():
    def generate():
        overall_start = time.time()
        report = {}
        for i, (key, title, timeout_sec) in enumerate(Q_STEPS):
            step_start = time.time()
            payload = {"step": i + 1, "total": len(Q_STEPS), "title": title, "key": key,
                       "elapsed_ms": int((time.time() - overall_start) * 1000)}
            yield f"event: progress\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            try:
                if key == "interfaces":
                    report["interfaces"] = run_step_with_timeout(q_step_interfaces, timeout_sec)
                elif key == "connectivity":
                    report["connectivity"] = run_step_with_timeout(q_step_connectivity, timeout_sec)
                elif key == "dns_perf":
                    report["dns_perf"] = run_step_with_timeout(q_step_dns_perf, timeout_sec)
                elif key == "latency_matrix":
                    report["latency_matrix"] = run_step_with_timeout(q_step_latency_matrix, timeout_sec)
                elif key == "packet_loss":
                    report["packet_loss"] = run_step_with_timeout(q_step_packet_loss, timeout_sec)
                elif key == "bandwidth":
                    report["bandwidth"] = run_step_with_timeout(q_step_bandwidth, timeout_sec)
                elif key == "router":
                    report["router"] = run_step_with_timeout(q_step_router, timeout_sec)
                elif key == "ipv6":
                    report["ipv6"] = run_step_with_timeout(q_step_ipv6, timeout_sec)
                elif key == "score":
                    report["score"] = run_step_with_timeout(lambda: q_step_score(report), timeout_sec)
                step_elapsed = int((time.time() - step_start) * 1000)
                yield f"event: step_done\ndata: {json.dumps({**payload, 'status': 'ok', 'step_elapsed_ms': step_elapsed, 'elapsed_ms': int((time.time() - overall_start) * 1000)}, ensure_ascii=False)}\n\n"
            except TimeoutError as e:
                step_elapsed = int((time.time() - step_start) * 1000)
                yield f"event: step_done\ndata: {json.dumps({**payload, 'status': 'timeout', 'error': str(e), 'step_elapsed_ms': step_elapsed, 'elapsed_ms': int((time.time() - overall_start) * 1000)}, ensure_ascii=False)}\n\n"
            except Exception as e:
                step_elapsed = int((time.time() - step_start) * 1000)
                yield f"event: step_done\ndata: {json.dumps({**payload, 'status': 'error', 'error': str(e), 'step_elapsed_ms': step_elapsed, 'elapsed_ms': int((time.time() - overall_start) * 1000)}, ensure_ascii=False)}\n\n"
        total_elapsed_ms = int((time.time() - overall_start) * 1000)
        report["_meta"] = {"total_elapsed_ms": total_elapsed_ms}
        yield f"event: complete\ndata: {json.dumps(report, ensure_ascii=False)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    print("🔍 网络链路检测服务启动: http://localhost:5099")
    app.run(host="127.0.0.1", port=5099, debug=False)
