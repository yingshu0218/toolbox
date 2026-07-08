#!/usr/bin/env python3
"""
网络质量检测工具 — Flask 后端 (SSR 版)
GET  /  → 空页面
POST /  → 运行八步检测，SSR 返回结果
"""
import subprocess
import re
import json
import socket
import math
import time
from flask import Flask, request, render_template, Response, stream_with_context

app = Flask(__name__)


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


# ── 步骤 1：网络接口扫描 ──────────────────────────────────────────────

def step_interface_scan():
    interfaces = []
    out, _, _ = run("ifconfig -l")
    iface_names = out.split()
    hw_out, _, _ = run("networksetup -listallhardwareports")

    # 解析 networksetup 的端口名称映射
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
            "mac": None, "mtu": None, "active": False,
            "type": "other"
        }
        # 接口类型
        if name.startswith("en") and not name.startswith("en") == False:
            info["type"] = "eth"
        elif name.startswith("wl"):
            info["type"] = "wifi"
        elif name.startswith("awdl"):
            info["type"] = "awdl"
        elif name.startswith("utun") or name.startswith("tun") or name.startswith("ppp"):
            info["type"] = "vpn"
        elif name.startswith("lo"):
            info["type"] = "loopback"
        elif name.startswith("bridge"):
            info["type"] = "bridge"
        elif name.startswith("llw"):
            info["type"] = "other"

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


# ── 步骤 2：互联网连通性 ──────────────────────────────────────────────

def step_connectivity():
    sites = [
        ("baidu.com", "百度"),
        ("qq.com", "腾讯"),
        ("taobao.com", "淘宝"),
        ("github.com", "GitHub"),
        ("google.com", "Google"),
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


# ── 步骤 3：DNS 解析性能 ──────────────────────────────────────────────

def step_dns_perf():
    domains = [
        ("baidu.com", "百度"),
        ("qcloud.com", "腾讯云"),
        ("github.com", "GitHub"),
        ("bilibili.com", "B站"),
        ("douyin.com", "抖音"),
    ]
    results = []
    for domain, label in domains:
        out, _, _ = run(f"dig {domain} +stats", timeout=10)
        m_time = re.search(r"Query time:\s*(\d+)\s*msec", out)
        m_server = re.search(r"SERVER:\s*(\S+)", out)
        m_size = re.search(r"MSG SIZE.*rcvd:\s*(\d+)", out)
        query_ms = int(m_time.group(1)) if m_time else -1
        results.append({
            "domain": domain, "label": label,
            "query_ms": query_ms,
            "dns_server": m_server.group(1) if m_server else "?",
            "msg_size": int(m_size.group(1)) if m_size else 0
        })
    valid = [r["query_ms"] for r in results if r["query_ms"] > 0]
    avg_ms = round(sum(valid) / len(valid), 1) if valid else 0
    return {"results": results, "avg_ms": avg_ms}


# ── 步骤 4：延迟矩阵 ──────────────────────────────────────────────────

def step_latency_matrix():
    targets = [
        ("114.114.114.114", "114 DNS", "北京"),
        ("101.226.4.6", "上海电信 DNS", "上海"),
        ("202.96.128.86", "广东电信 DNS", "广州"),
        ("1.1.1.1", "Cloudflare", "海外"),
        ("8.8.8.8", "Google DNS", "海外"),
    ]
    # 获取本地网关
    gw_out, _, _ = run("netstat -rn -f inet | grep default | head -1 | awk '{print $2}'")
    gw = gw_out.strip()
    if gw:
        targets.insert(0, (gw, "默认网关", "本地"))

    results = []
    for target, label, region in targets:
        out, _, _ = run(f"ping -c 5 -W 2000 {target}", timeout=12)
        m_stats = re.search(r"(\d+)\s+packets? transmitted.*?(\d+)\s+packets? received.*?([\d.]+)%\s+packet loss", out, re.DOTALL)
        m_rtt = re.search(r"round-trip min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
        loss_pct = 100.0
        if m_stats:
            sent, recv = int(m_stats.group(1)), int(m_stats.group(2))
            loss_pct = round(float(m_stats.group(3)), 1)
        else:
            sent, recv = 5, 0
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
            r = {
                "target": target, "label": label, "region": region,
                "avg_ms": 0, "min_ms": 0, "max_ms": 0, "stddev_ms": 0,
                "loss_pct": 100.0, "sent": sent, "received": recv
            }
        results.append(r)

    # 取所有可达目标的平均延迟
    reachable = [r for r in results if r["received"] > 0]
    overall_avg = round(sum(r["avg_ms"] for r in reachable) / len(reachable), 1) if reachable else 0
    return {"targets": results, "overall_avg_ms": overall_avg}


# ── 步骤 5：丢包率 & 抖动 ─────────────────────────────────────────────

def step_packet_loss():
    target = "223.5.5.5"
    out, _, _ = run(f"ping -c 50 -W 1000 {target}", timeout=55)
    m_stats = re.search(r"(\d+)\s+packets? transmitted.*?(\d+)\s+packets? received.*?([\d.]+)%\s+packet loss", out, re.DOTALL)
    m_rtt = re.search(r"round-trip min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m_stats and m_rtt:
        result = {
            "target": target, "label": "阿里 DNS",
            "sent": int(m_stats.group(1)), "received": int(m_stats.group(2)),
            "loss_pct": round(float(m_stats.group(3)), 1),
            "avg_ms": round(float(m_rtt.group(2)), 1),
            "min_ms": round(float(m_rtt.group(1)), 1),
            "max_ms": round(float(m_rtt.group(3)), 1),
            "jitter_ms": round(float(m_rtt.group(4)), 1),
        }
    else:
        result = {
            "target": target, "label": "阿里 DNS",
            "sent": 50, "received": 0, "loss_pct": 100.0,
            "avg_ms": 0, "min_ms": 0, "max_ms": 0, "jitter_ms": 0,
        }
    return result


# ── 步骤 6：带宽估算 ──────────────────────────────────────────────────

def step_bandwidth_test():
    # 优先用国内 CDN，备选多个
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
            result = {
                "download_speed_mbps": mbps,
                "bytes_downloaded": size_bytes,
                "time_seconds": round(time_s, 1),
                "url": url,
                "error": None
            }
            break
        else:
            result["error"] = out
    return result


# ── 步骤 7：IPv4/IPv6 双栈 ────────────────────────────────────────────

def step_ipv6_check():
    result = {
        "ipv4_public": None, "ipv6_public": None,
        "ipv4_available": False, "ipv6_available": False, "dual_stack": False
    }
    # IPv4
    out, _, rc = run("curl -4 -s --connect-timeout 3 https://api-ipv4.ip.sb/ip", timeout=5)
    if rc == 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", out.strip()):
        result["ipv4_public"] = out.strip()
        result["ipv4_available"] = True
    # IPv6
    out, _, rc = run("curl -6 -s --connect-timeout 3 https://api-ipv6.ip.sb/ip", timeout=5)
    if rc == 0 and ":" in out.strip():
        result["ipv6_public"] = out.strip()
        result["ipv6_available"] = True
    # 系统级检测
    if not result["ipv6_available"]:
        try:
            socket.getaddrinfo("ip.sb", 443, socket.AF_INET6)
            result["ipv6_available"] = True
        except Exception:
            pass
    result["dual_stack"] = result["ipv4_available"] and result["ipv6_available"]
    return result


# ── 步骤 8：综合评分 ──────────────────────────────────────────────────

def step_overall_score(data):
    """基于前 7 步的检测数据计算综合评分"""
    scores = {}
    details = []

    # 1. 连通性 (20%)
    conn = data.get("connectivity", {})
    reached = conn.get("reachable_count", 0)
    conn_score = (reached / 5) * 20
    scores["connectivity"] = conn_score
    details.append(f"连通 {reached}/5 个站点 → {conn_score:.1f}/20")

    # 2. 延迟 (25%) — 基于延迟矩阵所有可达目标的平均延迟
    matrix = data.get("latency_matrix", {})
    overall_avg = matrix.get("overall_avg_ms", 0)
    if overall_avg > 0:
        latency_score = max(0, (500 - overall_avg) / 400) * 25
    else:
        latency_score = 0
    scores["latency"] = latency_score
    details.append(f"平均延迟 {overall_avg}ms → {latency_score:.1f}/25")

    # 3. 丢包率 (20%)
    pl = data.get("packet_loss", {})
    loss_pct = pl.get("loss_pct", 100)
    loss_score = max(0, (5 - loss_pct) / 5) * 20
    scores["packet_loss"] = loss_score
    details.append(f"丢包率 {loss_pct}% → {loss_score:.1f}/20")

    # 4. DNS 性能 (15%)
    dns = data.get("dns_perf", {})
    dns_avg = dns.get("avg_ms", 0)
    if dns_avg > 0:
        dns_score = max(0, (300 - dns_avg) / 250) * 15
    else:
        dns_score = 0
    scores["dns"] = dns_score
    details.append(f"DNS 平均 {dns_avg}ms → {dns_score:.1f}/15")

    # 5. 带宽 (15%)
    bw = data.get("bandwidth", {})
    bw_mbps = bw.get("download_speed_mbps", 0)
    bw_score = min(bw_mbps / 100, 1) * 15
    scores["bandwidth"] = bw_score
    details.append(f"下载速率 {bw_mbps}Mbps → {bw_score:.1f}/15")

    # 6. 双栈 (5%)
    ipv6 = data.get("ipv6", {})
    ipv4_ok = ipv6.get("ipv4_available", False)
    ipv6_ok = ipv6.get("ipv6_available", False)
    dual_score = (2.5 if ipv4_ok else 0) + (2.5 if ipv6_ok else 0)
    scores["dual_stack"] = dual_score
    ip_txt = "IPv4" if ipv4_ok else ""
    if ipv6_ok: ip_txt += ("+IPv6" if ip_txt else "IPv6")
    details.append(f"{ip_txt or '无公网IP'} → {dual_score:.1f}/5")

    total = sum(scores.values())
    if total >= 90:
        grade = "A"
        desc = "网络状况优秀，延迟低且稳定"
    elif total >= 75:
        grade = "B"
        desc = "网络状况良好，日常使用无压力"
    elif total >= 60:
        grade = "C"
        desc = "网络一般，部分指标有待改善"
    else:
        grade = "D"
        desc = "网络较差，建议排查问题"

    # 针对性建议
    tips = []
    if conn_score < 15: tips.append("部分站点不可达，检查防火墙或代理设置")
    if latency_score < 15: tips.append("网络延迟偏高，检查路由器负载或更换 DNS")
    if loss_score < 15: tips.append(f"丢包率 {loss_pct}%，可能存在线路问题或无线干扰")
    if dns_score < 10: tips.append(f"DNS 解析缓慢 ({dns_avg}ms)，建议更换为 223.5.5.5 或 119.29.29.29")
    if bw_score < 10: tips.append(f"带宽不足 ({bw_mbps}Mbps)，检查网络套餐或网线/无线信道")
    if dual_score < 5: tips.append("仅支持 IPv4，IPv6 不可用")

    return {
        "total": round(total, 1), "grade": grade, "desc": desc,
        "scores": scores, "details": details, "tips": tips
    }


# ── 全集检测 ─────────────────────────────────────────────────────────

def run_all_checks():
    report = {}
    report["interfaces"] = step_interface_scan()
    report["connectivity"] = step_connectivity()
    report["dns_perf"] = step_dns_perf()
    report["latency_matrix"] = step_latency_matrix()
    report["packet_loss"] = step_packet_loss()
    report["bandwidth"] = step_bandwidth_test()
    report["ipv6"] = step_ipv6_check()
    report["score"] = step_overall_score(report)
    return report


# ── 路由 ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            data = run_all_checks()
            result_json = json.dumps(data, ensure_ascii=False)
            return render_template("index.html", result=result_json, error=None)
        except Exception as e:
            return render_template("index.html", result=None, error=str(e))
    return render_template("index.html", result=None, error=None)


@app.route("/api/health")
def health():
    return {"status": "ok"}


@app.route("/api/detect", methods=["POST"])
def detect_api():
    try:
        return {"success": True, "data": run_all_checks()}
    except Exception as e:
        return {"success": False, "error": str(e)}, 500


# ── SSE 流式检测 ─────────────────────────────────────────────────────

STEPS_META = [
    ("interfaces", "网络接口扫描"),
    ("connectivity", "互联网连通性"),
    ("dns_perf", "DNS 解析性能"),
    ("latency_matrix", "延迟矩阵"),
    ("packet_loss", "丢包率 & 抖动"),
    ("bandwidth", "带宽估算"),
    ("ipv6", "IPv4/IPv6 双栈"),
    ("score", "综合评分"),
]
TOTAL = len(STEPS_META)


@app.route("/api/detect/stream")
def detect_stream():
    def generate():
        report = {}
        for i, (key, title) in enumerate(STEPS_META):
            payload = {"step": i + 1, "total": TOTAL, "title": title, "key": key}
            yield f"event: progress\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            try:
                if key == "interfaces":
                    report["interfaces"] = step_interface_scan()
                elif key == "connectivity":
                    report["connectivity"] = step_connectivity()
                elif key == "dns_perf":
                    report["dns_perf"] = step_dns_perf()
                elif key == "latency_matrix":
                    report["latency_matrix"] = step_latency_matrix()
                elif key == "packet_loss":
                    report["packet_loss"] = step_packet_loss()
                elif key == "bandwidth":
                    report["bandwidth"] = step_bandwidth_test()
                elif key == "ipv6":
                    report["ipv6"] = step_ipv6_check()
                elif key == "score":
                    report["score"] = step_overall_score(report)
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
    print("📊 网络质量检测服务启动: http://localhost:5098")
    app.run(host="127.0.0.1", port=5098, debug=False)
