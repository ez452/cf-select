#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF 优选 IP 精选 v2
==================
相对 v1 的修正（每条都有实据，不是拍脑袋）：

1. 验证结果诚实
   v1 的 log 写「存活验证通过 82 / 82」，但 ip.txt 里 colo 全是 "?"。
   原因：宽松模式把 trace 不通的 IP 也 append 进 results，然后统计 len(results)。
   本版把 verified / unverified 两个列表彻底分开，日志分开报，未验证的绝不进 TOP。

2. 计票按源去重
   v1 的 votes 在端口循环里累加，同一 IP 在同一源出现多个端口会被重复计票
   （162.159.197.1 只有 3 个源却算出 31 票）。本版同源同 IP 只投一票。

3. 排除 DNS 解析器网段
   162.159.197.x / 162.159.198.x 是 CF 公共 DNS 后端，不是代理节点，
   v1 把它们排在了 TOP1 和 TOP2。

4. 端口如实
   v1 解析时记录了真实端口，输出却写死 :443，会把只开 2053 的 IP 写成 443 导致连不上。
   本版非 443 直接丢弃，输出恒为 :443。

5. 验证方式修正
   v1 用 urllib 请求 https://{ip}/cdn-cgi/trace，SNI 是 IP，CF 不认，必然失败。
   本版手动握手，SNI 设为 www.cloudflare.com，才拿到真实的 colo。

6. 拉源并发 + 重试
   v1 串行拉 6 个源，一个超时拖死后面（实测 10:58 那次 5/6 失败）。
   本版并发拉取，每个源重试 3 次，单个超时 12s。

7. 空结果保护
   验证通过不足 MIN_ACCEPT 个时，不覆盖 ip.txt，避免把可用节点冲成空订阅。
"""

import os
import re
import ssl
import json
import socket
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

CST = timezone(timedelta(hours=8))
NOW = datetime.now(CST)

# ============ 配置区 ============
TOP_N = 10               # 最终精选数量
CANDIDATE_LIMIT = 60     # 进入验证的候选上限（按票数取前 N）
MIN_ACCEPT = 3           # 验证通过少于这个数，不覆盖 ip.txt
FETCH_TIMEOUT = 12
FETCH_RETRY = 3
VERIFY_TIMEOUT = 4
VERIFY_WORKERS = 40
VERIFY_ROUNDS = 2

# 源：名称, 地址, 权重
# 权重只影响排序优先级，不参与"票数"。票数 = 收录该 IP 的独立源个数。
SOURCES = [
    ("cmliu",   "https://bestcf.pages.dev/cmliu/all.txt",                     9),
    ("cfyes",   "https://bestcf.pages.dev/cfyes/ipv4.txt",                    9),
    ("vvhan",   "https://bestcf.pages.dev/vvhan/ipv4.txt",                    8),
    ("ymyuuu",  "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt", 8),
    ("zhixuan", "https://bestcf.pages.dev/zhixuanwang/ipv4-onlyip.txt",       8),
    ("mini",    "https://bestcf.pages.dev/domain/mini.txt",                   7),
]

# CF 公共 DNS 解析器网段，不是代理节点
EXCLUDE_PREFIX = ("162.159.197.", "162.159.198.", "1.1.1.", "1.0.0.")

LOG = []


def log(msg):
    print(msg)
    LOG.append(msg)


# ============ 代理（仅用于拉源，验证一律直连） ============
def _win_proxy():
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        enable, _ = winreg.QueryValueEx(k, "ProxyEnable")
        server, _ = winreg.QueryValueEx(k, "ProxyServer")
        if enable and server:
            if "=" in server:
                for part in server.split(";"):
                    if part.lower().startswith(("https=", "http=")):
                        return part.split("=", 1)[1]
            return server
    except Exception:
        pass
    return None


def _build_fetch_opener():
    proxy = os.environ.get("CF_PROXY") or _win_proxy()
    if not proxy:
        return urllib.request.build_opener()
    p = proxy if "://" in proxy else "http://" + proxy
    netloc = urllib.parse.urlparse(p).netloc or proxy
    handler = urllib.request.ProxyHandler({"http": "http://" + netloc, "https": "http://" + netloc})
    return urllib.request.build_opener(handler)


FETCH_OPENER = _build_fetch_opener()


# ============ 解析 ============
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?")


def parse_entries(text):
    """只保留 443 端口的合法 IPv4，排除 DNS 网段"""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        m = IP_RE.search(line)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        octets = ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            continue
        p = int(port) if port else 443
        if p != 443:
            continue
        if ip.startswith(EXCLUDE_PREFIX):
            continue
        out.add(ip)
    return out


def fetch_source(name, url):
    for attempt in range(FETCH_RETRY):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cf-select/2.0"})
            with FETCH_OPENER.open(req, timeout=FETCH_TIMEOUT) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt == FETCH_RETRY - 1:
                log("[跳过] %s: %s" % (name, e))
            else:
                time.sleep(1.5)
    return None


# ============ 共识统计 ============
def collect():
    votes = {}   # ip -> {"sources": set, "weight": int}

    def work(item):
        name, url, weight = item
        text = fetch_source(name, url)
        if text is None:
            return name, weight, None
        return name, weight, parse_entries(text)

    with ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        for name, weight, ips in ex.map(work, SOURCES):
            if ips is None:
                continue
            log("[来源] %s: %d 条" % (name, len(ips)))
            for ip in ips:
                d = votes.setdefault(ip, {"sources": set(), "weight": 0})
                if name not in d["sources"]:      # 同源同 IP 只投一票
                    d["sources"].add(name)
                    d["weight"] += weight
    return votes


# ============ 真实存活验证 ============
def trace(ip):
    """SNI 设为 www.cloudflare.com 手动握手，返回 (ok, colo)"""
    for _ in range(VERIFY_ROUNDS):
        sock = None
        ss = None
        try:
            sock = socket.create_connection((ip, 443), timeout=VERIFY_TIMEOUT)
            ctx = ssl._create_unverified_context()
            ss = ctx.wrap_socket(sock, server_hostname="www.cloudflare.com")
            ss.sendall(
                b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                b"Host: www.cloudflare.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            data = b""
            while len(data) < 8192:
                chunk = ss.recv(4096)
                if not chunk:
                    break
                data += chunk
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="ignore")
            else:
                body = data.decode("utf-8", errors="ignore")
            if "colo=" in body:
                colo = ""
                for kv in body.splitlines():
                    if kv.startswith("colo="):
                        colo = kv.split("=", 1)[1].strip()
                        break
                if colo:
                    return True, colo
        except Exception:
            pass
        finally:
            try:
                if ss:
                    ss.close()
                elif sock:
                    sock.close()
            except Exception:
                pass
    return False, ""


# ============ 主流程 ============
def main():
    log("===== CF 优选精选 v2 %s CST =====" % NOW.strftime("%Y-%m-%d %H:%M:%S"))

    votes = collect()
    log("候选池（去重 / 仅443 / 已排除DNS网段）：%d 个" % len(votes))

    if not votes:
        log("[中止] 一个源都没拉到，保留旧 ip.txt 不动")
        _write_log()
        return

    ranked = sorted(
        votes.items(),
        key=lambda kv: (-len(kv[1]["sources"]), -kv[1]["weight"], kv[0]),
    )
    cand = ranked[:CANDIDATE_LIMIT]
    log("进入验证：%d 个（票数 %d ~ %d）" % (
        len(cand), len(cand[0][1]["sources"]), len(cand[-1][1]["sources"])))

    verified, unverified = [], []
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as ex:
        futs = {ex.submit(trace, ip): (ip, d) for ip, d in cand}
        for f in as_completed(futs):
            ip, d = futs[f]
            ok, colo = f.result()
            item = {
                "ip": ip,
                "colo": colo,
                "source_count": len(d["sources"]),
                "sources": sorted(d["sources"]),
                "weight": d["weight"],
            }
            (verified if ok else unverified).append(item)

    verified.sort(key=lambda x: (-x["source_count"], -x["weight"], x["ip"]))
    unverified.sort(key=lambda x: (-x["source_count"], -x["weight"], x["ip"]))

    log("真实存活验证通过：%d / %d" % (len(verified), len(cand)))
    log("未通过验证（只进 backup.txt，不进 TOP）：%d" % len(unverified))

    # ---- 写出 ip_all / backup ----
    with open("ip_all.txt", "w", encoding="utf-8") as f:
        f.write("# 全部通过验证 - %s CST\n" % NOW.strftime("%Y-%m-%d %H:%M"))
        for r in verified:
            f.write("%s:443#%s|源%d\n" % (r["ip"], r["colo"], r["source_count"]))

    with open("backup.txt", "w", encoding="utf-8") as f:
        f.write("# 未通过验证，不建议使用，仅供排查 - %s CST\n" % NOW.strftime("%Y-%m-%d %H:%M"))
        for r in unverified:
            f.write("%s:443#未验证|源%d\n" % (r["ip"], r["source_count"]))

    # ---- 空结果保护 ----
    if len(verified) < MIN_ACCEPT:
        log("[保护] 验证通过仅 %d 个（< %d），不覆盖 ip.txt，避免把可用节点冲成空订阅" % (
            len(verified), MIN_ACCEPT))
    else:
        top = verified[:TOP_N]
        with open("ip.txt", "w", encoding="utf-8") as f:
            f.write("# CF优选精选 v2 - %s CST | 全部经 trace 验证\n" % NOW.strftime("%Y-%m-%d %H:%M"))
            for i, r in enumerate(top, 1):
                f.write("%s:443#%02d|%s|源%d\n" % (r["ip"], i, r["colo"], r["source_count"]))
        if len(top) < TOP_N:
            log("[告警] 验证通过不足 %d 个，本次输出 %d 个，不拿未验证 IP 凑数" % (TOP_N, len(top)))
        log("已写入 ip.txt：TOP%d" % len(top))
        for i, r in enumerate(top, 1):
            log("  %02d. %s:443  colo=%s  源%d(%s)" % (
                i, r["ip"], r["colo"], r["source_count"], ",".join(r["sources"])))

    meta = {
        "version": "v2",
        "updated": NOW.strftime("%Y-%m-%d %H:%M:%S CST"),
        "candidates": len(votes),
        "tested": len(cand),
        "verified": len(verified),
        "unverified": len(unverified),
        "top": verified[:TOP_N],
        "sources": [s[0] for s in SOURCES],
    }
    with open("meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    _write_log()


def _write_log():
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write("\n".join(LOG) + "\n\n")


if __name__ == "__main__":
    main()
