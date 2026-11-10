#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地实测精选
============
用 CloudflareSpeedTest 对 ip_all.txt 做真实测速，两轮筛选后输出 ip.txt。

为什么必须两轮：
  实测发现延迟最低的 35.78.243.103（149ms / 东京）下载速度为 0，
  只按延迟排序会把带宽为 0 的废 IP 选进来。

用法：
  python scripts/local_check.py      （或双击根目录 local_check.bat）

依赖：
  根目录放 cfst.exe（CloudflareSpeedTest）
  根目录有 bestcf.py 跑出来的 ip_all.txt
"""

import os
import csv
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
os.chdir(ROOT)

CFST = "cfst.exe"
TOP_N = 6           # 最终保留几个
LAT_LIMIT = 400     # 延迟上限 ms
SPEED_MIN = 5.0     # 下载速度下限 MB/s
LOSS_MAX = 0.25     # 丢包率上限
PRE_PICK = 15       # 先按延迟取前 N 个进入下载测速


def read_ips(path):
    ips = []
    if not os.path.exists(path):
        return ips
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split("#")[0].split(":")[0].strip()
            if ip.count(".") == 3:
                ips.append(ip)
    return ips


def run_cfst(inp, out, extra):
    cmd = [CFST, "-f", inp, "-httping", "-o", out] + extra
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8-sig") as f:
        r = csv.reader(f)
        next(r, None)
        for row in r:
            if len(row) >= 7:
                try:
                    rows.append({
                        "ip": row[0].strip(),
                        "loss": float(row[3] or 0),
                        "lat": float(row[4] or 9999),
                        "speed": float(row[5] or 0),
                        "colo": row[6].strip(),
                    })
                except ValueError:
                    continue
    return rows


def main():
    if not os.path.exists(CFST):
        print("[错误] 找不到 cfst.exe，请放在 %s" % ROOT)
        return 1

    ips = read_ips("ip_all.txt")
    if not ips:
        print("[错误] ip_all.txt 为空或不存在，先跑一次 scripts/bestcf.py")
        return 1
    print("候选 %d 个" % len(ips))
    with open("candidates.txt", "w", encoding="ascii") as f:
        f.write("\n".join(ips))

    print("第 1 轮：延迟测速...")
    run_cfst("candidates.txt", "latency.csv", ["-dd", "-p", "60"])
    lat = [r for r in read_csv("latency.csv") if r["loss"] <= LOSS_MAX and r["lat"] < LAT_LIMIT]
    lat.sort(key=lambda x: x["lat"])
    if not lat:
        print("[错误] 延迟测速无一达标")
        return 1
    pre = lat[:PRE_PICK]
    print("延迟达标 %d 个，取前 %d 个进入下载测速" % (len(lat), len(pre)))
    with open("pre.txt", "w", encoding="ascii") as f:
        f.write("\n".join(r["ip"] for r in pre))

    print("第 2 轮：下载测速（每个最多 8 秒）...")
    run_cfst("pre.txt", "result.csv", ["-dn", "10", "-dt", "8", "-sl", "0", "-p", "60"])
    res = read_csv("result.csv")
    ok = [r for r in res
          if r["loss"] <= LOSS_MAX and r["lat"] < LAT_LIMIT and r["speed"] >= SPEED_MIN]
    ok.sort(key=lambda x: -x["speed"])

    if len(ok) < 3:
        print("[保护] 双达标仅 %d 个，不覆盖 ip.txt，保留上一版" % len(ok))
        return 1

    top = ok[:TOP_N]
    with open("ip.txt", "w", encoding="utf-8") as f:
        f.write("# CF优选实测精选 - 本机实测\n")
        f.write("# 筛选：丢包<=%.2f / 延迟<%dms / 下载>=%.1fMB/s，按下载速度排序\n"
                % (LOSS_MAX, LAT_LIMIT, SPEED_MIN))
        for i, r in enumerate(top, 1):
            f.write("%s:443#%02d|%s|%dms|%.1fMB/s\n"
                    % (r["ip"], i, r["colo"] or "?", r["lat"], r["speed"]))

    # 给客户端的「优选 IP 替换」功能用的纯列表，一行一个 IP:443
    with open("ip_plain.txt", "w", encoding="ascii") as f:
        for r in top:
            f.write("%s:443\n" % r["ip"])

    print("完成，已写入 ip.txt：TOP%d" % len(top))
    for i, r in enumerate(top, 1):
        print("  %02d. %-16s %-4s %5dms  %.1fMB/s"
              % (i, r["ip"], r["colo"] or "?", r["lat"], r["speed"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
