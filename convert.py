#!/usr/bin/env python3
"""
conf-routing: конвертер roscomvpn geosite.dat / geoip.dat (v2fly protobuf)
в текстовые списки правил (.list) для Shadowrocket (RULE-SET).

Категории и их назначение взяты 1:1 из конфига маршрутизации Incy "FlexieRoutIng".
Запуск без аргументов скачивает свежие dat из релизов hydraponique.

Только стандартная библиотека Python 3.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

GEOSITE_URL = "https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat"
GEOIP_URL = "https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat"

# Порядок категорий соответствует RouteOrder=block-proxy-direct исходного конфига Incy.
GEOSITE_CATS = [
    ("win-spy", "REJECT"),
    ("torrent", "REJECT"),
    ("category-ads", "REJECT"),
    ("github", "PROXY"),
    ("youtube", "PROXY"),
    ("twitch", "PROXY"),
    ("telegram", "PROXY"),
    ("private", "DIRECT"),
    ("category-ru", "DIRECT"),
    ("whitelist", "DIRECT"),
    ("apple", "DIRECT"),
    ("epicgames", "DIRECT"),
    ("riot", "DIRECT"),
    ("escapefromtarkov", "DIRECT"),
    ("steam", "DIRECT"),
    ("origin", "DIRECT"),
    ("pinterest", "DIRECT"),
    ("faceit", "DIRECT"),
]
GEOIP_CATS = [("private", "DIRECT"), ("direct", "DIRECT")]


# ---------- минимальный protobuf-парсер (v2fly dlc формат) ----------

def _varint(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf):
    i, n = 0, len(buf)
    while i < n:
        tag, i = _varint(buf, i)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 2:
            length, i = _varint(buf, i)
            value = buf[i:i + length]
            i += length
        elif wire == 5:
            value = buf[i:i + 4]
            i += 4
        elif wire == 1:
            value = buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unexpected wire type {wire}")
        yield field, value


def parse_geosite(data):
    """-> {category: [(type, value), ...]}; type: 0=keyword 1=regex 2=suffix 3=full"""
    out = {}
    for field, entry in _fields(data):
        if field != 1:
            continue
        code, domains = None, []
        for f, v in _fields(entry):
            if f == 1:
                code = v.decode()
            elif f == 2:
                dtype, dval = 0, None
                for f2, v2 in _fields(v):
                    if f2 == 1:
                        dtype = v2
                    elif f2 == 2:
                        dval = v2.decode()
                domains.append((dtype, dval))
        out[code.lower()] = domains
    return out


def parse_geoip(data):
    """-> {category: [(ip_bytes, prefix), ...]}"""
    out = {}
    for field, entry in _fields(data):
        if field != 1:
            continue
        code, cidrs = None, []
        for f, v in _fields(entry):
            if f == 1:
                code = v.decode()
            elif f == 2:
                ip, prefix = None, 0
                for f2, v2 in _fields(v):
                    if f2 == 1:
                        ip = v2
                    elif f2 == 2:
                        prefix = v2
                cidrs.append((ip, prefix))
        out[code.lower()] = cidrs
    return out


# ---------- конвертация в синтаксис Shadowrocket ----------

def regex_to_keyword(rx):
    """Shadowrocket не поддерживает regex по домену. Берём самую длинную
    литеральную подстроку регэкспа как DOMAIN-KEYWORD (подстрока домена).
    Возвращает None, если надёжного литерала нет — тогда правило пропускается."""
    s = rx.replace("\\.", "\x00")  # экранированная точка — литерал
    s = re.sub(r"\[[^\]]*\]", "|", s)  # символьные классы — не литералы
    s = re.sub(r"\{[^}]*\}", "|", s)   # квантификаторы {m,n} — не литералы
    parts = [p.replace("\x00", ".") for p in re.split(r"[\^\$\.\*\+\?\(\)\|\\]", s)]
    parts = [p for p in parts if re.fullmatch(r"[a-z0-9.-]+", p)]
    best = max(parts, key=len) if parts else ""
    return best if len(best) >= 6 else None


def geosite_lines(entries):
    lines, notes = [], []
    for dtype, value in entries:
        if dtype == 2:
            lines.append(f"DOMAIN-SUFFIX,{value}")
        elif dtype == 3:
            lines.append(f"DOMAIN,{value}")
        elif dtype == 0:
            lines.append(f"DOMAIN-KEYWORD,{value}")
        elif dtype == 1:
            kw = regex_to_keyword(value)
            if kw:
                lines.append(f"# regexp:{value} -> приближено ключевым словом:")
                lines.append(f"DOMAIN-KEYWORD,{kw}")
            else:
                lines.append(f"# UNSUPPORTED regexp:{value}")
                notes.append(value)
    return lines, notes


def ipbytes_to_str(ip):
    if len(ip) == 4:
        return ".".join(str(b) for b in ip)
    import socket
    return socket.inet_ntop(socket.AF_INET6, ip)


def geoip_lines(entries):
    lines = []
    for ip, prefix in entries:
        addr = ipbytes_to_str(ip)
        rtype = "IP-CIDR" if len(ip) == 4 else "IP-CIDR6"
        lines.append(f"{rtype},{addr}/{prefix}")
    return lines


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "conf-routing"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
        final_url = r.geturl()
    m = re.search(r"/releases/download/([^/]+)/", final_url)
    return data, (m.group(1) if m else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--geosite", help="локальный путь к geosite.dat (иначе скачать)")
    ap.add_argument("--geoip", help="локальный путь к geoip.dat (иначе скачать)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules"))
    args = ap.parse_args()

    if args.geosite:
        gs_data, gs_tag = open(args.geosite, "rb").read(), None
    else:
        gs_data, gs_tag = fetch(GEOSITE_URL)
    if args.geoip:
        gi_data, gi_tag = open(args.geoip, "rb").read(), None
    else:
        gi_data, gi_tag = fetch(GEOIP_URL)

    geosite = parse_geosite(gs_data)
    geoip = parse_geoip(gi_data)

    os.makedirs(args.out, exist_ok=True)
    meta = {
        "geosite": {"sha256": hashlib.sha256(gs_data).hexdigest(), "tag": gs_tag},
        "geoip": {"sha256": hashlib.sha256(gi_data).hexdigest(), "tag": gi_tag},
        "files": {},
    }

    problems = []
    for cat, policy in GEOSITE_CATS:
        if cat not in geosite:
            problems.append(f"geosite:{cat} отсутствует в dat!")
            continue
        lines, notes = geosite_lines(geosite[cat])
        rule_count = sum(1 for l in lines if not l.startswith("#"))
        header = [
            f"# conf-routing | geosite:{cat} -> {policy}",
            f"# source: roscomvpn-geosite ({meta['geosite']['sha256'][:16]}…)",
            f"# rules: {rule_count}",
        ]
        path = os.path.join(args.out, f"geosite-{cat}.list")
        with open(path, "w") as f:
            f.write("\n".join(header + lines) + "\n")
        meta["files"][f"geosite-{cat}.list"] = rule_count

    for cat, policy in GEOIP_CATS:
        if cat not in geoip:
            problems.append(f"geoip:{cat} отсутствует в dat!")
            continue
        lines = geoip_lines(geoip[cat])
        header = [
            f"# conf-routing | geoip:{cat} -> {policy}",
            f"# source: roscomvpn-geoip ({meta['geoip']['sha256'][:16]}…)",
            f"# rules: {len(lines)}",
        ]
        path = os.path.join(args.out, f"geoip-{cat}.list")
        with open(path, "w") as f:
            f.write("\n".join(header + lines) + "\n")
        meta["files"][f"geoip-{cat}.list"] = len(lines)

    with open(os.path.join(args.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1, ensure_ascii=False)
        f.write("\n")

    total = sum(meta["files"].values())
    print(f"OK: {len(meta['files'])} файлов, {total} правил -> {args.out}")
    if problems:
        print("ПРОБЛЕМЫ:", *problems, sep="\n  ", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
