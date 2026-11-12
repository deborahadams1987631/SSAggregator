#!/usr/bin/env python3
"""Convert a URI subscription text file (ss/vmess/vless/trojan/hysteria2/http)
into a sing-box JSON config. Usage:
    python3 singbox_convert.py <input.txt> <output.json>
Lines that cannot be parsed (or protocols sing-box does not support,
e.g. ssr) are skipped and counted. Output always contains the proxy
outbounds plus an urltest group "auto", a selector "proxy", and
direct/block outbounds, so the file imports as a complete config.
"""
import sys, os, json, base64, urllib.parse


def b64d(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", "replace")


def q1(qs, key, default=""):
    v = qs.get(key, [default])
    return v[0] if v else default


def parse_ss(line):
    body = line[5:]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    name = urllib.parse.unquote(frag)
    plugin = ""
    if "?" in body:
        body, qs = body.split("?", 1)
        plugin = urllib.parse.parse_qs(qs).get("plugin", [""])[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            cred = b64d(userinfo)
        except Exception:
            cred = urllib.parse.unquote(userinfo)
    else:
        dec = b64d(body)
        cred, hostport = dec.split("@", 1) if "@" in dec else ("", dec)
        if ":" in cred and "@" not in body:
            pass
        # legacy whole-uri base64: cred@host:port all inside dec
        if "@" in dec:
            cred, hostport = dec.rsplit("@", 1)
    method, password = cred.split(":", 1)
    server, port = hostport.rsplit(":", 1)
    out = {"type": "shadowsocks", "tag": name, "server": server.strip("[]"),
           "server_port": int(port), "method": method, "password": password}
    if plugin:
        pname, _, popts = plugin.partition(";")
        out["plugin"] = pname
        if popts:
            out["plugin_opts"] = popts
    return out


def parse_vmess(line):
    j = json.loads(b64d(line[8:]))
    out = {"type": "vmess", "tag": j.get("ps", ""),
           "server": j.get("add", ""), "server_port": int(j.get("port", 0)),
           "uuid": j.get("id", ""), "alter_id": int(j.get("aid", 0) or 0),
           "security": j.get("scy", "auto") or "auto"}
    net = (j.get("net") or "tcp").lower()
    if j.get("tls") == "tls":
        tls = {"enabled": True}
        if j.get("sni"):
            tls["server_name"] = j["sni"]
        out["tls"] = tls
    if net == "ws":
        tr = {"type": "ws", "path": j.get("path", "/")}
        if j.get("host"):
            tr["headers"] = {"Host": j["host"]}
        out["transport"] = tr
    elif net == "grpc":
        out["transport"] = {"type": "grpc", "service_name": j.get("path", "")}
    elif net in ("h2", "http"):
        tr = {"type": "http", "path": j.get("path", "/")}
        if j.get("host"):
            tr["host"] = [h for h in str(j["host"]).split(",") if h]
        out["transport"] = tr
    return out


def split_uri(line):
    u = urllib.parse.urlsplit(line)
    qs = urllib.parse.parse_qs(u.query)
    name = urllib.parse.unquote(u.fragment)
    return u, qs, name


def apply_transport(out, qs):
    net = q1(qs, "type", "tcp").lower()
    if net == "ws":
        tr = {"type": "ws", "path": q1(qs, "path", "/")}
        host = q1(qs, "host")
        if host:
            tr["headers"] = {"Host": host}
        out["transport"] = tr
    elif net == "grpc":
        out["transport"] = {"type": "grpc",
                            "service_name": q1(qs, "serviceName", q1(qs, "service_name"))}
    elif net in ("h2", "http"):
        tr = {"type": "http", "path": q1(qs, "path", "/")}
        host = q1(qs, "host")
        if host:
            tr["host"] = [host]
        out["transport"] = tr


def apply_tls(out, qs, default_sni=""):
    sec = q1(qs, "security").lower()
    if sec in ("tls", "reality", "xtls"):
        tls = {"enabled": True}
        sni = q1(qs, "sni", q1(qs, "peer", default_sni))
        if sni:
            tls["server_name"] = sni
        alpn = q1(qs, "alpn")
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        fp = q1(qs, "fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if sec == "reality":
            r = {}
            pbk = q1(qs, "pbk")
            sid = q1(qs, "sid")
            if pbk:
                r["public_key"] = pbk
            if sid:
                r["short_id"] = sid
            tls["reality"] = {"enabled": True, **r}
        out["tls"] = tls


def parse_trojan(line):
    u, qs, name = split_uri(line)
    out = {"type": "trojan", "tag": name, "server": u.hostname,
           "server_port": u.port, "password": urllib.parse.unquote(u.username or "")}
    apply_tls(out, qs, u.hostname or "")
    if "tls" not in out and q1(qs, "security").lower() not in ("none",):
        out["tls"] = {"enabled": True, "server_name": q1(qs, "sni", q1(qs, "peer", u.hostname or ""))}
    apply_transport(out, qs)
    return out


def parse_vless(line):
    u, qs, name = split_uri(line)
    out = {"type": "vless", "tag": name, "server": u.hostname,
           "server_port": u.port, "uuid": u.username or ""}
    flow = q1(qs, "flow")
    if flow:
        out["flow"] = flow
    apply_tls(out, qs, u.hostname or "")
    apply_transport(out, qs)
    return out


def parse_hy2(line):
    u, qs, name = split_uri(line)
    out = {"type": "hysteria2", "tag": name, "server": u.hostname,
           "server_port": u.port, "password": urllib.parse.unquote(u.username or "")}
    tls = {"enabled": True}
    sni = q1(qs, "sni", q1(qs, "peer"))
    if sni:
        tls["server_name"] = sni
    if q1(qs, "insecure") in ("1", "true"):
        tls["insecure"] = True
    out["tls"] = tls
    obfs = q1(qs, "obfs")
    if obfs:
        o = {"type": obfs}
        op = q1(qs, "obfs-password")
        if op:
            o["password"] = op
        out["obfs"] = o
    return out


def parse_http(line):
    u, qs, name = split_uri(line)
    out = {"type": "http", "tag": name, "server": u.hostname, "server_port": u.port}
    if u.username:
        out["username"] = urllib.parse.unquote(u.username)
    if u.password:
        out["password"] = urllib.parse.unquote(u.password)
    if u.scheme == "https":
        out["tls"] = {"enabled": True}
    return out


PARSERS = (("ss://", parse_ss), ("vmess://", parse_vmess),
           ("trojan://", parse_trojan), ("vless://", parse_vless),
           ("hysteria2://", parse_hy2), ("hy2://", parse_hy2),
           ("http://", parse_http), ("https://", parse_http))


def main():
    src, dst = sys.argv[1], sys.argv[2]
    if not os.path.exists(src):
        print(f"input {src} missing, skip")
        return
    seen, tags, outbounds = set(), set(), []
    ok = skip = 0
    with open(src, encoding="utf-8", errors="replace") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    for line in lines:
        fn = None
        for prefix, parser in PARSERS:
            if line.startswith(prefix):
                fn = parser
                break
        if fn is None:
            skip += 1
            continue
        try:
            o = fn(line)
        except Exception:
            skip += 1
            continue
        if not o.get("server") or not o.get("server_port"):
            skip += 1
            continue
        key = json.dumps(o, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        tag = o.get("tag") or f"{o['type']}-{o['server']}:{o['server_port']}"
        base, n = tag, 2
        while tag in tags:
            tag = f"{base}-{n}"
            n += 1
        o["tag"] = tag
        tags.add(tag)
        outbounds.append(o)
        ok += 1
    proxies = [o["tag"] for o in outbounds]
    config = {
        "log": {"level": "warn"},
        "outbounds": outbounds + [
            {"type": "urltest", "tag": "auto", "outbounds": proxies,
             "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "selector", "tag": "proxy",
             "outbounds": ["auto"] + proxies, "default": "auto"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ] if proxies else [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"final": "proxy"} if proxies else {"final": "direct"},
    }
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    print(f"{src}: converted={ok} skipped={skip} -> {dst}")


if __name__ == "__main__":
    main()
