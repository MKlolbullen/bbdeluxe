#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bb_live.py — Live dashboard server for bbdeluxe

Features
- HTTP server (stdlib) + optional WebSocket (if 'websockets' is installed), SSE fallback, or polling
- Live D3 UI with Tailwind (served from this process; D3/Tailwind via CDN)
- NetworkX graph model (optional): hosts, IPs, URLs, ports, tech, CDNs, filetypes, params, vulns
- Pandas tables (optional): hosts, urls, vulns, ports, filetypes (with Aquatone thumbnails)
- Watches/tails bbdeluxe artifacts (dnsx.jsonl, httpx.jsonl, naabu.jsonl, scan/nuclei.jsonl, dalfox.txt, kxss.txt, urls.txt)
- Serves Aquatone screenshots from shots/screenshots/*.png and adds thumbnails to Host/URL tables
- Search/filter in graph and tables; dark/light theme toggle

Intended usage
- Imported and started by bbdeluxe.py:
    from bb_live import LiveService
    live = LiveService("127.0.0.1:8765", target_dir, mode="auto", theme="dark")
    live.start(open_browser=True)
    live.watch_files(dnsx=..., httpx=..., naabu=..., nuclei=..., dalfox=..., kxss=..., urls=..., shots_dir=...)

- Or run standalone for a directory with artifacts:
    python3 bb_live.py --bind 127.0.0.1:8765 --dir ./runs/example.com/2025... --open
"""

import json
import os
import re
import threading
import time
import http.server
import socketserver
import urllib.parse
import webbrowser
import mimetypes
import argparse
from pathlib import Path
from typing import Optional, Tuple

# Optional libs
try:
    import pandas as pd
except Exception:
    pd = None

try:
    import networkx as nx
except Exception:
    nx = None

try:
    import websockets
    import asyncio
except Exception:
    websockets = None
    asyncio = None


# ------------------------- Event bus (SSE + optional WS) -------------------------

class EventBus:
    def __init__(self):
        self.clients = []              # SSE queues
        self.lock = threading.Lock()
        self.ws_clients = set()        # WebSocket connections
        self._ws_loop = None           # asyncio loop (if WS enabled)

    def subscribe(self):
        import queue
        q = queue.Queue()
        with self.lock:
            self.clients.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.clients:
                self.clients.remove(q)

    def publish(self, event: dict):
        # SSE listeners
        with self.lock:
            for q in list(self.clients):
                try:
                    q.put_nowait(event)
                except Exception:
                    pass
        # WebSocket broadcast (if enabled)
        if websockets and self._ws_loop:
            try:
                asyncio.run_coroutine_threadsafe(self._ws_broadcast(json.dumps(event)), self._ws_loop)
            except Exception:
                pass

    async def _ws_broadcast(self, msg: str):
        dead = set()
        for ws in list(self.ws_clients):
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead


# ------------------------- State & builders -------------------------

def _simplify_name(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


class GraphState:
    """
    Holds the in-memory state for graph + tables and updates it from tailed files.
    """
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.lock = threading.RLock()

        # Structs
        self.g = nx.Graph() if nx else None
        self.httpx = []
        self.dnsx = []
        self.naabu = []
        self.vulns = []
        self.urls = []

        # Screenshots
        self.shots_dir = self.out_dir / "shots" / "screenshots"
        self._shot_index = []           # [(filename, simplified), ...]
        self._last_index_scan = 0.0

    # ----- Screenshots index/match -----
    def _index_shots(self):
        now = time.time()
        if (now - self._last_index_scan) < 2.0:   # throttle scan
            return
        self._last_index_scan = now
        shots = []
        d = self.shots_dir
        if d and d.exists():
            for p in d.glob("*.png"):
                shots.append((p.name, _simplify_name(p.stem)))
        with self.lock:
            self._shot_index = shots

    def _match_shot_for_host(self, host: str) -> Optional[str]:
        if not host:
            return None
        key = _simplify_name(host)
        best = None
        for name, simp in self._shot_index:
            if key and key in simp:
                best = name
                break
        return best

    # ----- Graph helpers -----
    def _add_node(self, node_id: str, **attrs):
        if not node_id or self.g is None:
            return
        if node_id not in self.g:
            self.g.add_node(node_id, **attrs)
        else:
            # Update but don't delete
            self.g.nodes[node_id].update({k: v for k, v in attrs.items() if v is not None})

    def _add_edge(self, a: str, b: str, **attrs):
        if self.g is None or not a or not b:
            return
        self.g.add_edge(a, b, **attrs)

    @staticmethod
    def _filetype_from_url(url: str) -> Optional[str]:
        try:
            path = urllib.parse.urlsplit(url).path
            _, ext = os.path.splitext(path)
            ext = ext.lower().lstrip(".")
            return ext or None
        except Exception:
            return None

    @staticmethod
    def _params_from_url(url: str):
        try:
            q = urllib.parse.urlsplit(url).query
            return urllib.parse.parse_qsl(q, keep_blank_values=True)
        except Exception:
            return []

    # ----- Updaters from tailed files -----
    def update_from_dnsx(self, line: str, bus: Optional[EventBus] = None):
        try:
            j = json.loads(line)
        except Exception:
            return
        host = j.get("host") or j.get("fqdn") or j.get("input") or j.get("name")
        ip = j.get("a") or j.get("ip") or j.get("answer")
        ips = ip if isinstance(ip, list) else ([ip] if isinstance(ip, str) else [])
        with self.lock:
            self.dnsx.append(j)
            if self.g:
                if host:
                    self._add_node(host, kind="host", label=host)
                    for addr in ips:
                        self._add_node(addr, kind="ip", label=addr)
                        self._add_edge(host, addr, rel="resolves")
        if bus:
            bus.publish({"type": "dnsx", "host": host, "ips": ips})

    def update_from_httpx(self, line: str, bus: Optional[EventBus] = None):
        try:
            j = json.loads(line)
        except Exception:
            return
        url = j.get("url")
        host = j.get("host") or (urllib.parse.urlsplit(url).netloc if url else None)
        cdn = j.get("cdn")
        status = j.get("status_code")
        title = j.get("title")
        ip = j.get("ip")
        tech = j.get("tech") or []

        with self.lock:
            self.httpx.append(j)
            if self.g:
                if host:
                    self._add_node(host, kind="host", label=host)
                if url:
                    self._add_node(url, kind="url", status=status, title=title, label=url)
                    self._add_edge(host, url, rel="serves")
                    # filetype node
                    ext = self._filetype_from_url(url)
                    if ext:
                        ft = f"ft:{ext}"
                        self._add_node(ft, kind="filetype", label=ext)
                        self._add_edge(url, ft, rel="filetype")
                    # params nodes
                    for k, v in self._params_from_url(url):
                        pn = f"param:{k}"
                        self._add_node(pn, kind="param", label=k)
                        self._add_edge(url, pn, rel="param")
                if ip:
                    self._add_node(str(ip), kind="ip", label=str(ip))
                    self._add_edge(host, str(ip), rel="served_by")
                if cdn:
                    cn = f"cdn:{host}"
                    self._add_node(cn, kind="cdn", label=str(cdn))
                    self._add_edge(host, cn, rel="cdn")
                for t in tech:
                    tn = f"tech:{t}"
                    self._add_node(tn, kind="tech", label=t)
                    self._add_edge(host, tn, rel="tech")
        if bus:
            bus.publish({"type": "httpx", "url": url, "host": host, "status": status})

    def update_from_naabu(self, line: str, bus: Optional[EventBus] = None):
        try:
            j = json.loads(line)
        except Exception:
            return
        host = j.get("host") or j.get("ip")
        port = j.get("port")
        service = (j.get("service") or "").lower()
        with self.lock:
            self.naabu.append(j)
            if self.g and host and port:
                pnode = f"port:{host}:{port}"
                self._add_node(host, kind="host", label=host)
                self._add_node(pnode, kind="port", port=port, service=service, label=str(port))
                self._add_edge(host, pnode, rel="open")
        if bus:
            bus.publish({"type": "naabu", "host": host, "port": port})

    def update_from_urls(self, line: str, bus: Optional[EventBus] = None):
        url = (line or "").strip()
        if not url:
            return
        with self.lock:
            self.urls.append(url)
            if self.g:
                host = urllib.parse.urlsplit(url).netloc
                self._add_node(host, kind="host", label=host)
                self._add_node(url, kind="url", label=url)
                self._add_edge(host, url, rel="serves")
                ext = self._filetype_from_url(url)
                if ext:
                    ft = f"ft:{ext}"
                    self._add_node(ft, kind="filetype", label=ext)
                    self._add_edge(url, ft, rel="filetype")
                for k, v in self._params_from_url(url):
                    pn = f"param:{k}"
                    self._add_node(pn, kind="param", label=k)
                    self._add_edge(url, pn, rel="param")
        if bus:
            bus.publish({"type": "url", "url": url})

    def update_from_nuclei(self, line: str, bus: Optional[EventBus] = None):
        try:
            j = json.loads(line)
        except Exception:
            j = {"type": "raw", "raw": line}
        with self.lock:
            self.vulns.append(j)
            if self.g:
                host = j.get("host")
                sev = (j.get("severity") or "info").lower()
                vtag = j.get("template") or j.get("info", {}).get("name") or "finding"
                vnode = f"vuln:{vtag}:{host or ''}"
                self._add_node(vnode, kind="vuln", severity=sev, label=vtag)
                url = j.get("matched-at") or j.get("matched_at")
                if url and url in self.g:
                    self._add_edge(url, vnode, rel="vuln")
                if host and host in self.g:
                    self._add_edge(host, vnode, rel="vuln")
        if bus:
            bus.publish({"type": "vuln", "template": j.get("template"), "severity": j.get("severity")})

    # ----- Outputs -----
    def to_d3(self) -> dict:
        with self.lock:
            if not self.g:
                return {"nodes": [], "links": []}
            nodes = []
            for n, attrs in self.g.nodes(data=True):
                d = {"id": n}
                d.update(attrs or {})
                nodes.append(d)
            links = []
            for a, b, attrs in self.g.edges(data=True):
                links.append({"source": a, "target": b, **(attrs or {})})
            return {"nodes": nodes, "links": links}

    def tables(self) -> dict:
        """
        Returns dict of lists for hosts/urls/vulns/ports/filetypes.
        If pandas is present, do richer aggregation and include 'shot' for hosts/urls.
        """
        self._index_shots()
        with self.lock:
            # Minimal fallback if pandas unavailable
            if pd is None:
                # Very light-weight summaries
                urls_simple = [{"url": u} for u in self.urls]
                # Add httpx urls
                for j in self.httpx:
                    uu = j.get("url")
                    if uu:
                        urls_simple.append({"url": uu, "status_code": j.get("status_code"), "title": j.get("title")})
                # Dedup by url
                seen = set()
                urls_simple_dedup = []
                for r in urls_simple:
                    if r["url"] not in seen:
                        urls_simple_dedup.append(r)
                        seen.add(r["url"])

                # Hosts list
                hosts_set = set()
                for r in urls_simple_dedup:
                    try:
                        hosts_set.add(urllib.parse.urlsplit(r["url"]).netloc)
                    except Exception:
                        pass
                hosts_list = [{"host": h} for h in sorted(hosts_set)]

                return {
                    "hosts": hosts_list,
                    "urls": urls_simple_dedup,
                    "vulns": self.vulns[:],
                    "ports": self.naabu[:],
                    "filetypes": [],
                }

            # pandas path
            df_httpx = pd.DataFrame(self.httpx) if self.httpx else pd.DataFrame(columns=["url","status_code","title","tech","ip","cdn"])
            df_urls_only = pd.DataFrame({"url": self.urls}) if self.urls else pd.DataFrame(columns=["url"])
            base_cols = ["url","status_code","title","tech","ip","cdn"]
            part_httpx = df_httpx[base_cols] if not df_httpx.empty else pd.DataFrame(columns=base_cols)
            df_urls = pd.concat([part_httpx, df_urls_only], ignore_index=True)
            if not df_urls.empty:
                df_urls.drop_duplicates(subset=["url"], keep="first", inplace=True)
            else:
                df_urls = pd.DataFrame(columns=base_cols)

            def parse_host(u):
                try:
                    return urllib.parse.urlsplit(u).netloc
                except Exception:
                    return ""

            def parse_ft(u):
                try:
                    p = urllib.parse.urlsplit(u).path
                    _, ext = os.path.splitext(p)
                    return ext.lower().lstrip(".")
                except Exception:
                    return ""

            df_urls["host"] = df_urls["url"].map(parse_host)
            df_urls["filetype"] = df_urls["url"].map(parse_ft)

            # map shots by host
            shot_map = {}
            for h in df_urls["host"].dropna().unique():
                fname = self._match_shot_for_host(h)
                if fname:
                    shot_map[h] = f"/shots/{fname}"
            df_urls["shot"] = df_urls["host"].map(lambda h: shot_map.get(h, ""))

            df_ports = pd.DataFrame(self.naabu) if self.naabu else pd.DataFrame(columns=["host","ip","port","service"])
            df_v = pd.DataFrame(self.vulns) if self.vulns else pd.DataFrame(columns=["template","severity","host","matched-at","matched_at"])

            # Hosts summary
            if not df_ports.empty:
                ports_count = df_ports.groupby("host")["port"].nunique().reset_index().rename(columns={"port":"open_ports"})
            else:
                ports_count = pd.DataFrame(columns=["host","open_ports"])
            if not df_urls.empty:
                urls_count = df_urls.groupby("host")["url"].nunique().reset_index().rename(columns={"url":"url_count"})
            else:
                urls_count = pd.DataFrame(columns=["host","url_count"])
            hosts = ports_count.merge(urls_count, on="host", how="outer").fillna({"open_ports": 0, "url_count": 0})
            hosts["shot"] = hosts["host"].map(lambda h: shot_map.get(h, ""))

            # Filetypes per host
            if not df_urls.empty:
                filetypes = (df_urls[df_urls["filetype"] != ""]
                             .groupby(["host", "filetype"])["url"]
                             .nunique().reset_index().rename(columns={"url": "files"}))
            else:
                filetypes = pd.DataFrame(columns=["host","filetype","files"])

            return {
                "hosts": hosts.to_dict(orient="records"),
                "urls": df_urls.fillna("").to_dict(orient="records"),
                "vulns": df_v.fillna("").to_dict(orient="records"),
                "ports": df_ports.fillna("").to_dict(orient="records"),
                "filetypes": filetypes.to_dict(orient="records"),
            }


# ------------------------- File tailer -------------------------

class FileTailer(threading.Thread):
    """
    Tails a file and invokes a callback(line, bus) for each new line.
    """
    def __init__(self, path: Path, callback, bus: EventBus, stop_evt: threading.Event):
        super().__init__(daemon=True)
        self.path = Path(path) if path else None
        self.callback = callback
        self.bus = bus
        self.stop_evt = stop_evt
        self._pos = 0

    def run(self):
        while not self.stop_evt.is_set():
            try:
                if not self.path or not self.path.exists():
                    time.sleep(1.0)
                    continue
                size = self.path.stat().st_size
                if size < self._pos:
                    self._pos = 0
                if size > self._pos:
                    with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                        f.seek(self._pos)
                        chunk = f.read()
                        self._pos = f.tell()
                    for line in chunk.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            self.callback(line, self.bus)
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(1.0)


# ------------------------- HTTP handler -------------------------

class LiveHTTPHandler(http.server.BaseHTTPRequestHandler):
    state: GraphState = None
    bus: EventBus = None
    theme: str = "dark"

    def log_message(self, *_a, **_k):
        return

    def _send_bytes(self, data: bytes, ctype: str = "application/octet-stream", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self._send_bytes(data, "application/json; charset=utf-8", code)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/ui"):
            html = UI_HTML.replace("{{THEME}}", self.theme).encode("utf-8")
            return self._send_bytes(html, "text/html; charset=utf-8")
        if path == "/events":
            return self._sse_events()
        if path == "/ws":
            # handled by websockets server on port+1; here only return info
            return self._send_json({"error": "WebSocket served on port+1 /ws"}, 400)
        if path == "/graph.json":
            return self._send_json(self.state.to_d3())
        if path == "/tables.json":
            return self._send_json(self.state.tables())
        if path.startswith("/shots/"):
            rel = path.split("/shots/", 1)[1]
            f = (self.state.shots_dir / rel)
            if f.exists():
                ctype = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
                return self._send_bytes(f.read_bytes(), ctype)
            return self._send_json({"error": "not found"}, 404)
        if path == "/healthz":
            return self._send_json({"ok": True})
        return self._send_json({"error": "not found"}, 404)

    def _sse_events(self):
        import queue
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = self.bus.subscribe()
        try:
            while True:
                evt = q.get()
                data = json.dumps(evt).encode("utf-8")
                self.wfile.write(b"data: " + data + b"\n\n")
                self.wfile.flush()
        except Exception:
            pass
        finally:
            self.bus.unsubscribe(q)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ------------------------- Service -------------------------

class LiveService:
    """
    Start/stop the live server and file tailers.
    """
    def __init__(self, bind: str, out_dir: Path, mode: str = "auto", theme: str = "dark"):
        host, _, port = bind.partition(":")
        self.addr = (host or "127.0.0.1", int(port or "8765"))

        self.state = GraphState(out_dir)
        self.bus = EventBus()

        self.theme = theme
        LiveHTTPHandler.state = self.state
        LiveHTTPHandler.bus = self.bus
        LiveHTTPHandler.theme = theme

        self.stop_evt = threading.Event()
        self.httpd = ThreadingHTTPServer(self.addr, LiveHTTPHandler)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

        self.tailers = []

        # WebSocket server on port+1 (optional)
        self.ws_mode = (mode in ("auto", "ws")) and (websockets is not None)
        self.ws_thread = None
        if self.ws_mode:
            try:
                self.bus._ws_loop = asyncio.new_event_loop()
                self.ws_thread = threading.Thread(target=self._run_ws_server, daemon=True)
            except Exception:
                self.ws_mode = False

    def _run_ws_server(self):
        asyncio.set_event_loop(self.bus._ws_loop)
        async def handler(ws, _path):
            self.bus.ws_clients.add(ws)
            try:
                async for _ in ws:
                    pass
            except Exception:
                pass
            finally:
                self.bus.ws_clients.discard(ws)
        start_server = websockets.serve(handler, self.addr[0], self.addr[1] + 1, ping_interval=20, ping_timeout=20)
        self.bus._ws_loop.run_until_complete(start_server)
        self.bus._ws_loop.run_forever()

    def start(self, open_browser: bool = False):
        self.server_thread.start()
        if self.ws_thread:
            self.ws_thread.start()
        if open_browser:
            try:
                webbrowser.open(f"http://{self.addr[0]}:{self.addr[1]}/ui", new=2)
            except Exception:
                pass

    def stop(self):
        try:
            self.stop_evt.set()
            for t in self.tailers:
                try:
                    t.join(timeout=0.5)
                except Exception:
                    pass
            self.httpd.shutdown()
            if self.ws_thread and self.bus._ws_loop:
                self.bus._ws_loop.call_soon_threadsafe(self.bus._ws_loop.stop)
        except Exception:
            pass

    def watch_files(self,
                    dnsx: Optional[Path] = None,
                    httpx: Optional[Path] = None,
                    naabu: Optional[Path] = None,
                    nuclei: Optional[Path] = None,
                    dalfox: Optional[Path] = None,
                    kxss: Optional[Path] = None,
                    urls: Optional[Path] = None,
                    shots_dir: Optional[Path] = None):
        """
        Start tailers for provided files. Any None path is ignored.
        """
        def add_tail(p: Optional[Path], cb):
            if not p:
                return
            t = FileTailer(Path(p), cb, self.bus, self.stop_evt)
            t.start()
            self.tailers.append(t)

        add_tail(dnsx, self.state.update_from_dnsx)
        add_tail(httpx, self.state.update_from_httpx)
        add_tail(naabu, self.state.update_from_naabu)
        add_tail(urls, self.state.update_from_urls)
        if nuclei:
            add_tail(nuclei, self.state.update_from_nuclei)
        if dalfox:
            add_tail(dalfox, lambda line, bus: self.state.update_from_nuclei(json.dumps({"type": "dalfox", "raw": line}), bus))
        if kxss:
            add_tail(kxss, lambda line, bus: self.state.update_from_nuclei(json.dumps({"type": "kxss", "raw": line}), bus))
        if shots_dir:
            self.state.shots_dir = Path(shots_dir) / "screenshots"


# ------------------------- UI (HTML) -------------------------

UI_HTML = r"""<!doctype html>
<html lang="en" data-theme="{{THEME}}">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>bbdeluxe Live</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    :root { color-scheme: dark; }
    html[data-theme='light'] { filter: invert(1) hue-rotate(180deg); background: #f8fafc; }
    body { background: #0b1020; }
    .card { background: rgba(15, 23, 42, .85); border: 1px solid rgba(56, 189, 248, .25); border-radius: 16px; box-shadow: 0 0 20px rgba(56, 189, 248,.15); }
    .btn { border: 1px solid rgba(56,189,248,.4); padding: 6px 10px; border-radius: 10px; }
    .btn:hover { box-shadow: 0 0 12px rgba(34,197,94,.35); }
    .badge { border: 1px solid #94a3b8; padding: 2px 6px; border-radius: 8px; }
    .glow { box-shadow: 0 0 16px rgba(59, 130, 246, .35); }
    table.matrix { width: 100%; border-collapse: collapse; }
    table.matrix th, table.matrix td { border-bottom: 1px solid rgba(148,163,184,.25); padding: 6px 8px; vertical-align: middle; }
    table.matrix tr:hover { background: rgba(2,132,199,.12); }
    .thumb { width: 120px; height: 80px; object-fit: cover; border-radius: 8px; border: 1px solid rgba(56,189,248,.6); box-shadow: 0 0 10px rgba(56,189,248,.25); }
    .cell-url { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  </style>
</head>
<body class="text-slate-100">
  <div class="p-3 grid grid-cols-3 gap-3">
    <div class="col-span-2 card p-3">
      <div class="flex items-center gap-2 mb-2">
        <span class="text-lg font-bold">Graph</span>
        <input id="search" placeholder="Search (substring or /regex/)" class="ml-2 flex-1 bg-slate-800 rounded px-2 py-1 outline-none border border-cyan-700"/>
        <select id="kind" class="bg-slate-800 rounded px-2 py-1 border border-cyan-700">
          <option value="">All kinds</option>
          <option>host</option><option>ip</option><option>url</option><option>port</option><option>vuln</option><option>cdn</option><option>tech</option><option>filetype</option><option>param</option>
        </select>
        <select id="sev" class="bg-slate-800 rounded px-2 py-1 border border-cyan-700">
          <option value="">Any severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option>
        </select>
        <button id="reset" class="btn">Reset</button>
        <button id="theme" class="btn">Dark/Light</button>
      </div>
      <svg id="graph" width="100%" height="620" class="glow rounded-lg"></svg>
    </div>
    <div class="col-span-1 card p-3">
      <div class="tabs flex space-x-2 mb-2">
        <button class="tab btn" data-tab="hosts">Hosts</button>
        <button class="tab btn" data-tab="urls">URLs</button>
        <button class="tab btn" data-tab="vulns">Vulns</button>
        <button class="tab btn" data-tab="filetypes">Filetypes</button>
        <button class="tab btn" data-tab="node">Node</button>
      </div>
      <div class="flex items-center mt-1">
        <input id="tsearch" placeholder="Filter table..." class="w-full bg-slate-800 rounded px-2 py-1 border border-cyan-700"/>
      </div>
      <div id="panel" class="text-xs h-[540px] overflow-auto mt-2"></div>
    </div>
  </div>
<script>
const colorByKind = (k) => ({host:"#60a5fa", ip:"#34d399", url:"#fbbf24", port:"#f472b6", vuln:"#f87171", cdn:"#22d3ee", tech:"#94a3b8", filetype:"#a7f3d0", param:"#c084fc"}[k] || "#e5e7eb");
const sevSize = {critical:14, high:12, medium:10, low:8, info:7};

const svg = d3.select("#graph");
const width = document.getElementById("graph").clientWidth, height = 620;
const root = svg.append("g");
svg.call(d3.zoom().on("zoom", (ev)=> root.attr("transform", ev.transform)));

let graph = {nodes:[], links:[]}, filtered = null;
let link = root.append("g").attr("stroke","#334155").attr("stroke-opacity",0.7).selectAll("line");
let node = root.append("g").selectAll("circle");
let label = root.append("g").selectAll("text");

let sim = d3.forceSimulation()
  .force("link", d3.forceLink().id(d=>d.id).distance(70).strength(0.4))
  .force("charge", d3.forceManyBody().strength(-180))
  .force("center", d3.forceCenter(width/2, height/2));

function render(g){
  link = link.data(g.links, d => (d.source.id||d.source) + "-" + (d.target.id||d.target) + ":" + (d.rel||""));
  link.exit().remove();
  link = link.enter().append("line").attr("stroke-width",1).merge(link);

  node = node.data(g.nodes, d => d.id);
  node.exit().remove();
  const enter = node.enter().append("circle")
    .attr("r", d=> d.kind==="vuln" ? (sevSize[(d.severity||"info")]||8) : 6)
    .attr("fill", d=> colorByKind(d.kind))
    .call(drag(sim))
    .on("click", (_, d)=> showNode(d));
  node = enter.merge(node);

  label = label.data(g.nodes, d => d.id);
  label.exit().remove();
  label = label.enter().append("text")
    .text(d=> (d.kind==="url" ? new URL(d.id).hostname : (d.label || d.id)).slice(0,80))
    .attr("font-size", 10).attr("fill", "#94a3b8").merge(label);

  sim.nodes(g.nodes).on("tick", ()=>{
    link.attr("x1", d=>d.source.x).attr("y1", d=>d.source.y).attr("x2", d=>d.target.x).attr("y2", d=>d.target.y);
    node.attr("cx", d=>d.x).attr("cy", d=>d.y);
    label.attr("x", d=>d.x+8).attr("y", d=>d.y+4);
  });
  sim.force("link").links(g.links);
  sim.alpha(0.9).restart();
}

function drag(sim){
  function dragstarted(event, d) { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }
  function dragged(event, d) { d.fx=event.x; d.fy=event.y; }
  function dragended(event, d) { if (!event.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }
  return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
}

function applyFilter(){
  const q = document.getElementById("search").value.trim();
  const kind = document.getElementById("kind").value.trim();
  const sev = document.getElementById("sev").value.trim();
  const test = (txt)=>{
    if(!q) return true;
    if(q.startsWith("/") && q.endsWith("/")){
      try{ return new RegExp(q.slice(1,-1), "i").test(txt); }catch(e){ return true; }
    }
    return (txt||"").toLowerCase().includes(q.toLowerCase());
  };
  const nodes = graph.nodes.filter(n => (!kind || n.kind===kind) && (!sev || (n.kind!=="vuln" || (n.severity||"")===sev)) && (test(n.id) || test(n.label)));
  const ids = new Set(nodes.map(n=>n.id));
  const links = graph.links.filter(l=> ids.has(l.source.id||l.source) && ids.has(l.target.id||l.target));
  filtered = {nodes, links};
  render(filtered);
}

function reset(){ document.getElementById("search").value=""; document.getElementById("kind").value=""; document.getElementById("sev").value=""; filtered=null; render(graph); }
document.getElementById("reset").addEventListener("click", reset);
document.getElementById("search").addEventListener("input", applyFilter);
document.getElementById("kind").addEventListener("change", applyFilter);
document.getElementById("sev").addEventListener("change", applyFilter);

document.getElementById("theme").addEventListener("click", ()=>{
  const html = document.querySelector("html");
  html.dataset.theme = (html.dataset.theme === "dark" ? "light" : "dark");
});

function htmlEscape(s){ return (s||"").replace(/[&<>\"']/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m])); }

async function getTables(){
  const t = await (await fetch("/tables.json",{cache:"no-store"})).json();
  return t;
}

function renderTable(name, rows){
  const filter = document.getElementById("tsearch").value.toLowerCase();
  const keep = (o)=> !filter || JSON.stringify(o).toLowerCase().includes(filter);
  let html = '<table class="matrix"><thead><tr>';
  if(name==="hosts"){
    html += '<th>Host</th><th class="text-right">Ports</th><th class="text-right">URLs</th><th>Shot</th>';
  }else if(name==="urls"){
    html += '<th>Status</th><th>URL</th><th>Type</th><th>Shot</th>';
  }else if(name==="vulns"){
    html += '<th>Severity</th><th>Template</th><th>Host</th><th>Matched</th>';
  }else if(name==="filetypes"){
    html += '<th>Host</th><th>Filetype</th><th class="text-right">Files</th>';
  }else if(name==="node"){
    html += '<th>Field</th><th>Value</th>';
  }
  html += '</tr></thead><tbody>';

  const data = rows.filter(keep);
  if(name==="hosts"){
    for(const r of data){
      html += `<tr><td>${htmlEscape(r.host||"")}</td>
        <td class="text-right">${r.open_ports||0}</td>
        <td class="text-right">${r.url_count||0}</td>
        <td>${r.shot?`<img src="${r.shot}" class="thumb"/>`:''}</td></tr>`;
    }
  }else if(name==="urls"){
    for(const r of data){
      const short = (r.url||"").slice(0, 120);
      html += `<tr><td>${r.status_code||""}</td>
        <td class="cell-url" title="${htmlEscape(r.url||"")}">${htmlEscape(short)}</td>
        <td>${htmlEscape(r.filetype||"")}</td>
        <td>${r.shot?`<img src="${r.shot}" class="thumb"/>`:''}</td></tr>`;
    }
  }else if(name==="vulns"){
    for(const r of data){
      html += `<tr><td>${htmlEscape((r.severity||"").toUpperCase())}</td>
        <td>${htmlEscape(r.template||r.info?.name||"")}</td>
        <td>${htmlEscape(r.host||"")}</td>
        <td>${htmlEscape(r["matched-at"]||r["matched_at"]||"")}</td></tr>`;
    }
  }else if(name==="filetypes"){
    for(const r of data){
      html += `<tr><td>${htmlEscape(r.host||"")}</td><td>${htmlEscape(r.filetype||"")}</td><td class="text-right">${r.files||0}</td></tr>`;
    }
  }else if(name==="node"){
    for(const [k,v] of Object.entries(rows[0]||{})){
      html += `<tr><td>${htmlEscape(k)}</td><td>${htmlEscape(String(v))}</td></tr>`;
    }
  }
  html += '</tbody></table>';
  return html;
}

function setTab(name, payload){
  getTables().then(t=>{
    let rows = [];
    if(name==="node"){ rows = [payload]; }
    else { rows = t[name] || []; }
    document.getElementById("panel").innerHTML = renderTable(name, rows);
  });
}

document.getElementById("tsearch").addEventListener("input", ()=>{
  const active = document.querySelector(".tab.active");
  if(active){ active.click(); }
});

document.querySelectorAll(".tab").forEach(btn=>{
  btn.addEventListener("click", (ev)=>{
    document.querySelectorAll(".tab").forEach(b=>b.classList.remove("active"));
    ev.target.classList.add("active");
    const tab = ev.target.getAttribute("data-tab");
    setTab(tab, {});
  });
});

let transport = "poll";
function handleEvent(msg){ fetchGraph(); }
function setupTransport(){
  const loc = window.location;
  const wsUrl = (loc.protocol==="https:"?"wss://":"ws://")+loc.hostname+":"+(parseInt(loc.port||"80")+1)+"/ws";
  try{
    const ws = new WebSocket(wsUrl);
    ws.onopen = ()=>{ transport="ws"; };
    ws.onmessage = handleEvent;
    ws.onerror = ()=>{ setupSSE(); };
    ws.onclose = ()=>{ setupSSE(); };
  }catch(e){ setupSSE(); }
}
function setupSSE(){
  try{
    const es = new EventSource("/events");
    es.onmessage = handleEvent;
    es.onerror = ()=>{ transport="poll"; };
    transport = "sse";
  }catch(e){ transport="poll"; }
}

let lastGraph = null;
function fetchGraph(){
  fetch("/graph.json",{cache:"no-store"})
    .then(r=>r.json())
    .then(g=>{ lastGraph=g; graph=g; render(filtered||graph); })
    .catch(()=>{});
}

function showNode(d){
  document.querySelectorAll(".tab").forEach(b=>b.classList.remove("active"));
  document.querySelector('.tab[data-tab="node"]').classList.add("active");
  setTab("node", d);
}

setupTransport();
fetchGraph();
setInterval(()=>{ if(transport==="poll"){ fetchGraph(); } }, 2000);
</script>
</body>
</html>
"""


# ------------------------- Standalone runner (optional) -------------------------

def parse_args():
    p = argparse.ArgumentParser(description="bb_live.py standalone")
    p.add_argument("--bind", default="127.0.0.1:8765", help="Bind host:port")
    p.add_argument("--dir", default=".", help="Artifact directory to watch")
    p.add_argument("--open", action="store_true", help="Open browser to UI")
    p.add_argument("--theme", default="dark", choices=["dark", "light"])
    return p.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.dir).resolve()

    # Guess common files
    dnsx = out_dir / "dnsx.jsonl"
    httpx = out_dir / "httpx.jsonl"
    naabu = out_dir / "naabu.jsonl"
    nuclei = out_dir / "scan" / "nuclei.jsonl"
    dalfox = out_dir / "scan" / "dalfox.txt"
    kxss = out_dir / "scan" / "kxss.txt"
    urls = out_dir / "urls.txt"
    shots_dir = out_dir / "shots"

    svc = LiveService(args.bind, out_dir, mode="auto", theme=args.theme)
    svc.start(open_browser=args.open)
    svc.watch_files(
        dnsx=dnsx if dnsx.exists() else None,
        httpx=httpx if httpx.exists() else None,
        naabu=naabu if naabu.exists() else None,
        nuclei=nuclei if nuclei.exists() else None,
        dalfox=dalfox if dalfox.exists() else None,
        kxss=kxss if kxss.exists() else None,
        urls=urls if urls.exists() else None,
        shots_dir=shots_dir if shots_dir.exists() else None
    )

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()


if __name__ == "__main__":
    main()