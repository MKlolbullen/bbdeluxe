#!/usr/bin/env python3
# See previous message for full comments. Minimal stdlib server with NetworkX + Pandas support.
import json, threading, time, socketserver, http.server, urllib.parse, webbrowser
from pathlib import Path
try: import pandas as pd
except Exception: pd=None
try: import networkx as nx
except Exception: nx=None

class GraphState:
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.lock = threading.RLock()
        self.g = nx.Graph() if nx else None
        self.httpx, self.dnsx, self.naabu, self.vulns = [], [], [], []

    def _add_node(self, n, **attrs):
        if not self.g: return
        if n not in self.g: self.g.add_node(n, **attrs)
        else: self.g.nodes[n].update({k:v for k,v in attrs.items() if v is not None})
    def _add_edge(self, a,b, **attrs):
        if self.g and a and b: self.g.add_edge(a,b,**attrs)

    def update_from_dnsx(self, line):
        try: j=json.loads(line)
        except Exception: return
        host = j.get("host") or j.get("fqdn") or j.get("input") or j.get("name")
        ip = j.get("a") or j.get("ip") or j.get("answer")
        ips = ip if isinstance(ip, list) else ([ip] if isinstance(ip,str) else [])
        with self.lock:
            self.dnsx.append(j)
            if self.g and host:
                self._add_node(host, kind="host")
                for addr in ips:
                    self._add_node(addr, kind="ip")
                    self._add_edge(host, addr, rel="resolves")

    def update_from_httpx(self, line):
        try: j=json.loads(line)
        except Exception: return
        url=j.get("url"); host=j.get("host") or (urllib.parse.urlsplit(url).netloc if url else None)
        cdn=j.get("cdn"); status=j.get("status_code"); title=j.get("title"); ip=j.get("ip"); tech=j.get("tech") or []
        with self.lock:
            self.httpx.append(j)
            if self.g:
                if host: self._add_node(host, kind="host")
                if url: self._add_node(url, kind="url", status=status, title=title)
                if url and host: self._add_edge(host, url, rel="serves")
                if ip: self._add_node(str(ip), kind="ip"); self._add_edge(host, str(ip), rel="served_by")
                if cdn: self._add_node(f"cdn:{host}", kind="cdn"); self._add_edge(host, f"cdn:{host}", rel="cdn")
                for t in tech: self._add_node(f"tech:{t}", kind="tech", label=t); self._add_edge(host, f"tech:{t}", rel="tech")

    def update_from_naabu(self, line):
        try: j=json.loads(line)
        except Exception: return
        host=j.get("host") or j.get("ip"); port=j.get("port"); service=(j.get("service") or "").lower()
        if not (host and port): return
        with self.lock:
            self.naabu.append(j)
            if self.g:
                pnode=f"port:{host}:{port}"; self._add_node(host, kind="host"); self._add_node(pnode, kind="port", port=port, service=service); self._add_edge(host, pnode, rel="open")

    def update_from_nuclei(self, line):
        try: j=json.loads(line)
        except Exception: j={"type":"raw","raw":line}
        with self.lock:
            self.vulns.append(j)
            if self.g:
                host = j.get("host") or j.get("matcher_name") or j.get("matched-at") or j.get("matched_at")
                sev  = j.get("severity") or "info"
                tag  = j.get("template") or (j.get("info",{}).get("name") if isinstance(j.get("info"), dict) else "finding")
                vnode=f"vuln:{tag}:{host}"
                self._add_node(vnode, kind="vuln", severity=sev, label=tag)
                if host and host in self.g: self._add_edge(host, vnode, rel="vuln")
                url=j.get("matched-at") or j.get("matched_at")
                if isinstance(url,str) and url in self.g: self._add_edge(url, vnode, rel="vuln")

    def to_d3(self):
        with self.lock:
            if not self.g: return {"nodes": [], "links": []}
            nodes=[{"id":n, **(self.g.nodes[n] or {})} for n in self.g.nodes]
            links=[{"source":a, "target":b, **(self.g.edges[a,b] or {})} for a,b in self.g.edges]
            return {"nodes":nodes, "links":links}

    def tables(self):
        with self.lock:
            if pd is None:
                return {"hosts": len(set([ (x.get("host") or x.get("ip")) for x in self.naabu ])),
                        "urls": len(self.httpx), "vulns": len(self.vulns)}
            import urllib.parse as _u
            df_httpx = pd.DataFrame(self.httpx) if self.httpx else pd.DataFrame(columns=["url","status_code","title","tech","ip","cdn"])
            dns_rows=[]; 
            for j in self.dnsx:
                h=j.get("host") or j.get("fqdn") or j.get("input") or j.get("name")
                ip=j.get("a") or j.get("ip") or j.get("answer")
                if isinstance(ip,list):
                    for i in ip: dns_rows.append({"host":h,"ip":i})
                elif isinstance(ip,str):
                    dns_rows.append({"host":h,"ip":ip})
            df_dns = pd.DataFrame(dns_rows) if dns_rows else pd.DataFrame(columns=["host","ip"])
            df_ports = pd.DataFrame(self.naabu) if self.naabu else pd.DataFrame(columns=["host","ip","port","service"])
            df_v     = pd.DataFrame(self.vulns) if self.vulns else pd.DataFrame(columns=["template","severity","host","matched-at","matched_at"])
            if not df_httpx.empty:
                df_httpx['host'] = df_httpx['url'].apply(lambda u: _u.urlsplit(u).netloc if isinstance(u,str) else "")
                cdn_flag = df_httpx.groupby('host')['cdn'].max().reset_index(name='cdn') if 'cdn' in df_httpx else pd.DataFrame(columns=['host','cdn'])
            else:
                cdn_flag = pd.DataFrame(columns=['host','cdn'])
            host_ports = df_ports.groupby('host')['port'].nunique().reset_index(name='open_ports') if not df_ports.empty else pd.DataFrame(columns=['host','open_ports'])
            host_ips   = df_dns.groupby('host')['ip'].nunique().reset_index(name='ips') if not df_dns.empty else pd.DataFrame(columns=['host','ips'])
            hosts_sum  = host_ports.merge(host_ips, on='host', how='outer').merge(cdn_flag, on='host', how='outer').fillna({'cdn': False, 'open_ports': 0, 'ips': 0})
            return {
                "hosts": hosts_sum.to_dict(orient="records"),
                "urls": df_httpx[['url','status_code','title','tech','ip','cdn']].fillna("").to_dict(orient="records") if not df_httpx.empty else [],
                "vulns": df_v.to_dict(orient="records") if not df_v.empty else [],
                "ports": df_ports[['host','port','service']].fillna("").to_dict(orient="records") if not df_ports.empty else [],
                "dns": df_dns.to_dict(orient="records") if not df_dns.empty else [],
            }

class Handler(http.server.BaseHTTPRequestHandler):
    state=None
    def log_message(self, *a, **k): return
    def _send(self, data, ctype="application/json; charset=utf-8", code=200):
        if isinstance(data, (dict,list)): data=json.dumps(data).encode(); ctype="application/json; charset=utf-8"
        elif isinstance(data,str): data=data.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        p=self.path.split("?")[0]
        if p in ("/","/ui"): return self._send(UI_HTML, "text/html; charset=utf-8")
        if p=="/graph.json": return self._send(self.state.to_d3())
        if p=="/tables.json": return self._send(self.state.tables())
        if p=="/healthz": return self._send({"ok":True})
        return self._send({"error":"not found"}, code=404)

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads=True; allow_reuse_address=True

class LiveService:
    def __init__(self, bind: str, out_dir: Path):
        host, _, port = bind.partition(":"); self.addr=(host or "127.0.0.1", int(port or "8765"))
        self.state=GraphState(out_dir); Handler.state=self.state
        self.httpd=ThreadingHTTPServer(self.addr, Handler); self.stop_evt=threading.Event()
        self.server_thread=threading.Thread(target=self.httpd.serve_forever, daemon=True); self.tailers=[]
    def start(self, open_browser=False):
        self.server_thread.start()
        if open_browser: webbrowser.open(f"http://{self.addr[0]}:{self.addr[1]}/ui", new=2)
    def stop(self):
        try:
            self.stop_evt.set()
            for t in self.tailers:
                try: t.join(timeout=0.5)
                except Exception: pass
            self.httpd.shutdown()
        except Exception: pass
    def watch_files(self, dnsx=None, httpx=None, naabu=None, nuclei=None, dalfox=None, kxss=None):
        def add_tail(path, cb):
            if not path: return
            t=FileTailer(Path(path), cb, self.stop_evt); t.start(); self.tailers.append(t)
        add_tail(dnsx, self.state.update_from_dnsx)
        add_tail(httpx, self.state.update_from_httpx)
        add_tail(naabu, self.state.update_from_naabu)
        if nuclei: add_tail(nuclei, self.state.update_from_nuclei)
        if dalfox: add_tail(dalfox, lambda line: self.state.update_from_nuclei(json.dumps({"type":"dalfox","raw":line})))
        if kxss:   add_tail(kxss,   lambda line: self.state.update_from_nuclei(json.dumps({"type":"kxss","raw":line})))

class FileTailer(threading.Thread):
    def __init__(self, path: Path, cb, stop_evt: threading.Event):
        super().__init__(daemon=True); self.path=Path(path); self.cb=cb; self.stop_evt=stop_evt; self.pos=0
    def run(self):
        while not self.stop_evt.is_set():
            try:
                if not self.path.exists(): time.sleep(1.0); continue
                with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self.pos)
                    for line in f:
                        s=line.strip()
                        if s: 
                            try: self.cb(s)
                            except Exception: pass
                    self.pos=f.tell()
            except Exception:
                pass
            time.sleep(1.0)

UI_HTML = """<!doctype html>
<html><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>bbdeluxe Live</title>
<script src='https://cdn.tailwindcss.com'></script>
<script src='https://d3js.org/d3.v7.min.js'></script>
</head>
<body class='bg-slate-950 text-slate-100'>
<div class='grid grid-cols-3 gap-4 p-4'>
  <div class='col-span-2 bg-slate-900/70 rounded-2xl p-3 shadow'>
    <div class='flex justify-between items-center mb-2'>
      <h1 class='text-xl font-bold'>Live Graph</h1>
      <div id='stats' class='text-sm text-slate-400'></div>
    </div>
    <svg id='graph' width='100%' height='640'></svg>
  </div>
  <div class='col-span-1 bg-slate-900/70 rounded-2xl p-3 shadow'>
    <div class='tabs flex space-x-2 mb-2'>
      <button class='tab px-3 py-1 rounded bg-slate-800' data-tab='node'>Node</button>
      <button class='tab px-3 py-1 rounded bg-slate-800' data-tab='hosts'>Hosts</button>
      <button class='tab px-3 py-1 rounded bg-slate-800' data-tab='urls'>URLs</button>
      <button class='tab px-3 py-1 rounded bg-slate-800' data-tab='vulns'>Vulns</button>
    </div>
    <div id='panel' class='text-sm h-[600px] overflow-auto whitespace-pre-wrap'></div>
  </div>
</div>
<script>
const colorByKind=k=>({host:'#60a5fa',ip:'#34d399',url:'#fbbf24',port:'#f472b6',vuln:'#f87171',cdn:'#a78bfa',tech:'#94a3b8'}[k]||'#e5e7eb');
const svg=d3.select('#graph');const width=document.getElementById('graph').clientWidth,height=640;
const g=svg.append('g');svg.call(d3.zoom().on('zoom',ev=>g.attr('transform',ev.transform)));
let sim=d3.forceSimulation().force('link',d3.forceLink().id(d=>d.id).distance(70).strength(0.4)).force('charge',d3.forceManyBody().strength(-180)).force('center',d3.forceCenter(width/2,height/2));
let link=g.append('g').attr('stroke','#475569').attr('stroke-opacity',.7).selectAll('line');let node=g.append('g').selectAll('circle');let label=g.append('g').selectAll('text');
function render(graph){
  document.getElementById('stats').innerText=`nodes ${graph.nodes.length} • links ${graph.links.length}`;
  link=link.data(graph.links,d=>d.source.id+'-'+d.target.id);link.exit().remove();link=link.enter().append('line').attr('stroke-width',1).merge(link);
  node=node.data(graph.nodes,d=>d.id);node.exit().remove();const ne=node.enter().append('circle').attr('r',6).attr('fill',d=>colorByKind(d.kind)).call(drag(sim)).on('click',(_,d)=>showNode(d));node=ne.merge(node);
  label=label.data(graph.nodes,d=>d.id);label.exit().remove();label=label.enter().append('text').text(d=>(d.kind==='url'?new URL(d.id).hostname:(d.label||d.id)).slice(0,60)).attr('font-size',10).attr('fill','#94a3b8').merge(label);
  sim.nodes(graph.nodes).on('tick',()=>{link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);node.attr('cx',d=>d.x).attr('cy',d=>d.y);label.attr('x',d=>d.x+8).attr('y',d=>d.y+4)});
  sim.force('link').links(graph.links);sim.alpha(.9).restart();
}
function drag(sim){function s(e,d){if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y}function r(e,d){d.fx=e.x;d.fy=e.y}function e(e,d){if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}return d3.drag().on('start',s).on('drag',r).on('end',e)}
async function refresh(){try{const r=await fetch('/graph.json',{cache:'no-store'});render(await r.json())}catch(e){} setTimeout(refresh,2000)}
function setTab(name,data){const p=document.getElementById('panel');p.textContent=(Array.isArray(data)?data:[data]).map(x=>JSON.stringify(x,null,2)).join('\\n\\n')}
async function showNode(d){let payload={node:d};try{const t=await (await fetch('/tables.json',{cache:'no-store'})).json();payload.tables=t}catch(e){}document.querySelectorAll('.tab').forEach(b=>b.classList.remove('bg-sky-800'));document.querySelector('.tab[data-tab=\"node\"]').classList.add('bg-sky-800');setTab('node',payload)}
document.querySelectorAll('.tab').forEach(btn=>{btn.addEventListener('click',async ev=>{const tab=ev.target.getAttribute('data-tab');const t=await (await fetch('/tables.json',{cache:'no-store'})).json();setTab(tab,t[tab]||t);document.querySelectorAll('.tab').forEach(b=>b.classList.remove('bg-sky-800'));ev.target.classList.add('bg-sky-800')})})
refresh();
</script>
</body></html>
"""
