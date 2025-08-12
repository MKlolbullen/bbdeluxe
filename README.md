# bbdeluxe

# Bug Bounty Multi‑Super‑Tool Deluxe (bbdeluxe)

> **Industrial‑grade recon + triage pipeline** for bug bounty / pentests. Batteries included: subdomain discovery, DNS/HTTP tech fingerprinting, URL crawling, port scans, fuzzing, secret hunting, SSRF candidate detection, OOB integrations, and external intel (Shodan/Censys/FOFA/VirusTotal/urlscan/BinaryEdge).  
> **Burp‑friendly by default** — point traffic through your proxy and let your intercept rules/web vulns extensions shine.

---

## ✨ Highlights

- **Subdomains:** assetfinder / subfinder / chaos / amass → `dsieve` → `shuffledns` or `massdns` → `dnsx`
- **Tech + alive probing:** `httpx` (title, techs, CDN, IP, status, CL) with optional proxy
- **TLS intel:** `tlsx` SAN harvesting + **diff report** → feed back to subdomain list
- **URLs at scale:** `gau`/`gauplus`, `katana`, `hakrawler`, **JS endpoint** extraction via `linkfinder`
- **Ports:** `naabu` → service‑aware URL construction → fallback scheme re‑probe; optional `nmap`
- **Extras:** `favirecon` (+mmh3 → names); `csprecon` (+heuristics); `cariddi`; `cloakquest3r`
- **Secret grep:** headers + bodies on juicy extensions (`.js`, `.json`, `.env`, `.conf`, …) with AWS/GCP/Azure/DO patterns, JWTs, DB URIs, private keys, **k8s/docker envs**
- **SSRF candidate finder:** ranks parameters likely vulnerable (`url`, `redirect_uri`, `dest`, etc.), stores a flat target list
- **Payload fuzzer:** categories (`xss`, `lfi`, `sqli`, `domxss`, `ssti`, `ssrf`, `rce`) with **per‑host or per‑scheme budgets**, UA/proxy rotation, **SQLite de‑dupe**, and **double‑URL‑encoding** switch
- **OOB:** optional `interactsh-client` for SSRF/XXE/Blind RCE callbacks
- **External intel (opt‑in):** Shodan, Censys, FOFA, VirusTotal, urlscan.io, BinaryEdge
- **BurpSuite co‑op:** global proxy (`-p http://127.0.0.1:8080`) routes all HTTP requests and `httpx` through Burp

---

## 🧭 Pipeline (high‑level)

---

## ⚙️ Installation

### 1) Python deps
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install rich requests
```

### 2) Third‑party binaries (install what you plan to use)

- **ProjectDiscovery**: `httpx`, `subfinder`, `dnsx`, `naabu`, `tlsx`, `katana`, `nuclei`
- **Others**: `assetfinder`, `amass`, `chaos` (requires key), `shuffledns`, `massdns`, `dsieve`, `hakrawler`, `linkfinder`, `favirecon`, `csprecon`, `ffuf`, `cariddi`, `interactsh-client`, `cloakquest3r`, `nmap`

Examples:
```bash
# Go tools (examples)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip install linkfinder

# Interactsh
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

> Tip: ensure your `GOBIN` is on `PATH`. For Debian/Ubuntu: `apt install -y nmap massdns` etc.

---

## 🚀 Quickstart

```bash
# 1) Minimal recon (no heavy tools), save to ./runs/<domain>/<ts>
python3 bbdeluxe.py -d example.com --dnsx -p http://127.0.0.1:8080

# 2) Full recon + TLS + URLs + grep + SSRF candidates, through Burp
python3 bbdeluxe.py -d example.com -p http://127.0.0.1:8080 \
  --dnsx --tlsx --grep-intel

# 3) Add ports + scans + OOB + fuzz (aggressive)
python3 bbdeluxe.py -d example.com -p http://127.0.0.1:8080 \
  --dnsx --tlsx --naabu --scan --interactsh 120 \
  --fuzz xss sqli lfi ssti ssrf rce --fuzz-per-scheme 30 --ua-rotate
```

- Output root: `runs/<domain>/<YYYYMMDD_HHMMSS>/`
- Unified manifest: `intel.json`
- Normalized view: `intel_normalized.json`
- Handy files: `subs.txt`, `alive_roots.txt`, `urls.txt`, `js.txt`, `grep_summary.json`, `ssrf_candidates.ndjson`, `payload_fuzz.ndjson`

---

## 🧪 BurpSuite Co‑Use

- Start Burp on **`127.0.0.1:8080`** (default).
- Run `bbdeluxe` with `-p http://127.0.0.1:8080`  
  This sets `HTTP_PROXY`/`HTTPS_PROXY` and forwards `httpx` & Python `requests` traffic.
- Use Burp’s **Logger/Proxy/Repeater** to watch requests, enrich with extensions (e.g., Param Miner, Backslash Powered Scanner).
- Optional: proxy pool rotation with `--proxy-file proxies.txt` (one URL per line). The `-p` proxy is used as the first/default proxy.

> Heads‑up: heavy fuzzing via Burp can be noisy; throttle with `--fuzz-per-host` or scope via `--fuzz-per-scheme` to control volume.

---

## 🔌 External Intel APIs (opt‑in)

Enable with `--ext-intel` and pass keys via flags or env vars:

| Source        | Flag(s)                        | ENV                     | Notes |
|---------------|--------------------------------|-------------------------|-------|
| Shodan        | `--shodan-key`                 | `SHODAN_API_KEY`        | Enrich IPs from `dnsx`/`httpx` |
| Censys        | `--censys-id --censys-secret`  | `CENSYS_ID`, `CENSYS_SECRET` | Host search (HTTP services, DNS names) |
| FOFA          | `--fofa-email --fofa-key`      | `FOFA_EMAIL`, `FOFA_KEY`| Domain‑centric search |
| VirusTotal    | `--vt-key`                     | `VT_KEY`                | Domain and subdomain intel |
| urlscan.io    | `--urlscan-key` (optional)     | `URLSCAN_KEY`           | Public/Keyed search |
| BinaryEdge    | `--binaryedge-key`             | `BINARYEDGE_KEY`        | Per‑IP telemetry |

Outputs are written under `extintel/` in the run directory.

Example:
```bash
export SHODAN_API_KEY=xxx CENSYS_ID=xxx CENSYS_SECRET=xxx VT_KEY=xxx
python3 bbdeluxe.py -d example.com --dnsx --tlsx --ext-intel
```

---

## 🔍 Secret & Intel Grep

Enable with `--grep-intel`. The stage fetches **only “interesting” extensions**:
`.js,.css,.php,.env,.bak,.conf,.config,.ini,.cfg,.yaml,.yml,.json,.txt,.properties`

Patterns include (non‑exhaustive):

- **AWS**: `AKIA...` access keys, secret access key prompts, S3 bucket forms (`s3://`, `*.s3.amazonaws.com`)
- **GCP**: `AIza...` API keys, `gs://` buckets
- **Azure**: storage connection strings, `*.blob.core.windows.net/...`
- **DigitalOcean**: `*.digitaloceanspaces.com/...`
- Generic: Slack/GitHub tokens, JWTs, DB URIs, private key headers, k8s/docker envs

Artifacts:
- `grep_intel.ndjson` — per‑URL hits (headers & bodies) + redirect trails
- `grep_summary.json` — pattern counts and top URLs

Tune with `--grep-max`, `--grep-size`, `--grep-timeout`.

---

## 🕳️ SSRF Candidate Finder

Automatically ranks parameters that smell like SSRF:
- Names: `url, uri, path, dest, redirect(_uri|_url), next, return, image, target, to, continue, callback, link, file, fetch, proxy, feed, json, xml`
- Values containing URIs, internal hosts/IPs, `@`, `:`, `&`, `$`, etc.

Outputs:
- `ssrf_candidates.ndjson` — `{ url, params:[{param, value, score}] }`
- `ssrf_params.txt` — flat list for triage/fuzz targetting

Use together with OOB by adding `--interactsh 120` and fuzz category `ssrf` (see next section).

---

## 💣 Payload Fuzzer

```bash
--fuzz xss sqli lfi ssti ssrf rce domxss \
--fuzz-per-host 50 --fuzz-per-scheme 30 --ua-rotate \
--proxy-file proxies.txt --cache-db fuzz_cache.sqlite \
--encode-payloads 2
```

- **Budgets**: cap requests per host or per `(scheme, host)`; avoid stampeding a single endpoint.
- **Encoding**: `--encode-payloads 0|1|2` (double‑encoding helps bypass naive WAFs).
- **OOB**: with `--interactsh N`, SSRF payloads also set `X‑Forwarded‑Host` and `Referer` to your OOB domain.
- **Reports**: `reports/summary.json` + per‑category `.ndjson` under `reports/`.

---

## 🧰 Other Useful Stages

- **favirecon** → `favirecon.txt` and optional `favirecon_mapped.json` via `--mmh3-map hashes.json`
- **csprecon** → `csprecon.txt` + `csp_analysis.json` (heuristics for `unsafe-inline`, missing `object-src 'none'`, wildcard `script-src`, no nonce/hash)
- **naabu** → `naabu.jsonl` then **service‑aware** URL construction and `httpx` re‑probe (+HTTP↔HTTPS fallback)
- **nmap** → one output file per host with detected ports

---

## 📁 Output Structure

```
runs/<domain>/<timestamp>/
  subs.txt                 # deduped subdomains
  dnsx.jsonl               # DNS answers
  alive_roots.txt          # alive base URLs from httpx
  httpx.jsonl              # httpx JSON (tech, status, cl, ip, cdn, title)
  tlsx.jsonl               # certificate scan JSON
  subs_from_tls.txt        # SAN-derived subs
  urls.txt                 # collected URLs
  js.txt                   # linkfinder endpoints
  naabu.jsonl, nmap/       # ports
  favirecon.txt, csprecon.txt, csp_analysis.json
  grep_intel.ndjson, grep_summary.json
  ssrf_candidates.ndjson, ssrf_params.txt
  payload_fuzz.ndjson, reports/
  extintel/                # shodan/censys/fofa/vt/urlscan/binaryedge outputs (opt)
  intel.json               # run manifest
  intel_normalized.json    # normalized view
```

---

## 🧩 Useful CLI Flags (cheatsheet)

```
-d, --domain              Target domain
-p, --proxy               Global HTTP/HTTPS proxy (Burp friendly)
--dnsx, --tlsx            DNS answers & TLS SAN harvesting
--naabu, --nmap           Port scan and service fingerprinting
--grep-intel              Secret/token/bucket regex hunting
--interactsh N            Enable OOB polling for N seconds
--fuzz <cats...>          xss lfi sqli ssti ssrf rce domxss
--fuzz-per-host N         Per-host budget
--fuzz-per-scheme N       Separate budgets for http/https
--encode-payloads N       URL-encode payloads 0/1/2 times
--ffuf --ffuf-wl path     Directory brute-forcing
--favirecon --mmh3-map    Favicon hash mapping
--csprecon                CSP collection + heuristics
--ext-intel               Shodan/Censys/FOFA/VT/urlscan/BinaryEdge (keys)
--ndjson                  Also emit hosts.ndjson/urls.ndjson/vulns.ndjson
--use-workdir             Mirror outputs to ~/work/bug_bountys/<domain>_bugbounty
```

---

## 🛡️ Ethics, Scope & Safety

- **Only test assets you’re authorized to test.** Respect program rules & rate limits.
- The tool can get **noisy** — set budgets, throttle, and use `--ffuf-max`, `--fuzz-per-host`, and `--fuzz-per-scheme`.
- When using external intel APIs, be mindful of **privacy and ToS**.  
- Consider running through Burp with **scope control** and **match/replace** to avoid unintended targets.

---

## 🗺️ Roadmap (nice‑to‑haves)

- Enrich pattern packs (Stripe/Twilio/Firebase/Mapbox/Datadog/etc.)
- Param miner style discovery for non‑obvious SSRF sinks
- Optional Docker image with pinned tools

---

## 📦 Credits

Built for speed and clarity; orchestrates fantastic OSS from ProjectDiscovery and friends.  
PRs welcome — keep it **safe**, **fast**, and **scoped**.

---

### Run it

```bash
python3 bbdeluxe.py -h
```

Happy hunting. 🐉
