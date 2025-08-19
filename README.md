

# BBdeluxe - A 🔥 Bug Bounty Multi-Super-Tool Deluxe + Live UI

Asset discovery → DNS/HTTP intel → URL & JS collection → Ports → Scanners → Grep intel → Fuzz → External intelligence → Live visualization.
This repo fuses a heavy-hitting recon pipeline with a real-time dashboard. Think ProjectDiscovery vibes, but with a custom D3 live graph, Pandas-driven matrices, and Aquatone screenshots wired right into your workflow.

> Built by and for offensive security engineers. Fast, skeptical, and brutally practical. 🧨




---

✨ Highlights

🕸️ Host Graph (D3 + NetworkX): visualize hosts ↔ IPs ↔ URLs ↔ ports ↔ tech ↔ CDNs ↔ filetypes ↔ params ↔ vulns (Nuclei/Dalfox/KXSS).

📊 Data Grids (Pandas): sortable/filterable matrices for Hosts, URLs, Vulns, Filetypes—with Aquatone thumbnails next to hosts/URLs.

⚡ Live Pipeline: tails dnsx.jsonl, httpx.jsonl, naabu.jsonl, crawled URLs, and scanner outputs in real time via WebSocket/SSE.

🧪 Fuzzing & Grep Intel: category-based payloads (XSS/LFI/SQLi/SSTI/SSRF/RCE) with caching, budgets, proxy rotation; secret/cloud regex sweeps on “juicy” files.

🔌 External Intel (opt-in): Shodan, Censys, FOFA, VirusTotal, urlscan.io, BinaryEdge (API keys supported).

🛰️ Screenshots: Aquatone snapshots aligned to hosts and surfaced inline in the matrices, PD-style.

🧭 Proxy-native: Everything can flow through Burp (e.g., --proxy http://127.0.0.1:8080).

---

🖼️ Screens (example data)
<img width="3398" height="1420" alt="image" src="https://github.com/user-attachments/assets/6db8492e-9855-4790-a96a-546c78ad68fe" />


D3 force-graph: hosts, URLs, IPs, ports, tech, filetypes, params, and vulns.


Hosts/URLs matrices with a thumbnail column (Aquatone).


---

🚀 Quick Start

# 1) Python deps
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 2) External CLI tools you actually want (see next section for options)
# (macOS/Linux via Homebrew)
brew install projectdiscovery/tap/httpx naabu nuclei subfinder dnsx shuffledns tlsx katana
brew install nmap
brew install aquatone
# Or see “Manual Go installs” below

## Live UI

Add --ui to start the embedded dashboard (binds to 127.0.0.1:8765, opens your browser):

The dashboard opens at http://127.0.0.1:8765/ui (dark theme; toggle dark/light in the UI).
WebSocket is served on port+1 automatically (fallback to SSE/poll if WS missing).


---

🧰 What gets visualized

Hosts ↔ IPs from dnsx, plus CDNs and tech from httpx.

URLs from httpx/gau/katana/hakrawler, with filetype and query param nodes extracted live.

Ports from naabu (+ optional nmap service scripts).

Vulns from nuclei (and optionally dalfox, kxss) with severity-scaled nodes.

Screenshots from aquatone (served from shots/screenshots/*.png) mapped to hosts/URLs and shown in the matrices.



---



2) External CLI tools (pick your stack)

Homebrew (macOS/Linux):

brew install projectdiscovery/tap/httpx naabu nuclei subfinder dnsx shuffledns tlsx katana
brew install nmap
brew install aquatone

Manual Go installs (examples):
```bash
# ProjectDiscovery
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Tomnomnom & friends
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/hacks/kxss@latest

# URL collectors
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/bp0lr/gauplus@latest

# Content discovery
go install github.com/ffuf/ffuf/v2@latest

# Screenshots
go install github.com/michenriksen/aquatone@latest


```
pipx install xsrfprobe
pipx install xsstrike


From source (examples):

massdns: build from repo (C); make sure resolvers file is present.

amass: install from release or go install ... per upstream docs.

dalfox, cariddi, csprecon, favirecon, cloakquest3r: follow their repos.


> ⚠️ Versions move. If a go install path changes (e.g., /v2, /v3), follow the official docs for the precise module.




---

## 🧪 Usage patterns

Basic run:
```
python3 bbdeluxe.py -d example.com --dnsx --tlsx --naabu --scan --grep-intel --fuzz xss sqli lfi rce
```

Minimal live recon

python3 bbdeluxe.py -d example.com --dnsx --naabu \
  --live-ui --live-open

Full pipeline (URL + JS + scanning) + UI
```bash
python3 bbdeluxe.py -d example.com --dnsx --tlsx --naabu --scan --grep-intel --fuzz xss sqli lfi rce --ui
```

With Burp

python3 bbdeluxe.py -d example.com \
  --proxy http://127.0.0.1:8080 \
  --ui --aquatone --shots-dir shots

Artifacts written under:

runs/<domain>/<YYYYMMDD_HHMMSS>/
  subs.txt
  dnsx.jsonl
  httpx.jsonl
  naabu.jsonl
  urls.txt
  scan/nuclei.jsonl
  ...



---

🖥️ The Live UI

Graph panel (left): pan/zoom, drag nodes, type/regex filter (/regex/), filter by kind and severity, click a node to inspect fields.

Matrices panel (right): tabs for Hosts, URLs, Vulns, Filetypes, and Node details. A filter box narrows rows.
Hosts/URLs tables display a thumbnail if an Aquatone shot for that host exists.


Aquatone mapping: filenames in shots/screenshots/*.png are matched by host substring.
If you want perfect URL→screenshot mapping, hook the Aquatone HTML/JSON index and adjust _match_shot_for_host() in bb_live.py.


---

🔐 Proxies, APIs & env

Burp/Proxy: --proxy http://127.0.0.1:8080 also sets HTTP_PROXY/HTTPS_PROXY for subprocess tools and requests.

API keys (opt-in features): set these env vars to enable external intel stages:

SHODAN_API_KEY, CENSYS_ID, CENSYS_SECRET, FOFA_EMAIL, FOFA_KEY, VT_KEY, URLSCAN_KEY, BINARYEDGE_KEY.




---

🧱 Troubleshooting

No nodes in graph? Ensure your tools produced output (e.g., httpx.jsonl not empty). The live server tails files and will update incrementally.

WS not connecting? UI falls back to SSE/poll automatically. You can install websockets to enable WS.

No thumbnails? Confirm PNGs exist under shots/screenshots/. Names should include the host string somewhere.

Permissions: Some tools need elevated caps (raw sockets for port scans). Run appropriately.

Performance: Large scopes? Use flags like --grep-max, fuzzer budgets, and limit ffuf roots.



---

🧭 Roadmap (ideas)

📦 Export to Parquet/CSV for DataFrame nerds.

🖼️ Modal preview for screenshots + side-by-side diffs.

🧰 Gowitness/EyeWitness fallback if Aquatone missing.

🧷 Pin/lock nodes and persist layouts across sessions.



---

⚖️ License & Ethics

Use this only on targets you are explicitly authorized to test.
You are responsible for compliance with all applicable laws and program policies. Don’t be the reason we can’t have nice things.


---

Happy hunting. 🏴‍☠️

