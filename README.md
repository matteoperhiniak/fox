# fox

Detection and recon tool for authorized security audits and bug bounty.

## Disclaimer

Use `fox` only against systems you own or have **explicit written permission** to test.
Unauthorized use is illegal in most jurisdictions. The author assumes no liability
for misuse or damage caused by this tool.

## Features

- Subdomain discovery (crt.sh, hackertarget, optional DNS brute-force)
- HTTP fingerprinting (technologies, WAF/CDN, security headers, cookies, CORS)
- Port scanning with banner grabbing and TLS inspection
- Static analysis (secrets, Python taint heuristics, optional Semgrep)
- Bug-bounty modules: exposure sweep, inert reflection/SSTI/redirect probes, GraphQL discovery
- Output formats: JSON, SARIF, HTML, SQLite

## Install

```bash
git clone https://github.com/matteoperhiniak/fox.git
cd fox
python3 -m pip install -r requirements.txt
