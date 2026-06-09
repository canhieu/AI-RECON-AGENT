# AI Recon Agent - Setup

## Requirements

- Python 3.12+
- Go 1.22+ for Go-based recon tools
- Node.js 20+ optional
- `sudo` for package installation
- ShineShop API key in `.env`
- Kali packages such as `nmap`, `whatweb`, `curl`, `ffuf`, service clients, and `searchsploit`

## Quick Install

```bash
cd ai-recon-agent

sudo apt install -y whois dnsutils nmap masscan whatweb curl netcat-openbsd \
  smbclient redis-tools mysql-client ldap-utils nfs-common \
  snmp sshpass freetds-bin golang-go exploitdb

export PATH=$PATH:/usr/lib/go-1.22/bin:$HOME/go/bin:$HOME/.local/bin
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/sa7mon/s3scanner@latest
go install -v github.com/assetnote/kiterunner/cmd/kiterunner@latest
cp ~/go/bin/kiterunner ~/.local/bin/kr

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pipx install arjun
pipx install shodan

mkdir -p tools
git clone --depth 1 https://github.com/dolevf/graphw00f.git tools/graphw00f
git clone --depth 1 https://github.com/s0md3v/Corsy.git tools/Corsy
git clone --depth 1 https://github.com/drwetter/testssl.sh.git tools/testssl.sh
git clone --depth 1 https://github.com/laramies/theHarvester.git tools/theHarvester
pip install -e tools/theHarvester

cp .env.example .env
```

`kiterunner`, `graphw00f`, `Corsy`, `testssl`, `theHarvester`, `s3scanner`, `shodan`, and `trufflehog` are registered support tools, but not all are wired into the current default worker chain.

## Environment

```text
SHINE_API_KEY=sk-...
SHINE_BASE_URL=https://api.shineshop.dev/v1
SHINE_MODEL=codex/gpt5.5
SHINE_MODEL_CHEAP=codex/gpt-5.4-mini
SHODAN_API_KEY=
DEHASHED_API_KEY=
```

Runtime CLI no longer accepts `--model`, `--model-cheap`, or `--safe-mode`; model values are loaded from config/environment for analysis only.

## Run

```bash
source .venv/bin/activate
export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin
python3 agent/main.py --target example.com --max-steps 25 --verbose
AI_RECON_TUI=0 python3 agent/main.py --target example.com --max-steps 25 --verbose
```

Notes:

- `--threads` exists in CLI output but targets currently run sequentially.
- `--output` exists but the orchestrator still writes to `outputs/<target>/`.
- `config/scope.yaml` documents scope policy but is not enforced before command execution yet.

## RTK

Project instructions load through:

- `AGENTS.md`
- `AGENT.md`
- `RTK.md`

Use RTK for compact file/system inspection. Do not wrap recon binaries with RTK.

Check:

```bash
rtk --version
rtk init --codex --show
rtk gain
```

Restart the agent session after editing instruction files.

## UI

- Textual TUI needs a real TTY and `textual` installed.
- Non-TTY runs fall back to console.
- Disable TUI with `AI_RECON_TUI=0`.
- Live log path: `outputs/<target>/live-activity.log`.

## Tools

| Family | Tools |
|---|---|
| Passive | `whois`, `dig`, `crt_sh`, `subfinder`, `gau`, `dnsx`, `theHarvester` |
| Surface | `rustscan`, `nc_scan`, `nmap`, `masscan`, `whatweb`, `httpx`, `ffuf_dir`, `ffuf_vhost`, `ffuf_recursive`, `ffuf_ext`, `cms_detect`, `nuclei_general` |
| Service | `smb_check`, `ftp_check`, `mysql_check`, `redis_check`, `ldap_check`, `nfs_check`, `smtp_check`, `ssh_check`, `mssql_check`, `snmp_check`, `vnc_check`, `dns_check` |
| Deep/artifact | `web_download_interesting`, `ftp_deep`, `smb_deep`, `redis_deep`, `artifact_analyze` |
| Web expansion | `redirect_check`, `hosts_add`, `curl_headers`, `curl_body`, `katana`, `js_dump`, `js_deobfuscate`, `js_mine`, `arjun`, `cms_detect`, `cve_search`, `nuclei_general` |
| Registered support | `jsluice`, `kiterunner`, `graphw00f`, `s3scanner`, `shodan`, `trufflehog`, `corsy`, `nuclei_tech`, `testssl` |

## Wordlists

Fuzzing uses system seclists by default:

```text
/usr/share/seclists/Discovery/Web-Content/
```

Policy:

- `ffuf_dir`: default `medium`.
- `ffuf_recursive` and `ffuf_ext`: default `common` to control runtime.
- Escalate to `big` when signal warrants it or user requests deep/full.
- Tools accept `profile` or `size`: `small|common|medium|big`, or explicit `wordlist`.

## Focus Checks

```bash
python3 agent/skills/boot2root-recon/scripts/cms_detect.py http://10.48.166.32 --paths http://10.48.166.32/app/ --timeout 6
python3 agent/skills/boot2root-recon/scripts/cve_search.py --name "Pluck CMS" --version "4.7.13"
```
