# Tooling

## Canonical Tool Map

### Passive

- `whois`: domain ownership and RDAP cues.
- `dig`: DNS record fetch.
- `crt_sh`: certificate transparency discovery.
- `subfinder`: passive subdomain discovery.
- `gau`: historical URL collection.
- `dnsx`: DNS resolution and liveness validation.
- `theHarvester`: public footprint aggregation.

### Active / Web

- `rustscan`: primary fast full TCP sweep over `1-65535` without root.
- `nmap`: host and service discovery.
- `whatweb`: broad tech fingerprinting.
- `cms_detect`: CMS/framework detection from index HTML, response headers, cookies, meta generator tags, comments, asset paths/names, exposed versions/components, and linked CMS URLs from directory listings. Supports a `--paths` parameter to probe additional URLs beyond root. Runs twice: pass 1 on root, pass 2 on fuzz-discovered paths. Detects: WordPress, Drupal, Joomla, Magento, CMS Made Simple, Pluck CMS, Laravel, Django, Rails, Spring, Symfony.
- `artifact_analyze`: local artifact review for suspicious text, credentials, private keys, connection strings, and proof-like files. Emits redacted preview only; raw content remains in artifact files.
- `httpx`: HTTP probing, titles, tech, status, redirects.
- `ffuf_dir`: adaptive path discovery with 6-second fallback calibration.
- `ffuf_vhost`: adaptive vhost discovery.
- `ffuf_recursive`: adaptive recursive path discovery.
- `ffuf_ext`: adaptive extension fuzzing.
- `nuclei_general`: generic templates and basic findings.
- `masscan`: fast port broadening when scope allows.
- `nc_scan`: netcat TCP connect scan fallback; use `ports="1-65535"` only when time/noise budget allows.

### Service Checks

- `smb_check`
- `ftp_check`
- `mysql_check`
- `redis_check`
- `ldap_check`
- `nfs_check`
- `smtp_check`
- `ssh_check`
- `mssql_check`
- `snmp_check`
- `vnc_check`
- `dns_check`

### Web Expansion

- `katana`: crawl discovered web surface.
- `js_dump`: download discovered JavaScript artifacts.
- `js_deobfuscate`: statically beautify/decode JavaScript without eval.
- `js_mine`: extract endpoints, secrets, and source maps from JavaScript.
- `jsluice`: extract endpoints and secrets from JS.
- `arjun`: parameter discovery.
- `kiterunner`: API route expansion; registered support tool, not currently wired into the default WebWorker chain.
- `graphw00f`: GraphQL fingerprinting.
- `s3scanner`: S3 bucket exposure checks.
- `shodan`: external exposure context when available.
- `trufflehog`: secret scanning in repos/artifacts.
- `corsy`: CORS misconfiguration review.
- `nuclei_tech`: tech-specific template pass.
- `testssl`: TLS and protocol review.
- `curl_headers`: cheap header and response inspection.
- `curl_body`: body read for interesting paths and fuzz-discovered directory listings.
- `cve_search`: generic local `searchsploit --json` lookup for detected versions using `<name/service> <version> cve`.

## Use Policy

- Run port discovery first unless user explicitly requests passive-only: `rustscan` for primary full TCP sweep, `nc_scan` as fallback, `nmap` for service detail on discovered ports only.
- Use service checks when the banner or port is enough to narrow the target.
- Use web expansion after one live app is confirmed.
- Run `cms_detect` after headers/body reachability checks (pass 1 on root), then again after fuzz on discovered paths (pass 2). Inspect index HTML, headers, cookies, meta generator tags, comments, and assets. Treat exposed CMS/framework versions as at least medium severity.
- Fuzz with `/usr/share/seclists/Discovery/Web-Content` profile `medium` by default; recursive and extension fuzz use `common` unless signal warrants more.
- Adaptive fuzz calibration checks fallback noise over 6 seconds and adds `-fs`, `-fw`, or `-fl` only when one response cluster dominates.
- Preserve 403 responses by default because forbidden paths are useful CTF leads.
- Avoid broad scans until the target scores high enough.

