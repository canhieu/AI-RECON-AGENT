# Recon Report: https://acourse.hotropka.io.vn/
**Generated**: 2026-07-21T11:10:26.446689

## Executive Summary
- **Total findings**: 30
- Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 30

- **Tech stack**: Sale 
- **Open ports**: 80/http, 443/ssl/https

## INFO Findings

### nmap
- **Summary**: Ran nmap on acourse.hotropka.io.vn
- **Evidence**: `Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-21 11:07 +0700
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Host Discovery
Parallel DNS resolution of 1 host. Timing: About`
- **Time**: 2026-07-21 04:09:26

### whois
- **Summary**: Ran whois on acourse.hotropka.io.vn
- **Evidence**: `This TLD has no whois server, but you can access the whois database at
http://www.vnnic.vn/en
`
- **Time**: 2026-07-21 04:09:27

### dig
- **Summary**: Ran dig on acourse.hotropka.io.vn
- **Evidence**: `
; <<>> DiG 9.20.23-1-Debian <<>> acourse.hotropka.io.vn A +time=5
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28560
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUE`
- **Time**: 2026-07-21 04:09:29

### crt_sh
- **Summary**: Ran crt_sh on acourse.hotropka.io.vn
- **Evidence**: `<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx</center>
</body>
</html>
`
- **Time**: 2026-07-21 04:09:31

### subfinder
- **Summary**: Ran subfinder on acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:32

### dnsx
- **Summary**: Ran dnsx on acourse.hotropka.io.vn
- **Evidence**: `sh: 1: dnsx: not found`
- **Time**: 2026-07-21 04:09:33

### theharvester
- **Summary**: Ran theharvester on acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:35

### whatweb
- **Summary**: Ran whatweb on http://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:36

### redirect_check
- **Summary**: Ran redirect_check on http://acourse.hotropka.io.vn
- **Evidence**: `REDIRECT:https://acourse.hotropka.io.vn/
`
- **Time**: 2026-07-21 04:09:38

### redirect_target
- **Summary**: Switch web target to redirect domain: https://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:38

### ffuf_vhost
- **Summary**: Ran ffuf_vhost on https://acourse.hotropka.io.vn
- **Evidence**: ``
- **Time**: 2026-07-21 04:09:39

### httpx
- **Summary**: Ran httpx on https://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:40

### curl_headers
- **Summary**: Ran curl_headers on https://acourse.hotropka.io.vn
- **Evidence**: `HTTP/2 200 
age: 22
cache-control: public, max-age=0, must-revalidate
content-type: text/html; charset=utf-8
date: Tue, 21 Jul 2026 04:11:33 GMT
etag: "unkyj70o6v4inj"
server: Vercel
strict-transport-security: max-age=63072000
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segm`
- **Time**: 2026-07-21 04:09:42

### cms_detect
- **Summary**: Ran cms_detect on https://acourse.hotropka.io.vn
- **Evidence**: `{"cms": [{"confidence": "medium", "evidence": ["asset: https://i.ibb.co/Xr29cGMC/logo-Sale-Noti.png"], "method": "generic_inference", "name": "Sale", "version": ""}], "frameworks": [], "interesting_paths": [], "root_url": "https://acourse.hotropka.io.vn/", "target": "https://acourse.hotropka.io.vn",`
- **Time**: 2026-07-21 04:09:50

### cms_detect
- **Summary**: CMS/framework detected: Sale
- **Evidence**: `asset: https://i.ibb.co/Xr29cGMC/logo-Sale-Noti.png`
- **Time**: 2026-07-21 04:09:50

### katana
- **Summary**: Ran katana on https://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:09:51

### js_dump
- **Summary**: Ran js_dump on https://acourse.hotropka.io.vn
- **Evidence**: `{"pages": ["https://acourse.hotropka.io.vn", "https://acourse.hotropka.io.vn"], "js_urls": ["https://acourse.hotropka.io.vn/_next/static/chunks/03~yq9q893hmn.js", "https://acourse.hotropka.io.vn/_next/static/chunks/05f6efelq9fg..js", "https://acourse.hotropka.io.vn/_next/static/chunks/092yhsu9y.ayb.`
- **Time**: 2026-07-21 04:09:58

### js_deobfuscate
- **Summary**: Ran js_deobfuscate on https://acourse.hotropka.io.vn
- **Evidence**: `{"decoded": [{"file": "outputs/https___acourse.hotropka.io.vn_/artifacts/js/acourse.hotropka.io.vn__next_static_chunks_05f6efelq9fg..js.8e50830b.js", "encoding": "base64", "input": "reloadAndSetCurrentUserOrClear", "decoded": "hi'u'\nz{T\u03ac)^j"}, {"file": "outputs/https___acourse.hotropka.io.vn_/`
- **Time**: 2026-07-21 04:09:59

### js_mine
- **Summary**: Ran js_mine on https://acourse.hotropka.io.vn
- **Evidence**: `{"endpoints": ["http://${n}", "http://localhost", "http://n", "http://online.gov.vn/Home/WebDetails/142677", "http://www.w3.org/1998/Math/MathML", "http://www.w3.org/1999/xlink", "http://www.w3.org/2000/svg", "http://www.w3.org/XML/1998/namespace", "https://${", "https://${e.authDomain}/__/auth/hand`
- **Time**: 2026-07-21 04:10:02

### ffuf_dir
- **Summary**: Ran ffuf_dir on https://acourse.hotropka.io.vn
- **Evidence**: ``
- **Time**: 2026-07-21 04:10:04

### ffuf_recursive
- **Summary**: Ran ffuf_recursive on https://acourse.hotropka.io.vn
- **Evidence**: ``
- **Time**: 2026-07-21 04:10:05

### ffuf_ext
- **Summary**: Ran ffuf_ext on https://acourse.hotropka.io.vn
- **Evidence**: ``
- **Time**: 2026-07-21 04:10:07

### cms_detect
- **Summary**: Ran cms_detect on https://acourse.hotropka.io.vn
- **Evidence**: `{"cms": [{"confidence": "medium", "evidence": ["asset: https://i.ibb.co/Xr29cGMC/logo-Sale-Noti.png"], "method": "generic_inference", "name": "Sale", "version": ""}], "frameworks": [], "interesting_paths": [], "root_url": "https://acourse.hotropka.io.vn/", "target": "https://acourse.hotropka.io.vn",`
- **Time**: 2026-07-21 04:10:16

### cms_detect
- **Summary**: CMS/framework detected: Sale
- **Evidence**: `asset: https://i.ibb.co/Xr29cGMC/logo-Sale-Noti.png`
- **Time**: 2026-07-21 04:10:16

### web_download_interesting
- **Summary**: Ran web_download_interesting on https://acourse.hotropka.io.vn/mnt/c/Users/PC-
- **Evidence**: `{"artifacts": [], "skipped": "not interesting", "score": 0}
`
- **Time**: 2026-07-21 04:10:17

### curl_body
- **Summary**: Ran curl_body on https://acourse.hotropka.io.vn/mnt/c/Users/PC-
- **Evidence**: `<!DOCTYPE html><html lang="en" data-astro-cid-nbv56vs3> <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#000"><title>Vercel Security Checkpoint</title><style>.spinner[data-astro-cid-jlpqxutv]{display:flex;flex-directio`
- **Time**: 2026-07-21 04:10:19

### arjun
- **Summary**: Ran arjun on https://acourse.hotropka.io.vn
- **Evidence**: `{}`
- **Time**: 2026-07-21 04:10:21

### subdomain_live
- **Summary**: Ran subdomain_live on acourse.hotropka.io.vn
- **Evidence**: `sh: 1: subfinder: not found
Usage: httpx [OPTIONS] URL

Error: No such option '-s'.`
- **Time**: 2026-07-21 04:10:22

### nuclei_smart
- **Summary**: Ran nuclei_smart on https://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:10:23

### nuclei_cve
- **Summary**: Ran nuclei_cve on https://acourse.hotropka.io.vn
- **Time**: 2026-07-21 04:10:25

## Attack Leads
- **MEDIUM**: CMS/technology found; check public CVEs, admin panels, exposed modules, and login surfaces.
- **MEDIUM**: API endpoints discovered; probe for parameter injection, IDOR, excessive data exposure, and missing auth.
- **HIGH**: LLM analysis suggests specific vulnerability classes present; prioritize targeted testing based on identified classes.

## Recommendations
- ▶ Tech stack detected — check CVEs per version
- ▶ Run nuclei_smart + nuclei_cve with matching CVE templates
- ▶ Re-run with --verbose for detailed output
