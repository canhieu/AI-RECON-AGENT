# Recon Report: tryhackme.com
**Generated**: 2026-07-18T10:58:58.458852

## Executive Summary
- **Total findings**: 32
- Critical: 0 | High: 0 | Medium: 5 | Low: 0 | Info: 27

- **Tech stack**: Vercel unknown, Golang net/http unknown, TLS unknown, Namecheap Registrar unknown, Cloudflare DNS unknown, WHOIS Privacy Protection unknown, DNSSEC unsigned, DNS A record N/A, noVNC unknown, GitLab unknown, Wildcard TLS certificates unknown, dnsx unknown; installed build does not support -oJ, Wildcard TLS Certificates unknown, dnsx installed build does not support -oJ, HTTPS virtual hosting unknown, Wildcard or catch-all host handling unknown, text/html web application response unknown, HTTP/2 unknown, Vercel Challenge / Bot Mitigation unknown, text/html web response unknown, DNSSEC unsigned not enabled, Vercel edge protection / rate limiting unknown, JavaScript application surface unknown, HTTPS unknown, Vercel or edge-hosted web application unknown, Wildcard/custom error response handling unknown, ffuf-recursive-enumeration unknown, Wildcard or custom error response handling unknown, Possible Vercel or edge-hosted application unknown, Possible Vercel edge-hosted application unknown, Possible bot mitigation or edge filtering unknown, Vercel Security Checkpoint unknown, Vercel Edge Hosting unknown, JavaScript Bot Mitigation Challenge unknown, Next.js data route surface unknown, Astro-generated checkpoint page unknown, HTTP/2 HTTPS web service unknown, Astro unknown, Next.js path surface unknown, Vercel Edge Hosting / Bot Mitigation unknown, JavaScript challenge / browser verification unknown, HTML5 web application unknown, Vercel Security Checkpoint / Bot Mitigation unknown, Next.js unknown
- **Open ports**: 53/authoritative DNS via Cloudflare nameservers, 80/HTTP, 80/http, 80/http - Vercel edge service returning 308 Permanent Redirect to HTTPS, 80/http-redirect, 443/HTTP/2 TLS web service, 443/HTTP/2 over TLS, 443/HTTPS, 443/HTTPS edge/backend endpoint, 443/HTTPS web application behind Vercel, 443/HTTPS web application behind Vercel edge, 443/HTTPS web application behind Vercel edge protection, 443/http2-over-tls, 443/https, 443/https-vhost-candidate

## MEDIUM Findings

### subfinder
- **Summary**: Subdomain enumeration identified a broad TryHackMe attack surface spanning production VM infrastructure, reverse proxies, noVNC gateways, authentication setup, GitLab/assets hosts, status APIs, CDN/image delivery, remote access endpoints, blog/careers/help sites, and regional cell deployments. The most security-relevant findings are the exposed management-style and infrastructure-adjacent hostnames such as noVNC gateways, reverse-proxy nodes, GitLab assets, setup.auth, status-api.vm, and remote-* hosts, which may reveal authentication flows, tenant isolation issues, metadata, or misconfigured access controls. Multiple hosts include region/cell identifiers and wildcard certificate indicators, suggesting scalable multi-region infrastructure where virtual-host routing, wildcard TLS, and environment segregation should be tested carefully.
- **Evidence**: `subfinder returned numerous hostnames including reverse-proxy-us-east-1.tryhackme.com, multiple novnc.cell-prod-*.vm.tryhackme.com hosts, cell-prod regional VM hosts, reverse-proxy.cell-prod-*.vm.tryhackme.com hosts, setup.auth.tryhackme.com, status.tryhackme.com, status.vm.tryhackme.com, status-api`
- **Time**: 2026-07-18 03:38:24

### katana
- **Summary**: Katana successfully crawled https://tryhackme.com but discovered only the root URL and a single short path, /g, suggesting that the crawler was heavily constrained by edge controls, JavaScript-driven routing, authentication requirements, or bot mitigation. The broader session context indicates the target sits behind Vercel/Cloudflare-style edge infrastructure with HTTP/2, TLS, rate limiting or challenge behavior, wildcard/catch-all host handling, and a wide external attack surface including VM infrastructure, reverse proxies, noVNC gateways, GitLab/assets hosts, status APIs, and CDN/image-related services. The most actionable finding is not a direct vulnerability from this crawl, but confirmation that normal unauthenticated crawling of the main site yields limited visibility and that enumeration should pivot to discovered subdomains, authenticated application areas, API endpoints, noVNC gateways, and GitLab/assets infrastructure.
- **Evidence**: `Katana output shows successful crawl start for https://tryhackme.com and only two discovered URLs: https://tryhackme.com and https://tryhackme.com/g. The session context reports Vercel, Golang net/http, TLS, Cloudflare DNS, HTTP/2, Vercel Challenge / Bot Mitigation, wildcard TLS certificates, noVNC,`
- **Time**: 2026-07-18 03:45:58

### curl_body
- **Summary**: Requesting https://tryhackme.com/_next/data/ did not expose Next.js data JSON; instead the response was an HTML page titled "Vercel Security Checkpoint", indicating the endpoint is being intercepted by Vercel edge security/bot-mitigation controls. The body contains a JavaScript-based challenge with obfuscated module code and hidden root content, which explains why prior automated crawling and ffuf runs discovered little beyond wildcard/error patterns. The path remains high-value because /_next/data/ is normally associated with Next.js page-props JSON and can leak application routes or serialized data if a valid build ID and route are known.
- **Evidence**: `The curl response for https://tryhackme.com/_next/data/ returned an HTML document rather than Next.js JSON. The page title is "Vercel Security Checkpoint" and the HTML includes styles/classes for a spinner, hidden root element, noscript/checkpoint text containers, and an obfuscated JavaScript module`
- **Time**: 2026-07-18 03:53:44

### curl_body
- **Summary**: A direct request to https://tryhackme.com/_next/static/ returned an HTML page titled "Vercel Security Checkpoint" rather than a static directory listing, Next.js asset response, or conventional 404. The response contains an Astro-generated challenge page with JavaScript-based bot mitigation, indicating that Vercel edge protection is intercepting requests to framework-reserved paths such as /_next/static/. In a CTF/boot2root context, this means unauthenticated automated enumeration against the primary domain is likely being rate-limited, challenged, or routed through a custom edge checkpoint rather than exposing the underlying application directly.
- **Evidence**: `The curl response from https://tryhackme.com/_next/static/ begins with a full HTML document: '<!DOCTYPE html><html lang="en" ...><head>...<title>Vercel Security Checkpoint</title>'. The page includes Astro-style scoped attributes such as 'data-astro-cid-nbv56vs3' and 'data-astro-cid-jlpqxutv', CSS f`
- **Time**: 2026-07-18 03:54:17

### curl_body
- **Summary**: A direct request to https://tryhackme.com/api/ returned a Vercel Security Checkpoint HTML page instead of an API response, JSON error, route documentation, or a normal 404. This indicates that requests to the application API surface are being intercepted by Vercel edge bot-mitigation controls before reaching the backend application, which significantly limits unauthenticated curl-based enumeration. The response also reveals an Astro-generated checkpoint page and client-side JavaScript challenge behavior, suggesting that automated scanners may see false negatives unless they can execute JavaScript, preserve cookies, and mimic browser behavior.
- **Evidence**: `The body of https://tryhackme.com/api/ begins with an HTML document whose title is "Vercel Security Checkpoint". The response includes checkpoint-specific styling and JavaScript rather than JSON or an API error. Notable raw indicators include: '<title>Vercel Security Checkpoint</title>', Astro-style`
- **Time**: 2026-07-18 03:54:57

## INFO Findings

### nmap
- **Summary**: The target resolves to 64.239.109.193, with an additional address 64.239.123.193 not scanned, and exposes only HTTP on port 80 and HTTPS on port 443 while 112 TCP ports are filtered. Both web services appear to be fronted by Vercel, with HTTP returning 308 redirects to HTTPS and HTTPS presenting a valid TLS certificate for tryhackme.com. The scan does not reveal direct host-level services such as SSH or databases, suggesting the attack surface is primarily web/application-layer and CDN/platform configuration rather than traditional infrastructure exploitation.
- **Evidence**: `Nmap reported host 64.239.109.193 up with low latency and noted another address, 64.239.123.193, was not scanned. Only 80/tcp and 443/tcp were open; 112 TCP ports were filtered. Port 80 was identified as HTTP with server header 'Vercel' and returned 'HTTP/1.0 308 Permanent Redirect' with Location va`
- **Time**: 2026-07-18 03:34:38

### whois
- **Summary**: WHOIS shows tryhackme.com is a Namecheap-registered domain created in 2018 and renewed/updated in 2025, with registration valid until 2034. The domain uses Cloudflare authoritative nameservers, indicating DNS and likely edge protection/CDN services are in use, while registrant details are privacy-protected. DNSSEC is reported as unsigned, which is a minor DNS integrity weakness but not directly exploitable in most CTF web exploitation paths.
- **Evidence**: `WHOIS output lists Registrar: NameCheap, Inc.; Name Server: KIP.NS.CLOUDFLARE.COM and UMA.NS.CLOUDFLARE.COM; DNSSEC: unsigned; Domain Status: clientTransferProhibited; registrant organization is 'Privacy service provided by Withheld for Privacy ehf'. Session context also notes prior nmap resolution `
- **Time**: 2026-07-18 03:34:59

### dig
- **Summary**: The DNS A lookup for tryhackme.com returned two IPv4 addresses, 64.239.123.193 and 64.239.109.193, indicating the apex domain is load-balanced or served through multiple edge/backend endpoints. In the current recon context, only 64.239.109.193 has been scanned so far, meaning 64.239.123.193 remains an untested target that could expose different services, routing behavior, TLS certificates, headers, or virtual-host responses. The short TTL of 125 seconds suggests dynamic infrastructure, CDN/edge routing, or frequently rotated hosting records, so repeated resolution and per-IP testing may be useful in a CTF/boot2root workflow.
- **Evidence**: `DiG returned NOERROR for tryhackme.com A with two answers: tryhackme.com. 125 IN A 64.239.123.193 and tryhackme.com. 125 IN A 64.239.109.193. The query completed successfully via resolver 192.168.1.1 with a 63 msec response time. Prior session context states that 64.239.109.193 was scanned and expos`
- **Time**: 2026-07-18 03:35:19

### crt_sh
- **Summary**: The crt.sh certificate transparency lookup failed and returned no certificate/subdomain data, so this specific reconnaissance step did not produce additional hostnames or virtual hosts to target. Existing context indicates the domain is publicly registered through Namecheap, uses Cloudflare authoritative DNS, has unsigned DNSSEC, resolves to two IPv4 addresses, and exposes only HTTP/HTTPS on the scanned address, suggesting the main attack surface is web-focused rather than broad network service exposure.
- **Evidence**: `crt_sh reported Success: False with no tool output, meaning no certificate transparency results were obtained from this run. Session context shows previously discovered technologies and posture: Vercel unknown, Golang net/http unknown, TLS unknown, Namecheap Registrar, Cloudflare DNS, WHOIS Privacy `
- **Time**: 2026-07-18 03:36:35

### dnsx
- **Summary**: The dnsx execution did not complete because the supplied output flag `-oJ` is not supported by the installed dnsx version, so this step produced no DNS resolution, wildcard, CNAME, or JSON-formatted enrichment data. This is a tooling/version mismatch rather than a target-side security finding, but it creates a reconnaissance blind spot because previously discovered TryHackMe subdomains and edge infrastructure were not validated or normalized by this run. Existing context still indicates a broad web-facing attack surface behind Cloudflare/edge infrastructure with HTTP/HTTPS exposure, but this specific dnsx result should not be treated as evidence of DNS misconfiguration.
- **Evidence**: `dnsx returned `Success: False` with the error `flag provided but not defined: -oJ`, indicating local command-line option incompatibility. No DNS records or hostname enrichment were produced by this run. Session context separately notes Cloudflare authoritative nameservers, Namecheap registration, ap`
- **Time**: 2026-07-18 03:38:59

### theharvester
- **Summary**: theHarvester did not complete successfully and returned no usable OSINT artifacts for tryhackme.com, so this specific reconnaissance step did not add emails, employee names, hosts, or search-engine-derived subdomains. In the broader session context, the target already shows a sizeable externally exposed attack surface including production infrastructure, reverse proxies, noVNC gateways, GitLab/assets hosts, status/API surfaces, Vercel/Golang net/http indicators, Cloudflare DNS, wildcard TLS certificates, and DNSSEC being unsigned. The failed result should be treated as a tooling/data-source gap rather than evidence that no OSINT exposure exists.
- **Evidence**: `theHarvester reported Success: False and produced an empty Tool output, so no emails, names, or additional hosts were obtained from this step. Session context states discovered technologies and posture: Vercel unknown, Golang net/http unknown, TLS unknown, Namecheap Registrar, Cloudflare DNS, WHOIS `
- **Time**: 2026-07-18 03:40:31

### whatweb
- **Summary**: Ran whatweb on http://tryhackme.com
- **Evidence**: `[
{"target":"http://tryhackme.com","http_status":308,"request_config":{"headers":{"User-Agent":"WhatWeb/0.6.4"}},"plugins":{"Country":{"string":["UNITED STATES"],"module":["US"]},"HTTPServer":{"string":["Vercel"]},"IP":{"string":["64.239.109.1"]},"RedirectLocation":{"string":["https://tryhackme.com/`
- **Time**: 2026-07-18 03:40:44

### redirect_check
- **Summary**: Ran redirect_check on http://tryhackme.com
- **Evidence**: `REDIRECT:https://tryhackme.com/
`
- **Time**: 2026-07-18 03:40:47

### redirect_target
- **Summary**: Switch web target to redirect domain: https://tryhackme.com
- **Time**: 2026-07-18 03:40:48

### ffuf_vhost
- **Summary**: The ffuf virtual-host brute force against https://tryhackme.com produced multiple HTTP 403 responses for arbitrary Host headers such as SysAdmin2.tryhackme.com, TODO.tryhackme.com, U.tryhackme.com, and Travel.tryhackme.com. The responses are highly uniform in status, word count, line count, content type, and similar body length, which strongly suggests a wildcard/catch-all edge response rather than confirmed distinct virtual hosts. This finding is useful because it indicates the target's fronting infrastructure responds to unknown Host headers with a forbidden page, so future vhost enumeration must be calibrated with baseline filtering before treating hits as valid.
- **Evidence**: `ffuf command used Host header fuzzing: ffuf -u https://tryhackme.com -w /home/ngannguyen/Downloads/ppppp/data/wordlists/vhosts.txt -of json -o /tmp/tmpkd5pfh2q -H Host: FUZZ.tryhackme.com -fc 404. Multiple candidates returned HTTP 403 rather than 404, including SysAdmin2.tryhackme.com, TODO.tryhackm`
- **Time**: 2026-07-18 03:41:38

### httpx
- **Summary**: The httpx probe against https://tryhackme.com did not return successful output, so this specific run provides no fresh HTTP response metadata, status code, title, headers, or technology fingerprints. However, prior reconnaissance indicates a broad TryHackMe-owned attack surface involving Vercel/Golang-style HTTP services, Cloudflare DNS, wildcard/catch-all virtual hosting behavior, noVNC gateways, GitLab/assets hosts, VM infrastructure, status/API surfaces, and repeated 403 responses for arbitrary Host headers. The immediate value of this finding is that the primary apex target may be protected, filtered, rate-limited, or not producing parseable output for the current httpx build/configuration, so follow-up enumeration should focus on discovered subdomains, Host-header behavior, and service-specific endpoints rather than assuming the apex alone is the attack surface.
- **Evidence**: `The httpx run against https://tryhackme.com reported Success: False and produced no raw tool output. Session context records prior discoveries: Vercel unknown, Golang net/http unknown, TLS unknown, Namecheap Registrar, Cloudflare DNS, WHOIS Privacy Protection, DNSSEC unsigned, noVNC, GitLab, wildcar`
- **Time**: 2026-07-18 03:42:13

### curl_headers
- **Summary**: The target responded over HTTPS with HTTP/2 status 429 from Vercel, indicating the request was rate-limited or challenged by Vercel's edge mitigation layer rather than served directly by the application. Headers show `x-vercel-mitigated: challenge` and an `x-vercel-challenge-token`, meaning automated reconnaissance is being detected and gated before reaching the origin application. This limits direct fingerprinting of the root domain but confirms Vercel hosting/proxying and suggests subsequent testing should focus on subdomains, alternate virtual hosts, API endpoints, and request-profile tuning to distinguish edge defenses from origin behavior.
- **Evidence**: `curl_headers against https://tryhackme.com succeeded and returned `HTTP/2 429`, `server: Vercel`, `x-vercel-mitigated: challenge`, `x-vercel-challenge-[REDACTED:credential] `x-vercel-id: hkg1::1784346134-Yz9tHzHAKoiORp62qtdi3LTqlcfXz6yO`, `cache-control: private, no-store, max-age=0`, and `content-t`
- **Time**: 2026-07-18 03:42:59

### cms_detect
- **Summary**: The CMS detection run against https://tryhackme.com completed successfully but did not identify any common CMS, web framework, interesting default paths, or technology fingerprints. In context, this is consistent with earlier reconnaissance showing that the root site is likely fronted by Vercel and protected by rate limiting or bot mitigation, which may prevent fingerprinting tools from reaching the origin application. The lack of CMS findings should not be treated as evidence that the application has no framework or attack surface; it only means this specific probe did not fingerprint one.
- **Evidence**: `cms_detect output for target https://tryhackme.com returned success=true with root_url=https://tryhackme.com/ but empty arrays for cms, frameworks, interesting_paths, and tech_discovered. Session context also reports HTTPS on HTTP/2 with a prior 429 response from Vercel edge mitigation, broad subdom`
- **Time**: 2026-07-18 03:44:15

### js_dump
- **Summary**: The JavaScript extraction run against https://tryhackme.com completed successfully but returned no pages, JavaScript URLs, or client-side artifacts. In context with prior HTTP/2 429 responses from Vercel and limited crawling results, this likely indicates that edge bot mitigation, rate limiting, or JavaScript-heavy rendering prevented the tooling from accessing the real application surface rather than proving that no JavaScript exists. This result is useful primarily as negative evidence: unauthenticated automated reconnaissance from the current vantage point is being constrained at the edge.
- **Evidence**: `js_dump output for https://tryhackme.com reported Success: True but returned empty arrays for all extracted data: pages=[], js_urls=[], artifacts=[]. Prior session context shows katana only discovered the root URL and /g, curl observed HTTP/2 429 from Vercel, and CMS detection found no framework or `
- **Time**: 2026-07-18 03:47:08

### js_deobfuscate
- **Summary**: The JavaScript deobfuscation step completed successfully but returned no decoded strings or artifacts, meaning no client-side secrets, endpoints, source maps, API routes, or obfuscated logic were recovered from the supplied target at this stage. In the broader reconnaissance context, this is likely not evidence that the application has no JavaScript attack surface; rather, prior findings indicate Vercel edge rate-limiting/challenge behavior and constrained crawling, which likely prevented meaningful JavaScript collection before deobfuscation could occur. For a CTF or boot2root workflow, the current result should be treated as an access/visibility limitation and pivoted toward bypassing edge constraints, enumerating discovered subdomains, and targeting non-Vercel or less-protected application hosts.
- **Evidence**: `Tool js_deobfuscate completed with Success: True but returned {"decoded": [], "artifacts": []}. Prior context shows curl_headers received HTTP/2 429 from Vercel, katana crawled only the root URL and /g, and js_dump returned no pages, JavaScript URLs, or client-side artifacts, supporting the conclusi`
- **Time**: 2026-07-18 03:47:57

### js_mine
- **Summary**: The JavaScript mining step against https://tryhackme.com completed successfully but did not identify any endpoints, secrets, source maps, or other client-side artifacts. In the broader reconnaissance context, this reinforces the pattern that the root application is either heavily protected by Vercel edge/bot mitigation, highly JavaScript/API-gated in ways the tooling could not reach, or not exposing useful static assets to unauthenticated automated clients. For a CTF/boot2root workflow, the absence of findings here should not be treated as proof of no client-side attack surface; instead, it indicates that deeper crawling, authenticated analysis, subdomain-specific testing, and bypassing edge controls are likely required.
- **Evidence**: `js_mine completed with Success: True against https://tryhackme.com and returned empty arrays for all artifact categories: {"endpoints": [], "secrets": [], "source_maps": [], "artifacts": []}. This aligns with prior findings showing katana only reached the root URL and /g, js_dump returned no pages o`
- **Time**: 2026-07-18 03:48:25

### ffuf_dir
- **Summary**: The directory brute-force against https://tryhackme.com completed successfully but returned no surviving results after filtering out the dominant wildcard/error response pattern. The ffuf calibration observed that many invalid paths produce a consistent 3-line, 949-word response, indicating wildcard-style handling, custom error pages, or edge challenge behavior that can easily hide true positives if filters are too broad. In the broader context, this supports prior observations that the target is likely behind Vercel/edge protection and that unauthenticated crawling/fuzzing of the apex domain is heavily constrained.
- **Evidence**: `ffuf command: ffuf -u https://tryhackme.com/FUZZ -w /home/ngannguyen/Downloads/ppppp/data/wordlists/dir.txt -of json -o /tmp/tmp3f3swemg -fc 404 -fw 949 -fl 3. The run completed successfully with no results: "results": []. Calibration showed an initial run with 24 apparent results followed by filter`
- **Time**: 2026-07-18 03:49:04

### ffuf_recursive
- **Summary**: The recursive ffuf directory brute-force against https://tryhackme.com completed successfully but produced no surviving directory or file discoveries after filtering. The scan appears to have encountered a consistent wildcard/custom error response pattern, with calibration identifying dominant false-positive responses of 949 words and 3 lines, which were filtered out. In the context of the wider recon, this supports the conclusion that the root web surface is protected by edge/application controls and does not expose simple wordlist-discoverable paths from this scan configuration.
- **Evidence**: `ffuf command executed: ffuf -u https://tryhackme.com/FUZZ -w /home/ngannguyen/Downloads/ppppp/data/wordlists/dir.txt -of json -o /tmp/tmpto12mx9o -recursion -recursion-depth 2 -fc 404 -fw 949 -fl 3. The results array is empty: "results": []. Calibration initially produced 24 apparent results, then a`
- **Time**: 2026-07-18 03:50:00

### ffuf_ext
- **Summary**: The extension-based ffuf content discovery run against https://tryhackme.com completed successfully but produced no surviving findings after filtering the dominant wildcard/error response pattern. The calibration phase initially observed 504 apparent matches, then suppressed responses matching 949 words and 3 lines, indicating the site likely returns a consistent custom error, challenge, or catch-all page for nonexistent resources. No exposed backup files, config files, source artifacts, database dumps, logs, environment files, or common script extensions were identified by this wordlist scan.
- **Evidence**: `ffuf command targeted https://tryhackme.com/FUZZ with extensions .php,.asp,.aspx,.txt,.bak,.zip,.tar.gz,.sql,.conf,.inc,.old,.log,.json,.xml,.env,.yml,.yaml,.config,.db,.ds_store. The final results array is empty. Calibration recorded an initial run with result_count 504, followed by a calibrated ru`
- **Time**: 2026-07-18 03:53:14

### cms_detect
- **Summary**: Ran cms_detect on https://tryhackme.com
- **Evidence**: `{"cms": [], "frameworks": [], "interesting_paths": [], "root_url": "https://tryhackme.com/", "target": "https://tryhackme.com", "tech_discovered": []}
`
- **Time**: 2026-07-18 03:55:04

### web_download_interesting
- **Summary**: Ran web_download_interesting on https://tryhackme.com/api/*
- **Evidence**: `{"artifacts": [], "skipped": "not interesting", "score": 0}
`
- **Time**: 2026-07-18 03:55:06

### curl_body
- **Summary**: Ran curl_body on https://tryhackme.com/api/*
- **Evidence**: `<!DOCTYPE html><html lang="en" data-astro-cid-nbv56vs3> <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#000"><title>Vercel Security Checkpoint</title><style>.spinner[data-astro-cid-jlpqxutv]{display:flex;flex-directio`
- **Time**: 2026-07-18 03:55:09

### arjun
- **Summary**: Ran arjun on https://tryhackme.com
- **Evidence**: `{}`
- **Time**: 2026-07-18 03:55:11

### subdomain_live
- **Summary**: Ran subdomain_live on tryhackme.com
- **Evidence**: `https://admin.tryhackme.com [[33m301[0m] [[36m301 Moved Permanently[0m]
https://guacaworker.tryhackme.com [[31m400[0m]
https://docs.tryhackme.com [[33m301[0m] [[36m301 Moved Permanently[0m]
https://insights-proxy-worker.tryhackme.com [[31m401[0m]
https://blog.tryhackme.com [[33m301[0m]`
- **Time**: 2026-07-18 03:55:57

### nuclei_smart
- **Summary**: The nuclei scan did not execute because the local nuclei templates directory is missing, so no nuclei-based vulnerability conclusions can be drawn from this run. Existing reconnaissance indicates the target is strongly edge-protected by Vercel bot mitigation/security checkpoint behavior, with direct requests to API, Next.js, and static paths being intercepted rather than returning normal application responses. The broader attack surface appears to include multiple subdomains and infrastructure classes such as noVNC gateways, GitLab/assets hosts, reverse proxies, status/API services, and VM-related infrastructure, which are likely more productive targets than the heavily protected apex host.
- **Evidence**: `nuclei failed with: `[FTL] Could not run nuclei: could not create automatic scan service: could not get templates in directory: no templates found in path "/home/ngannguyen/nuclei-templates"`. Session context reports Vercel/edge protection and multiple intercepted paths: direct request to `https://t`
- **Time**: 2026-07-18 03:57:31

### nuclei_cve
- **Summary**: The nuclei CVE scan did not execute because no nuclei templates were provided, so this output does not confirm or deny the presence of known CVEs on the target. Existing reconnaissance indicates the main HTTPS surface is protected by Vercel edge controls and bot-mitigation challenge pages, which are preventing straightforward crawling and API/static route probing. The broader discovered attack surface appears more promising than the protected apex host, especially subdomains related to noVNC, GitLab/assets, authentication, status APIs, reverse proxies, and VM infrastructure.
- **Evidence**: `The nuclei tool failed with: '[FTL] Could not run nuclei: no templates provided for scan'. Prior findings show repeated Vercel checkpoint interception: direct requests to https://tryhackme.com/api/, https://tryhackme.com/_next/static/, and https://tryhackme.com/_next/data/ returned an HTML page titl`
- **Time**: 2026-07-18 03:58:53

### dns_check
- **Summary**: Ran dns_check on tryhackme.com
- **Evidence**: `service=dns
purpose=DNS recursion and zone leakage
ports=53
53: closed
`
- **Time**: 2026-07-18 03:58:57

## Attack Leads
- **MEDIUM**: CMS/technology found; check public CVEs, admin panels, exposed modules, and login surfaces.
- **HIGH**: SSH service + credential artifacts discovered; test password reuse and check for exposed private keys.
- **MEDIUM**: Admin/debug/backup endpoint exposed; probe for default credentials, information disclosure, and auth bypass.
- **MEDIUM**: API endpoints discovered; probe for parameter injection, IDOR, excessive data exposure, and missing auth.
- **HIGH**: LLM analysis suggests specific vulnerability classes present; prioritize targeted testing based on identified classes.

## Recommendations
- ▶ Tech stack detected — check CVEs per version
- ▶ Run nuclei_smart + nuclei_cve with matching CVE templates
- ▶ Re-run with --verbose for detailed output