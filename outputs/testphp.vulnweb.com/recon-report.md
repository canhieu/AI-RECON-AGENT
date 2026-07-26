# Recon Report: testphp.vulnweb.com
**Generated**: 2026-07-21T11:36:20.904470

## Executive Summary
- **Total findings**: 30
- Critical: 0 | High: 0 | Medium: 2 | Low: 5 | Info: 23

- **Tech stack**: AdGuardDNS 1218, Golang net/http server unknown, HTTPS/TLS unknown, AdGuard DNS 1218, DNS unknown, nginx unknown, subfinder 2.14.0, dnsx unknown; incompatible with -oJ flag, HTML5 , JavaScript , HTTP redirect/canonicalization unknown, HTML5 unknown, JavaScript unknown, ffuf unknown, HTTP unknown, HTTP 1.1, robots.txt unknown, dnsx unknown, Golang net/http unknown, PHP web application unknown, HTTP 1.1 unknown, robots.txt present
- **Open ports**: 53/AdGuard DNS resolver or DNS infrastructure, 53/DNS A record resolution to 94.140.14.33, 53/DNS resolution currently returning 94.140.14.33, 53/DNS resolution returned 94.140.14.33, 53/dns closed, 80/HTTP service associated with AdGuard DNS infrastructure, 80/HTTP web application, unverified in this tool output, 80/HTTP, likely AdGuard-related infrastructure based on prior nmap/session context, 80/http, 80/http - AdGuardDNS error/block page, 443/HTTPS/TLS service associated with AdGuard DNS infrastructure, 443/HTTPS/TLS, likely AdGuard-related infrastructure based on prior nmap/session context, 443/HTTPS/TLS, unverified in this tool output, 443/https, 443/https - AdGuardDNS-hosted page or interception endpoint

## MEDIUM Findings

### cve_search
- **Summary**: Public CVE/exploit references found for HTTP 1.1
- **Evidence**: `{"query": "HTTP 1.1 cve", "count": 899, "cves": ["CVE-1999-0018", "CVE-1999-0040", "CVE-1999-0045", "CVE-1999-0046", "CVE-1999-0051", "CVE-1999-0215", "CVE-1999-0233", "CVE-1999-0266", "CVE-1999-0283", "CVE-1999-0491"], "hits": [{"cves": ["CVE-2010-1093"], "edb_id": "14942", "path": "/usr/share/expl`
- **Time**: 2026-07-21 04:19:30

### subdomain_live
- **Summary**: Live subdomain reconnaissance confirms that testphp.vulnweb.com is reachable over HTTP and appears to be a deliberately vulnerable web application fronted by an nginx/Golang-style HTTP stack with HTML5/JavaScript content. Directory discovery found a confirmed /robots.txt endpoint and, more importantly, a suspicious /project-admins path returning HTTP 500, which may indicate an unhandled server-side error, hidden administrative functionality, or a malformed backend route. Prior findings also mention non-404 behavior and failed extension enumeration, so response-size/status-code calibration will be important before trusting brute-force results.
- **Evidence**: `subdomain_live reported Success: True for target testphp.vulnweb.com. Session context lists discovered technologies including nginx unknown, Golang net/http server unknown, HTTP 1.1, HTML5, JavaScript, and HTTPS/TLS unknown. Recent findings state that recursive ffuf discovery found /robots.txt retur`
- **Time**: 2026-07-21 04:34:22

## LOW Findings

### ffuf_dir
- **Summary**: Directory brute forcing against http://testphp.vulnweb.com identified one confirmed accessible file, /robots.txt, returning HTTP 200 with a small text/plain response, plus several non-404 paths returning HTTP 500 with zero-length bodies. The HTTP 500 responses on CGI- and database/member-related names may indicate backend routing, legacy handlers, or application error behavior rather than confirmed accessible content, but they are worth validating manually because they differ from the filtered baseline. The ffuf run filtered known 404 and large default responses, so the remaining hits are likely anomalies or real routes requiring follow-up.
- **Evidence**: `ffuf command: ffuf -u http://testphp.vulnweb.com/FUZZ -w /home/ngannguyen/Downloads/ppppp/data/wordlists/dir.txt -of json -o /tmp/tmpts2hfga7 -fc 404 -fs 382231 -fw 19013 -fl 6. Confirmed hit: /robots.txt returned status 200, length 26, words 3, lines 3, content-type text/plain. Anomalous non-404 hi`
- **Time**: 2026-07-21 04:23:48

### ffuf_recursive
- **Summary**: Recursive ffuf discovery against http://testphp.vulnweb.com found a confirmed accessible /robots.txt file returning HTTP 200 and a suspicious /project-admins path returning HTTP 500 with an empty response. The scan used filtering to remove a dominant false-positive response body, suggesting the application may return custom/nonstandard responses for many invalid paths; therefore the two remaining hits are notable. /robots.txt is a low-risk but useful reconnaissance artifact, while /project-admins is a higher-value lead because its admin-like naming and server-side error response may indicate a hidden administrative route, broken access control, or unhandled backend logic.
- **Evidence**: `ffuf command: ffuf -u http://testphp.vulnweb.com/FUZZ -w /home/ngannguyen/Downloads/ppppp/data/wordlists/dir.txt -of json -o /tmp/tmpgxvwig66 -recursion -recursion-depth 2 -fc 404 -fs 382231 -fw 19013 -fl 6. Results: http://testphp.vulnweb.com/robots.txt returned status 200, length 26, words 3, line`
- **Time**: 2026-07-21 04:25:49

### ffuf_ext
- **Summary**: The ffuf extension-enumeration phase did not complete successfully and produced no direct extension-discovery results, so no new files or extension-specific attack surface were confirmed from this tool run. However, prior reconnaissance context shows that /robots.txt is accessible and that /project-admins returns HTTP 500 with an empty response, which is notable because it suggests a hidden or restricted administrative path with unstable backend handling. The target appears to be an HTTP web application on port 80 with nginx/front-end HTTP behavior and HTML5/JavaScript content, but the exact backend stack is not confirmed from this output.
- **Evidence**: `Tool ffuf_ext against http://testphp.vulnweb.com reported Success: False and returned no raw output, so extension enumeration did not produce confirmed findings. Session context shows prior confirmed accessible /robots.txt returning HTTP 200, a suspicious /project-admins path returning HTTP 500 with`
- **Time**: 2026-07-21 04:31:25

### web_download_interesting
- **Summary**: The robots.txt retrieval for http://testphp.vulnweb.com/robots.txt completed successfully but the downloader classified it as not interesting and produced no artifacts, meaning it likely did not expose disallowed sensitive paths or useful reconnaissance content. In the broader reconnaissance context, /robots.txt is still confirmed as an accessible HTTP 200 text/plain resource, while the more interesting lead remains the suspicious /project-admins path returning HTTP 500, suggesting a potentially unstable or hidden administrative route. No CMS fingerprint was identified, so testing should focus on generic web application vulnerabilities and manual endpoint discovery rather than CMS-specific exploits.
- **Evidence**: `Tool web_download_interesting targeted http://testphp.vulnweb.com/robots.txt and returned Success: True with output {"artifacts": [], "skipped": "not interesting", "score": 0}. Session context also reports ffuf discovery confirmed /robots.txt returning HTTP 200 with a small text/plain response and i`
- **Time**: 2026-07-21 04:32:18

### nuclei_smart
- **Summary**: The nuclei_smart scan did not execute because the local Nuclei template installation is incomplete or misconfigured, specifically missing the http/exposures template directory. No vulnerability findings were produced by this tool run, but prior reconnaissance confirms that http://testphp.vulnweb.com is live over HTTP, exposes /robots.txt, and has a suspicious /project-admins endpoint returning HTTP 500. Because this is a deliberately vulnerable PHP test application, the failed Nuclei run should be treated as a tooling issue rather than evidence of security posture.
- **Evidence**: `Nuclei failed before scanning: '[FTL] Could not run nuclei: could not create automatic scan service: could not get templates in directory: could not find file: open /home/ngannguyen/.local/nuclei-templates/http/exposures/: no such file or directory'. Session context confirms the host is reachable: '`
- **Time**: 2026-07-21 04:35:21

## INFO Findings

### nmap
- **Summary**: The scan did not reach the expected testphp.vulnweb.com web application; the hostname resolved to 94.140.14.33, whose reverse DNS and HTTP banner identify it as AdGuard DNS infrastructure. Ports 80 and 443 are open, but the HTTP responses are AdGuardDNS error/block pages returning HTTP 500 rather than the target application, so this output is primarily evidence of DNS interception, sinkholing, or resolver filtering rather than a vulnerability in the intended CTF target. Before attempting application testing, the target's DNS resolution path should be corrected and the real application IP verified.
- **Evidence**: `Nmap resolved testphp.vulnweb.com to 94.140.14.33 and reported rDNS as 94-140-14-33.adguard-dns.com. Port 80 returned 'Server: AdGuardDNS/1218' and was identified as 'Golang net/http server'. Both GET and OPTIONS probes returned 'HTTP/1.0 500 Internal Server Error' with an AdGuardDNS HTML page. Port`
- **Time**: 2026-07-21 04:10:20

### whois
- **Summary**: The WHOIS lookup did not complete because the process was terminated by signal 15, so it provides no registrar, netblock, or ownership confirmation for the intended target. In the current session context, the more important finding is that testphp.vulnweb.com resolved to 94.140.14.33, which appears to be AdGuard DNS infrastructure rather than the expected Vulnweb test application, meaning prior HTTP/Nmap observations are likely against the wrong host. This is an environment or DNS-resolution issue that must be corrected before drawing conclusions about the CTF target or attempting exploitation.
- **Evidence**: `WHOIS output: "Interrupted by signal 15...". Session context reports: "nmap: The scan did not reach the expected testphp.vulnweb.com web application; the hostname resolved to 94.140.14.33, whose reverse DNS and HTTP banner identify it as AdGuard DNS infrastructure." Discovered technologies also incl`
- **Time**: 2026-07-21 04:10:57

### dig
- **Summary**: The DNS lookup for testphp.vulnweb.com returned a single A record, 94.140.14.33, with a short TTL of 120 seconds. In the current session context, this IP has already been identified as AdGuard DNS infrastructure rather than the expected vulnerable web application, indicating the reconnaissance is likely being redirected, filtered, or affected by DNS sinkholing/resolver policy. This means subsequent HTTP/Nmap findings against 94.140.14.33 should not be treated as findings against the intended CTF target until DNS resolution is validated through independent resolvers.
- **Evidence**: `DiG returned NOERROR with one answer: `testphp.vulnweb.com. 120 IN A 94.140.14.33`. The DNS server queried was `10.22.103.10#53`, indicating a local/internal recursive resolver was used. Session context states that 94.140.14.33 reverse DNS and HTTP banner identify it as AdGuard DNS infrastructure, a`
- **Time**: 2026-07-21 04:11:22

### crt_sh
- **Summary**: The crt.sh lookup did not return certificate data for the intended host and instead produced a 502 Bad Gateway page served by nginx, indicating an upstream failure or blocked request to the certificate transparency service. In context, this does not provide new application attack surface on testphp.vulnweb.com; it reinforces that the hostname is not reliably resolving to the expected CTF target and is currently pointing at unrelated AdGuardDNS infrastructure. The immediate next step is to validate DNS/SNI/vhost handling and confirm the real application endpoint before attempting web exploitation.
- **Evidence**: `["crt_sh tool output returned an HTML error page: '<title>502 Bad Gateway</title>' and '<center><h1>502 Bad Gateway</h1></center>'", "The error page footer identifies the intermediary as 'nginx', showing the failure occurred at the proxy layer rather than exposing target application content", "Sessi`
- **Time**: 2026-07-21 04:12:03

### subfinder
- **Summary**: Subfinder completed successfully against testphp.vulnweb.com but found zero additional subdomains. This result is likely not a meaningful indication of a small attack surface because the broader session shows the target hostname resolving to 94.140.14.33, which appears to be AdGuard DNS infrastructure rather than the intended VulnWeb test application. The current reconnaissance path is therefore likely polluted by DNS filtering, sinkholing, resolver interference, or an incorrect resolution path, and further web exploitation should wait until the hostname resolves to the real target.
- **Evidence**: `Subfinder output states: 'Enumerating subdomains for testphp.vulnweb.com' followed by 'Found 0 subdomains for testphp.vulnweb.com in 51 seconds 17 milliseconds'. Session context shows DNS lookup returned a single A record, 94.140.14.33, with TTL 120, and that this IP was identified as AdGuard DNS in`
- **Time**: 2026-07-21 04:13:22

### dnsx
- **Summary**: The dnsx run did not produce DNS reconnaissance results because the invoked binary does not support the requested `-oJ` flag, indicating a tooling/version mismatch rather than a target-side finding. This is important because the current session is already showing suspicious or misleading resolution for `testphp.vulnweb.com` to `94.140.14.33`, which appears to be AdGuard DNS infrastructure rather than the intended vulnerable web application. DNS enumeration should be repeated with a compatible dnsx version or adjusted flags, and resolution should be validated against multiple resolvers before continuing web exploitation.
- **Evidence**: `dnsx failed with: `flag provided but not defined: -oJ`. Session context shows prior DNS lookup for `testphp.vulnweb.com` returned a single A record `94.140.14.33` with TTL 120, and nmap did not reach the expected web application; reverse DNS and HTTP banner identified the host as AdGuard DNS infrast`
- **Time**: 2026-07-21 04:13:47

### theharvester
- **Summary**: theHarvester did not produce any usable OSINT results for testphp.vulnweb.com, and the command is marked unsuccessful with an empty output body. In the broader session context, multiple reconnaissance steps appear to be affected by tooling or upstream issues rather than target-side security controls: dnsx failed due to an unsupported -oJ flag, crt.sh returned an nginx-served 502, WHOIS was terminated, and subfinder found no additional subdomains. The currently observed A record, 94.140.14.33, appears associated with AdGuard DNS rather than the expected web application origin, so DNS resolution may be polluted, filtered, proxied, or otherwise not representative of the actual target.
- **Evidence**: `Tool: theharvester; Target: testphp.vulnweb.com; Success: False; Tool output was empty. Session context shows repeated reconnaissance reliability issues rather than confirmed target findings: dnsx produced no DNS results because the binary does not support the requested -oJ flag; subfinder completed`
- **Time**: 2026-07-21 04:15:16

### whatweb
- **Summary**: WhatWeb received an HTTP 500 from http://testphp.vulnweb.com and only fingerprinted a generic HTML5/Script page plus a server banner of AdGuardDNS/1218. This is not a normal application fingerprint and strongly suggests the request is being handled by an upstream DNS/proxy/sinkhole layer, a misrouted virtual host, or a defensive front end rather than the intended web application. At this stage, there is no confirmed app-level vulnerability; the most useful next step is to validate whether the target resolves to the expected service and whether alternate hostnames, HTTPS, or different Host headers expose the real application.
- **Evidence**: `WhatWeb output returned http_status 500 for http://testphp.vulnweb.com and fingerprinted only plugins for Country=FRANCE, HTML5, HTTPServer=AdGuardDNS/1218, IP=94.140.14.33, and Script. The server banner does not match the expected application stack and the session context already notes the same IP,`
- **Time**: 2026-07-21 04:16:23

### redirect_check
- **Summary**: The redirect check succeeded and shows that http://testphp.vulnweb.com redirects only to its canonical trailing-slash URL, http://testphp.vulnweb.com/. This finding does not indicate an exploitable redirect issue by itself, but it confirms an HTTP-accessible web service on port 80 and suggests the site is not enforcing HTTPS during this request. Given earlier reconnaissance anomalies showing AdGuardDNS/1218 and HTTP 500 behavior, this result should be treated as a basic reachability/canonicalization finding rather than reliable application fingerprinting.
- **Evidence**: `redirect_check against http://testphp.vulnweb.com completed successfully and returned: REDIRECT:http://testphp.vulnweb.com/. This demonstrates the target responds over HTTP and redirects to the same host with a trailing slash rather than upgrading to HTTPS or redirecting to a different host.`
- **Time**: 2026-07-21 04:16:50

### redirect_target
- **Summary**: Switch web target to redirect domain: http://testphp.vulnweb.com
- **Time**: 2026-07-21 04:16:51

### ffuf_vhost
- **Summary**: The virtual-host fuzzing run against http://testphp.vulnweb.com completed successfully but did not identify any additional valid subdomain-based virtual hosts from the supplied 4,750-entry wordlist. The scan observed a dominant response profile of 382231 bytes, 19013 words, and 6 lines, which was filtered out as likely noise/catch-all behavior, leaving zero actionable vhost hits. This is an informational reconnaissance result rather than a vulnerability, but it suggests that either name-based vhosts are not exposed for the tested namespace or the current filters/wordlist did not cover them.
- **Evidence**: `ffuf command used Host-header fuzzing with '-H Host: FUZZ.testphp.vulnweb.com' against 'http://testphp.vulnweb.com' using 4,750 candidate vhosts. The results array is empty: "results": []. Calibration showed dominant response characteristics of size 382231, words 19013, and lines 6, which were appli`
- **Time**: 2026-07-21 04:18:36

### httpx
- **Summary**: The httpx run against http://testphp.vulnweb.com did not return usable output and is marked unsuccessful, so this specific result does not confirm a reachable application fingerprint or vulnerability. Prior session context shows the host canonicalizes to http://testphp.vulnweb.com/ and has intermittently returned HTTP 500 with a generic HTML5/JavaScript page and an AdGuardDNS/1218 banner, which likely indicates an upstream resolver/filtering/error page rather than the real application stack. No additional virtual hosts were discovered via ffuf vhost fuzzing, so the next step should be direct application enumeration against the canonical HTTP URL while validating DNS and proxy behavior.
- **Evidence**: `httpx result: Target http://testphp.vulnweb.com, Success: False, Tool output empty. Session context notes ffuf vhost fuzzing completed successfully but found no additional valid subdomain-based virtual hosts from a 4,750-entry wordlist. Redirect check shows http://testphp.vulnweb.com redirects only `
- **Time**: 2026-07-21 04:19:06

### curl_headers
- **Summary**: The HTTP request to http://testphp.vulnweb.com returned a 500 Internal Server Error with a Server banner of AdGuardDNS/1218, which suggests the response may be coming from an intermediary DNS/filtering/proxy layer rather than the expected vulnerable web application. In the current reconnaissance context, multiple tools have failed to obtain a reliable application fingerprint, so this result does not confirm the actual backend technology stack or an exploitable web vulnerability. The main actionable finding is that the target is reachable over HTTP on port 80 but is currently returning an abnormal error response that may be caused by DNS resolution, filtering, virtual-host handling, or upstream application failure.
- **Evidence**: `curl_headers against http://testphp.vulnweb.com succeeded at the transport level but returned: HTTP/1.1 500 Internal Server Error, Content-Type: text/html, Server: AdGuardDNS/1218, Date: Tue, 21 Jul 2026 04:19:07 GMT. Session context also states that httpx did not return usable output, WhatWeb only `
- **Time**: 2026-07-21 04:19:29

### cms_detect
- **Summary**: The CMS detection module did not identify any known CMS, framework, or interesting default paths on http://testphp.vulnweb.com/. This suggests the application is either custom-built, not fingerprintable by the scanner, or the scan received non-application responses due to upstream filtering/interception observed in earlier results. In a CTF/boot2root context, lack of CMS fingerprinting does not reduce attack surface; the target should be treated as a custom web application where manual enumeration of forms, parameters, and dynamic endpoints is likely more productive.
- **Evidence**: `cms_detect returned success but no CMS, frameworks, interesting_paths, or tech_discovered: {"cms": [], "frameworks": [], "interesting_paths": [], "root_url": "http://testphp.vulnweb.com/", "target": "http://testphp.vulnweb.com", "tech_discovered": []}. Session context also shows inconsistent upstrea`
- **Time**: 2026-07-21 04:20:06

### katana
- **Summary**: Katana successfully crawled the target but only reported the site root, indicating either a very shallow crawl result, limited link discovery, blocking/intermediary behavior, or a crawl configuration that did not extract additional URLs. The broader session context contains conflicting infrastructure fingerprints: the application target is testphp.vulnweb.com, but prior tooling saw AdGuardDNS/1218 and a 500 response, suggesting some requests may have been intercepted, misrouted, filtered, or affected by DNS/HTTP tooling behavior rather than accurately fingerprinting the web application. In a CTF/boot2root workflow, the main value of this result is confirming the crawl did not enumerate useful paths yet; manual browsing, alternate crawlers, parameter discovery, and classic web vulnerability testing should follow.
- **Evidence**: `Katana output shows: 'Started standard crawling for => http://testphp.vulnweb.com' and only emitted 'http://testphp.vulnweb.com' as a discovered URL. Session context also records previous observations including 'curl_headers: The HTTP request to http://testphp.vulnweb.com returned a 500 Internal Ser`
- **Time**: 2026-07-21 04:20:44

### js_dump
- **Summary**: The JavaScript extraction/dump phase completed successfully but found no pages, JavaScript URLs, or client-side artifacts, so this result does not expose any client-side endpoints, secrets, routes, or framework fingerprints. In context, prior reconnaissance also shows inconsistent reachability and possible intermediary behavior, including a 500 response with an AdGuardDNS/1218 banner rather than the expected origin web server, suggesting the scanner may not be reaching the intended application consistently. This finding is therefore informational by itself, but it increases the need to validate DNS resolution, Host header behavior, redirects, and baseline HTTP access before relying on crawl-derived results.
- **Evidence**: `js_dump reported Success: True but returned empty collections: pages=[], js_urls=[], artifacts=[]. Session context also notes that katana only reported the site root, cms_detect identified no known CMS/framework/default paths, httpx did not return usable output, and curl_headers saw a 500 Internal S`
- **Time**: 2026-07-21 04:21:11

### js_deobfuscate
- **Summary**: The JavaScript deobfuscation phase completed successfully but did not recover any decoded scripts, hidden endpoints, secrets, routes, or client-side artifacts. In the current reconnaissance context, this means there is no evidence of obfuscated client-side logic to exploit, and attack focus should shift toward server-side discovery, parameterized PHP endpoints, and resolving the apparent intermediary/banner inconsistency where prior requests returned AdGuardDNS/1218 and HTTP 500 responses.
- **Evidence**: `Tool js_deobfuscate completed with Success: True and returned {"decoded": [], "artifacts": []}. Related session findings state that JavaScript extraction/dump found no pages, JavaScript URLs, or client-side artifacts; Katana only reported the site root; CMS detection found no known CMS; and curl_hea`
- **Time**: 2026-07-21 04:21:34

### js_mine
- **Summary**: The JavaScript mining phase completed successfully but did not identify any client-side endpoints, embedded secrets, source maps, or other JavaScript artifacts. This is a negative reconnaissance result: there is currently no evidence of exposed API routes, credentials, debug bundles, or source-map leakage from JavaScript. In the broader context, this suggests the application may be mostly server-rendered PHP/HTML or that crawl coverage was too shallow to discover linked scripts.
- **Evidence**: `js_mine executed against http://testphp.vulnweb.com with Success: True and returned {"endpoints": [], "secrets": [], "source_maps": [], "artifacts": []}. Session context also reports that js_deobfuscate recovered no decoded scripts, hidden endpoints, secrets, routes, or client-side artifacts; js_dum`
- **Time**: 2026-07-21 04:21:58

### cms_detect
- **Summary**: The CMS detection phase did not identify a known CMS, framework, interesting default path, or specific technology fingerprint on http://testphp.vulnweb.com/. In context, this is a negative fingerprinting result rather than proof of a hardened target: previous reconnaissance still confirms an HTTP web application with robots.txt exposed and a suspicious /project-admins path returning HTTP 500. The lack of CMS indicators suggests the target may be a custom or intentionally vulnerable PHP-style application, so manual parameter and endpoint testing is likely more valuable than CMS-specific exploit checks.
- **Evidence**: `cms_detect returned Success: True with empty arrays for cms, frameworks, interesting_paths, and tech_discovered: {"cms": [], "frameworks": [], "interesting_paths": [], "root_url": "http://testphp.vulnweb.com/", "target": "http://testphp.vulnweb.com", "tech_discovered": []}. Session context additiona`
- **Time**: 2026-07-21 04:31:55

### curl_body
- **Summary**: The retrieved robots.txt for http://testphp.vulnweb.com explicitly applies to all crawlers and disallows the entire site using `Disallow: /`. In a CTF or boot2root context, this does not enforce access control, but it is a reconnaissance signal that the site operator intended to hide all crawlable content from search engines, making manual crawling, directory brute forcing, and parameter discovery worthwhile. Combined with earlier discovery of an anomalous `/project-admins` path returning HTTP 500, this suggests there may be hidden or unstable application areas worth further investigation.
- **Evidence**: `curl successfully retrieved http://testphp.vulnweb.com/robots.txt. Raw body: `User-agent: *\nDisallow: /`. Session context also reports prior recursive ffuf discovery confirming `/robots.txt` with HTTP 200 and a suspicious `/project-admins` path returning HTTP 500 with an empty response.`
- **Time**: 2026-07-21 04:32:43

### arjun
- **Summary**: Arjun completed successfully against http://testphp.vulnweb.com but returned an empty result set, meaning it did not discover hidden or undocumented HTTP parameters on the tested target scope. This does not rule out parameter-based vulnerabilities because Arjun only identifies candidate parameter names and may miss application-specific parameters, parameters reachable only through crawling, POST bodies, JavaScript-driven requests, or authenticated workflows. In the broader recon context, the target still exposes web content over HTTP and prior enumeration identified /robots.txt and a suspicious /project-admins endpoint returning HTTP 500, which remain more actionable than this specific Arjun result.
- **Evidence**: `Arjun reported Success: True with tool output: {}. This means the scan executed but did not identify any candidate parameters. Session context also shows prior recon findings: /robots.txt returned HTTP 200, /project-admins returned HTTP 500 with an empty response, HTTP/1.1 is in use, and technologie`
- **Time**: 2026-07-21 04:33:05

### nuclei_cve
- **Summary**: The Nuclei CVE scan did not run, so no vulnerability assessment was produced from this tool invocation. The failure is environmental rather than target-side: Nuclei reported that no templates were provided, and prior context confirms the local template installation is incomplete or misconfigured. The target remains a reachable HTTP application with a PHP web stack and nginx/Golang-style fronting hints, so manual web enumeration is still warranted.
- **Evidence**: `["FTL] Could not run nuclei: no templates provided for scan", "Session context: nuclei_smart scan did not execute because the local Nuclei template installation is incomplete or misconfigured, specifically missing the http/exposures template directory", "Session context: Live subdomain reconnaissanc`
- **Time**: 2026-07-21 04:35:57

### dns_check
- **Summary**: The DNS-specific check against testphp.vulnweb.com found TCP/UDP DNS service on port 53 closed, so this host does not appear to be acting as an exposed authoritative or recursive DNS server. This reduces the likelihood of DNS recursion abuse, direct zone-transfer leakage, or DNS service exploitation on the target host itself. In the broader CTF context, effort should remain focused on the confirmed HTTP/PHP attack surface rather than DNS-layer exploitation.
- **Evidence**: `dns_check output reported service=dns, purpose=DNS recursion and zone leakage, ports=53, and '53: closed'. Session context separately confirms the host is live over HTTP as a PHP web application with robots.txt present, HTTP/1.1, HTML5/JavaScript, and an nginx/Golang-style fronting stack.`
- **Time**: 2026-07-21 04:36:20

## Attack Leads
- **MEDIUM**: CMS/technology found; check public CVEs, admin panels, exposed modules, and login surfaces.
- **MEDIUM**: Admin/debug/backup endpoint exposed; probe for default credentials, information disclosure, and auth bypass.
- **MEDIUM**: API endpoints discovered; probe for parameter injection, IDOR, excessive data exposure, and missing auth.
- **HIGH**: LLM analysis suggests specific vulnerability classes present; prioritize targeted testing based on identified classes.

## Recommendations
- ▶ Tech stack detected — check CVEs per version
- ▶ Run nuclei_smart + nuclei_cve with matching CVE templates
- ▶ Re-run with --verbose for detailed output