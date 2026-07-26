# Recon Report: scanme.nmap.org
**Generated**: 2026-07-21T11:36:22.595177

## Executive Summary
- **Total findings**: 42
- Critical: 0 | High: 0 | Medium: 17 | Low: 7 | Info: 18

- **Tech stack**: Apache httpd 2.4.7, Ubuntu unknown, Nmap Project favicon/site unknown, DNS A record N/A, subfinder 2.14.0, dnsx unknown; installed build does not support -oJ, Nmap Project site/branding unknown, Ubuntu Linux unknown, Google Analytics Universal, HTML5 unknown, Google Analytics Universal unknown, ffuf unknown, HTML unknown, Nmap Project site assets/branding unknown, Static CSS assets unknown, Static JavaScript assets unknown, Nmap Project Site Template / shared assets unknown, Static JavaScript unknown, Static CSS unknown, Google Analytics Universal analytics.js, Twitter Widgets unknown, Subversion working copy metadata unknown, Nmap Project site/template assets unknown, Apache mod_autoindex unknown, Ubuntu Linux , Apache mod_autoindex , Static HTML/CSS/JavaScript , Google Analytics Universal , Twitter Widgets , Subversion working copy metadata , Nmap Project site branding/template , Go ahead and ScanMe! , Index of /images , Static HTML/CSS/JavaScript unknown, Nmap Project site branding/template unknown, Google Analytics Universal analytics.js unknown, DNS not exposed on target host
- **Open ports**: 53/DNS resolution observed via recursive resolver, 53/closed, 80/Apache httpd 2.4.7, 80/Apache/2.4.7 (Ubuntu), 80/HTTP, 80/HTTP - Apache httpd 2.4.7 on Ubuntu, 80/http, 443/https

## MEDIUM Findings

### js_dump
- **Summary**: Artifact saved: source from http://scanme.nmap.org/shared/js/nst.js
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:21

### js_dump
- **Summary**: Artifact saved: source from http://scanme.nmap.org/shared/js/nst.js?v=2
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:21

### js_dump
- **Summary**: Artifact saved: source from http://www.google-analytics.com/analytics.js
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:21

### js_dump
- **Summary**: Artifact saved: source from https://nmap.org/shared/js/nst.js?v=2
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:21

### js_dump
- **Summary**: Artifact saved: source from https://platform.twitter.com/widgets.js
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:21

### js_dump
- **Summary**: Artifact saved: source from https://www.google-analytics.com/analytics.js
- **Evidence**: `javascript discovered from crawl/target`
- **Time**: 2026-07-21 04:18:22

### js_deobfuscate
- **Summary**: Artifact saved: source from outputs/scanme.nmap.org/artifacts/js/platform.twitter.com_widgets.js.2ba02cd5.js
- **Evidence**: `static javascript beautified`
- **Time**: 2026-07-21 04:18:50

### js_deobfuscate
- **Summary**: Artifact saved: source from outputs/scanme.nmap.org/artifacts/js/nmap.org_shared_js_nst.js.a0f3b9ad.js
- **Evidence**: `static javascript beautified`
- **Time**: 2026-07-21 04:18:50

### js_deobfuscate
- **Summary**: Artifact saved: source from outputs/scanme.nmap.org/artifacts/js/scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js
- **Evidence**: `static javascript beautified`
- **Time**: 2026-07-21 04:18:50

### js_deobfuscate
- **Summary**: Artifact saved: source from outputs/scanme.nmap.org/artifacts/js/www.google-analytics.com_analytics.js.f1a61277.js
- **Evidence**: `static javascript beautified`
- **Time**: 2026-07-21 04:18:50

### ffuf_dir
- **Summary**: Directory brute forcing against http://scanme.nmap.org identified a small Apache-hosted static-looking web root with several interesting paths: /index and /index.html return the same 200 response, while /images/, /shared/, and /.svn/ redirect as directories. Access to common sensitive dotfiles such as /.htaccess, /.htpasswd, /.hta, and /.svn/entries is denied with 403, which confirms Apache access controls are active but also suggests hidden/version-control-related paths exist and should be probed carefully. The presence of a browsable-looking /.svn directory redirect is the most notable lead because exposed Subversion metadata can sometimes disclose source files, repository structure, credentials, or historical content if individual metadata files are accessible despite some 403 responses.
- **Evidence**: `ffuf was run with: ffuf -u http://scanme.nmap.org/FUZZ -w ... -fc 404. Notable results include /.svn returning status 301 with redirectlocation http://scanme.nmap.org/.svn/ and length 316; /.svn/entries returning 403 length 294; /.htaccess and /.htpasswd returning 403 length 291; /.hta returning 403`
- **Time**: 2026-07-21 04:20:26

### ffuf_recursive
- **Summary**: Recursive ffuf enumeration of http://scanme.nmap.org found a mostly static Apache-hosted web root with several accessible and restricted paths. The most notable finding is the presence of a /.svn directory that redirects to /.svn/, while direct access to /.svn/entries is forbidden, indicating Subversion working-copy metadata may exist but is access-controlled by the web server. The scan also confirmed /images/ and /shared/ as directory paths, and /index plus /index.html returning identical 200 responses, consistent with a simple static site using shared assets.
- **Evidence**: `ffuf command used recursive discovery against http://scanme.nmap.org/FUZZ with recursion depth 2 and filtered 404 responses. Notable results include /.svn returning 301 with redirectlocation http://scanme.nmap.org/.svn/, /.svn/entries returning 403 with length 294, /.htaccess returning 403, /.htpass`
- **Time**: 2026-07-21 04:25:51

### ffuf_ext
- **Summary**: The extension brute-force tool did not return usable output and reported Success: False, so no new extension-specific endpoints can be confirmed from this run. However, prior ffuf enumeration shows the target is a mostly static Apache-hosted site with accessible and restricted paths, and the most important confirmed lead remains exposed Subversion metadata under /.svn. In a CTF or boot2root context, exposed VCS metadata is a high-value information disclosure issue because it may allow reconstruction of source files, historical paths, credentials, deployment notes, or hidden application logic.
- **Evidence**: `Tool ffuf_ext returned Success: False with no direct output, so no new extension findings are proven by this run. Session context reports Apache httpd 2.4.7 on Ubuntu, an Apache-hosted static-looking web root, /index and /index.html returning 200, and prior ffuf_recursive finding: 'The most notable `
- **Time**: 2026-07-21 04:31:21

### cms_detect
- **Summary**: The target appears to be a mostly static Apache-hosted website rather than a CMS, with page titles indicating a branded landing page and an exposed directory listing under /images. In the broader recon context, this host also shows signs of Apache autoindexing and exposed Subversion metadata, which are classic information-disclosure misconfigurations that can reveal source files, hidden paths, and deployment details. No direct RCE or auth bypass is evidenced here, but the exposed directories and version/control artifacts make this a promising CTF foothold for further enumeration.
- **Evidence**: `Raw output shows generic CMS inference only from page titles: "title: Go ahead and ScanMe!" and "title: Index of /images". The returned interesting paths include a live directory listing at "http://scanme.nmap.org/images/" and "http://scanme.nmap.org/index", indicating exposed content and autoindex-`
- **Time**: 2026-07-21 04:32:33

### subdomain_live
- **Summary**: The subdomain_live step completed successfully for scanme.nmap.org, but the provided raw tool output does not list any newly discovered live subdomains or additional hosts. In context, reconnaissance has already identified a mostly static Apache 2.4.7 site on Ubuntu with Apache autoindex enabled under /images and exposed Subversion working copy metadata under /.svn, which is the most actionable finding because it may allow source disclosure, recovery of deleted files, credentials, or hidden paths. The environment appears intentionally public and static, but the combination of legacy Apache/Ubuntu fingerprinting, directory indexing, and SCM metadata exposure is significant in a CTF/boot2root workflow.
- **Evidence**: `The subdomain_live tool reported Success: True but did not provide visible raw host output. Session context identifies Apache httpd 2.4.7 on Ubuntu, a mostly static Apache-hosted Nmap Project-branded site, Google Analytics Universal, Twitter Widgets, Apache mod_autoindex, an accessible 'Index of /im`
- **Time**: 2026-07-21 04:34:57

### nuclei_smart
- **Summary**: The nuclei_smart scan did not execute successfully because the local Nuclei template directory is incomplete or missing, specifically the http/exposures template path. As a result, no new vulnerability findings can be attributed to Nuclei from this run; however, existing reconnaissance context still indicates an Apache 2.4.7 Ubuntu-hosted static site with directory listing under /images and exposed Subversion metadata under /.svn, both of which are valuable CTF attack leads. The most important immediate issue is not a confirmed Nuclei finding, but the need to manually investigate the already discovered /.svn exposure and Apache mod_autoindex behavior.
- **Evidence**: `Nuclei failed before scanning: '[FTL] Could not run nuclei: could not create automatic scan service: could not get templates in directory: could not find file: open /home/ngannguyen/.local/nuclei-templates/http/exposures/: no such file or directory'. Session context reports Apache httpd 2.4.7 on Ubu`
- **Time**: 2026-07-21 04:35:22

### nuclei_cve
- **Summary**: The nuclei_cve step did not execute because the local Nuclei installation has no templates configured, so this run produced no CVE validation against http://scanme.nmap.org. In the broader reconnaissance context, the target appears to be a mostly static Apache httpd 2.4.7 site on Ubuntu with Apache autoindex enabled and exposed Subversion working-copy metadata, which is more actionable than the failed CVE scan itself. The most important follow-up is to fix the Nuclei template installation and manually investigate the exposed /.svn content for source disclosure, hidden paths, credentials, or deployment artifacts.
- **Evidence**: `The nuclei_cve tool returned Success: False with fatal error: "Could not run nuclei: no templates provided for scan", meaning no CVE findings were produced by this run. Existing session context identifies Apache httpd 2.4.7 on Ubuntu, Apache mod_autoindex, an exposed "Index of /images", and prior re`
- **Time**: 2026-07-21 04:36:01

## LOW Findings

### nmap
- **Summary**: The target scanme.nmap.org at 45.33.32.156 is reachable and exposes a single open TCP service: HTTP on port 80, running Apache httpd 2.4.7 on Ubuntu. Several mail/database-related ports are explicitly closed, while 104 scanned TCP ports are filtered, indicating firewalling or packet filtering. In a CTF/boot2root context, the web service is the primary attack surface and should be enumerated for hidden content, vulnerable applications, default files, and Apache/Ubuntu-specific misconfigurations.
- **Evidence**: `Nmap reports host 45.33.32.156 is up with 0.22s latency. Port 80/tcp is open and identified as 'http Apache httpd 2.4.7 ((Ubuntu))'. NSE output shows 'http-server-header: Apache/2.4.7 (Ubuntu)', 'http-title: Go ahead and ScanMe!', and 'http-favicon: Nmap Project'. Ports 25, 110, 143, 443, 465, 587, `
- **Time**: 2026-07-21 04:08:42

### whatweb
- **Summary**: WhatWeb confirms that http://scanme.nmap.org is serving HTTP successfully on port 80 with Apache httpd 2.4.7 on Ubuntu, returning a 200 OK page titled "Go ahead and ScanMe!". The exposed server version is old and may indicate an outdated Ubuntu/Apache stack, but this finding alone is primarily reconnaissance and version-disclosure rather than proof of exploitable compromise. The site also includes Google Analytics Universal tracking and client-side scripting, which may provide additional pages or JavaScript-driven functionality to review during content discovery.
- **Evidence**: `WhatWeb returned HTTP 200 for http://scanme.nmap.org and identified Apache version 2.4.7 via the Apache plugin. The HTTPServer plugin reported "Apache/2.4.7 (Ubuntu)" with OS "Ubuntu Linux". The IP plugin identified 45.33.32.156, the Title plugin reported "Go ahead and ScanMe!", and additional plugi`
- **Time**: 2026-07-21 04:13:37

### httpx
- **Summary**: The httpx execution itself failed and produced no direct output, so it does not add new HTTP fingerprinting evidence beyond the existing reconnaissance context. Prior tooling indicates the target is reachable over HTTP on port 80, serves a 200 OK Apache default/custom page titled "Go ahead and ScanMe!", and is running Apache httpd 2.4.7 on Ubuntu. Virtual-host fuzzing did not reveal additional vhosts, and redirect testing only identified benign canonicalization to a trailing-slash URL. In a CTF/boot2root context, this currently looks like a small exposed HTTP surface with one confirmed web service and an outdated Apache/Ubuntu stack worth enumerating more deeply.
- **Evidence**: `httpx result: Success=False with no raw tool output. Session context reports prior WhatWeb evidence: HTTP on port 80 returns 200 OK, title "Go ahead and ScanMe!", Apache httpd 2.4.7 on Ubuntu. Prior nmap evidence reports scanme.nmap.org at 45.33.32.156 is reachable with a single open TCP service: HT`
- **Time**: 2026-07-21 04:15:27

### curl_headers
- **Summary**: The HTTP service on http://scanme.nmap.org is reachable and returns a 200 OK response from Apache httpd 2.4.7 on Ubuntu. The response exposes detailed server/version information via the Server header, which is useful for targeted vulnerability research and suggests an older Ubuntu-era Apache build. No application-specific headers, cookies, redirects, or security headers are present in this header sample, so the immediate finding is primarily service fingerprinting and potential outdated software exposure.
- **Evidence**: `curl_headers returned HTTP/1.1 200 OK for http://scanme.nmap.org. The response includes 'Server: Apache/2.4.7 (Ubuntu)', 'Content-Type: text/html', 'Accept-Ranges: bytes', and 'Vary: Accept-Encoding'. Prior context also indicates nmap found a single open TCP service, HTTP on port 80, and WhatWeb ide`
- **Time**: 2026-07-21 04:15:50

### curl_body
- **Summary**: The /images/ directory is browsable and exposes an Apache autoindex listing, confirming directory indexing is enabled for at least one static asset directory. The listing discloses server technology and version information via the footer: Apache/2.4.7 on Ubuntu, which is an old Apache release commonly associated with Ubuntu 14.04-era systems. Only one file, sitelogo.png, is exposed here, so this specific path is low impact by itself, but in combination with prior findings such as accessible /.svn metadata, it supports a broader information disclosure and source/configuration recovery attack path.
- **Evidence**: `The response is an Apache-generated directory index for /images/: '<title>Index of /images</title>' and '<h1>Index of /images</h1>'. It lists a parent directory link and one image file: '<a href="sitelogo.png">sitelogo.png</a>' with timestamp '2015-04-16 04:19' and size '18K'. The footer discloses s`
- **Time**: 2026-07-21 04:31:45

### web_download_interesting
- **Summary**: A direct request to http://scanme.nmap.org/.htpasswd returned HTTP 403 Forbidden, indicating Apache is actively denying access to this sensitive filename rather than exposing it. This is a positive access-control result, but the existence of a 403 response still confirms that hidden/sensitive-file probing reaches Apache-level authorization logic and should be compared against other dotfiles, backup extensions, and exposed metadata paths such as the previously discovered /.svn directory. In the broader reconnaissance context, the target appears to be a mostly static Apache 2.4.7 on Ubuntu site with mod_autoindex exposure and Subversion metadata, so credential/configuration disclosure remains a more promising path than this specific .htpasswd URL.
- **Evidence**: `The tool attempted to download http://scanme.nmap.org/.htpasswd and failed with urllib.error.HTTPError: HTTP Error 403: Forbidden. Session context also reports Apache httpd 2.4.7 on Ubuntu, Apache mod_autoindex, an exposed Index of /images, and previously discovered Subversion working copy metadata `
- **Time**: 2026-07-21 04:32:54

### curl_body
- **Summary**: A direct request to http://scanme.nmap.org/.htpasswd returned HTTP 403 Forbidden rather than exposing credential hashes, indicating Apache is denying access to .ht* files as expected. The response discloses the web server banner as Apache/2.4.7 on Ubuntu, which is an old Apache version and should be treated as useful fingerprinting information in the broader CTF/boot2root chain. This finding is not directly exploitable by itself, but it reinforces that sensitive dotfiles and metadata paths are relevant on this host, especially given prior discovery of exposed Subversion metadata.
- **Evidence**: `Request to http://scanme.nmap.org/.htpasswd succeeded at the HTTP transport level but returned an Apache 403 Forbidden page: '<h1>Forbidden</h1><p>You don't have permission to access /.htpasswd on this server.</p>'. The footer disclosed '<address>Apache/2.4.7 (Ubuntu) Server at scanme.nmap.org Port `
- **Time**: 2026-07-21 04:33:15

## INFO Findings

### whois
- **Summary**: The WHOIS lookup for scanme.nmap.org did not complete because the process was interrupted by signal 15, so it provides no reliable registrant, netblock, ASN, or ownership intelligence. Based on the session context, the target remains reachable at 45.33.32.156 with a single confirmed exposed TCP service: HTTP on port 80 running Apache httpd 2.4.7 on Ubuntu. In a CTF or boot2root context, the failed WHOIS result should be treated as an enumeration gap rather than a finding, while the exposed web service remains the primary attack surface.
- **Evidence**: `WHOIS command failed with: 'Interrupted by signal 15...'. Session context states: 'Apache httpd 2.4.7, Ubuntu unknown, Nmap Project favicon/site unknown' and '[low] nmap: The target scanme.nmap.org at 45.33.32.156 is reachable and exposes a single open TCP service: HTTP on port 80, running Apache ht`
- **Time**: 2026-07-21 04:09:15

### dig
- **Summary**: DNS resolution for scanme.nmap.org succeeded and returned a single A record pointing to 45.33.32.156, confirming the hostname-to-IP mapping for subsequent web and network testing. The response was NOERROR with a TTL of 2761 seconds and was received from the configured recursive resolver at 10.22.103.10. In the current context, this reinforces that the previously discovered Apache HTTP service on port 80 should be tested both by IP address and by hostname, because name-based virtual hosting may expose different content or behavior.
- **Evidence**: `DiG query for scanme.nmap.org A returned status NOERROR with one answer: scanme.nmap.org. 2761 IN A 45.33.32.156. The response came from DNS resolver 10.22.103.10#53 over UDP and completed successfully with query time 0 msec. Session context also notes that 45.33.32.156 is reachable and exposes HTTP`
- **Time**: 2026-07-21 04:09:37

### crt_sh
- **Summary**: The crt.sh lookup for scanme.nmap.org completed successfully but returned no certificate transparency entries, indicating there are no publicly logged TLS certificates for this exact hostname in the queried data set. This is consistent with the currently observed exposure being plain HTTP on port 80 rather than HTTPS, and it does not reveal additional subdomains, SAN names, or virtual hosts to expand the attack surface. In a CTF/boot2root context, this reduces the usefulness of certificate-based recon but reinforces focusing on the discovered Apache HTTP service and alternate vhost/content discovery techniques.
- **Evidence**: `crt_sh lookup for target scanme.nmap.org succeeded but returned an empty array: []. Session context shows DNS resolution for scanme.nmap.org points to 45.33.32.156 and prior service detection found a single open TCP service: HTTP on port 80 running Apache httpd 2.4.7 on Ubuntu.`
- **Time**: 2026-07-21 04:09:57

### subfinder
- **Summary**: Subdomain enumeration for scanme.nmap.org completed successfully and identified one additional hostname: nmap.scanme.nmap.org, sourced from Wayback Machine archival data. This expands the target surface beyond the previously confirmed scanme.nmap.org host at 45.33.32.156, which is known from earlier reconnaissance to expose HTTP on TCP/80 running Apache httpd 2.4.7 on Ubuntu. Because the discovered subdomain comes from historical data, it should be validated with DNS resolution, HTTP probing, and virtual-host testing before assuming it is live or mapped to the same infrastructure.
- **Evidence**: `subfinder reported successful enumeration for scanme.nmap.org and found one subdomain: {"host":"nmap.scanme.nmap.org","input":"scanme.nmap.org","source":"waybackarchive"}. The tool output states: '[INF] Enumerating subdomains for scanme.nmap.org' and '[INF] Found 1 subdomains for scanme.nmap.org in `
- **Time**: 2026-07-21 04:11:13

### dnsx
- **Summary**: The dnsx run did not produce DNS intelligence because the command failed before execution due to an unsupported flag, specifically '-oJ'. This means no new DNS records, wildcard behavior, CNAMEs, resolvers, or additional host-to-IP mappings were validated by this tool invocation. Existing context remains the reliable basis for analysis: scanme.nmap.org resolves to 45.33.32.156, exposes HTTP on TCP/80, and appears to run Apache httpd 2.4.7 on Ubuntu, with one archival hostname nmap.scanme.nmap.org identified via subfinder.
- **Evidence**: `Tool execution failed with: 'flag provided but not defined: -oJ'. No dnsx results were generated. Prior session context indicates scanme.nmap.org resolves to 45.33.32.156, TCP/80 is open, Apache httpd 2.4.7 on Ubuntu was detected, and subfinder found nmap.scanme.nmap.org from Wayback Machine archiva`
- **Time**: 2026-07-21 04:11:35

### theharvester
- **Summary**: Reconnaissance shows the target 45.33.32.156 exposes only HTTP on port 80, running Apache httpd 2.4.7 on Ubuntu. DNS resolution for scanme.nmap.org is valid and a second hostname, nmap.scanme.nmap.org, was discovered via Wayback data, expanding the web attack surface. No certificate transparency entries were found for the exact hostname, and the dnsx step failed before execution, so DNS-based intelligence is incomplete.
- **Evidence**: `nmap reported one open TCP service: HTTP on port 80, running Apache httpd 2.4.7 on Ubuntu; dig resolved scanme.nmap.org to 45.33.32.156; subfinder identified nmap.scanme.nmap.org from Wayback Machine archival data; crt.sh returned no certificate transparency entries for the exact hostname; dnsx fail`
- **Time**: 2026-07-21 04:13:05

### redirect_check
- **Summary**: The redirect check against http://scanme.nmap.org completed successfully and indicates a redirect/canonicalization response to http://scanme.nmap.org/. This appears to be a benign normalization to the trailing-slash root URL rather than a meaningful external redirect or security-impacting behavior. In context, the target remains a simple HTTP-only Apache 2.4.7 service on Ubuntu with one additional discovered hostname, so further testing should focus on web content discovery, virtual host behavior, and legacy Apache/Ubuntu exposure rather than redirect abuse.
- **Evidence**: `redirect_check target http://scanme.nmap.org returned Success: True with output REDIRECT:http://scanme.nmap.org/. Prior reconnaissance context reports Apache httpd 2.4.7 on Ubuntu serving HTTP on port 80, a 200 OK page titled "Go ahead and ScanMe!", and one additional hostname discovered: nmap.scanm`
- **Time**: 2026-07-21 04:13:59

### redirect_target
- **Summary**: Switch web target to redirect domain: http://scanme.nmap.org
- **Time**: 2026-07-21 04:14:00

### ffuf_vhost
- **Summary**: Virtual-host fuzzing against http://scanme.nmap.org using a 4,750-entry vhost wordlist did not identify any additional name-based virtual hosts under the scanme.nmap.org domain. ffuf initially observed many baseline responses, then calibrated the dominant catch-all response profile with size 6974, 495 words, and 153 lines, and the final filtered run produced zero actionable results. This suggests either no discoverable vhosts exist in the tested wordlist, the server returns a uniform default page for unknown Host headers, or potentially valid vhosts were filtered out because they closely match the default response.
- **Evidence**: `ffuf command used Host-header fuzzing: `ffuf -u http://scanme.nmap.org ... -H Host: FUZZ.scanme.nmap.org -fc 404 -fs 6974 -fw 495 -fl 153`. The final `results` array is empty. Calibration showed an initial run with 24 apparent results, followed by a filtered rerun with `result_count: 0`. The dominan`
- **Time**: 2026-07-21 04:15:00

### cms_detect
- **Summary**: The CMS detection run completed successfully against http://scanme.nmap.org but did not identify any CMS, web framework, interesting paths, or additional web technologies. In the broader recon context, the host appears to be a simple Apache-served static or minimally dynamic site on Ubuntu, with prior evidence showing Apache httpd 2.4.7 and a 200 OK landing page titled "Go ahead and ScanMe!". This finding lowers the likelihood of CMS-specific attack paths such as WordPress, Joomla, or Drupal exploitation, but it does not rule out custom application flaws, Apache misconfiguration, exposed files, or hidden directories.
- **Evidence**: `cms_detect returned success=true with empty arrays for cms, frameworks, interesting_paths, and tech_discovered against root_url http://scanme.nmap.org/. Existing session evidence indicates the HTTP service is reachable on port 80, returns 200 OK, and exposes Apache httpd 2.4.7 on Ubuntu via prior cu`
- **Time**: 2026-07-21 04:16:20

### katana
- **Summary**: Katana successfully crawled http://scanme.nmap.org and found a small, mostly static web surface consisting of the root page and shared CSS/JavaScript assets, with many outbound links to nmap.org, npcap.com, seclists.org, sectools.org, insecure.org, and social platforms. No application-specific dynamic endpoints, forms, API routes, authentication paths, CMS paths, upload handlers, or obvious parameterized URLs were discovered in this crawl. In the broader recon context, this supports the assessment that scanme.nmap.org is likely a deliberately minimal Apache-hosted landing page rather than a feature-rich web application, so web exploitation opportunities appear limited unless hidden paths or server-level vulnerabilities are found.
- **Evidence**: `Katana output includes the root page and static local assets only: http://scanme.nmap.org, http://scanme.nmap.org/, http://scanme.nmap.org/site.css, http://scanme.nmap.org/shared/js/nst.js, http://scanme.nmap.org/shared/js/nst.js?v=2, http://scanme.nmap.org/shared/css/nst.css, http://scanme.nmap.org`
- **Time**: 2026-07-21 04:17:32

### js_dump
- **Summary**: The JavaScript crawl confirms that scanme.nmap.org exposes a very small, mostly static web surface consisting of the root page, shared CSS, and a single first-party JavaScript asset, with additional third-party scripts from Google Analytics and Twitter. The first-party script appears to be a shared Nmap Site Template asset reused between scanme.nmap.org and nmap.org, and no obvious application-specific API endpoints, credentials, source maps, or dynamic client-side routes were identified in this dump. From a CTF/boot2root perspective, this output does not reveal an immediate client-side exploit path, but it does identify several paths worth manually reviewing and reinforces that the exposed HTTP service is likely a static Apache-hosted site with limited attack surface.
- **Evidence**: `The js_dump crawl succeeded and discovered pages/assets including http://scanme.nmap.org, http://scanme.nmap.org/, http://scanme.nmap.org/shared/js/nst.js, http://scanme.nmap.org/shared/js/nst.js?v=2, http://scanme.nmap.org/site.css, and shared CSS files. JavaScript URLs included first-party assets `
- **Time**: 2026-07-21 04:18:21

### js_deobfuscate
- **Summary**: JavaScript deobfuscation/beautification completed successfully and produced local artifacts for first-party Nmap shared JavaScript as well as third-party Google Analytics and Twitter Widgets libraries. The attempted Base64 decodes appear to be false-positive pattern matches or non-meaningful decoded binary/control-character output rather than exposed secrets. The most relevant first-party asset is /shared/js/nst.js, which should be manually reviewed for client-side logic, hidden paths, DOM sinks, and assumptions about server-side endpoints, but this output alone does not demonstrate an exploitable vulnerability.
- **Evidence**: `Tool succeeded and produced beautified JavaScript artifacts: platform.twitter.com_widgets.js.2ba02cd5.js.beautified.js size 125575 sha256 [REDACTED:long_hex]; nmap.org_shared_js_nst.js.a0f3b9ad.js.beautified.js size 2655 sha256 [REDACTED:long_hex]; scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js.beauti`
- **Time**: 2026-07-21 04:18:50

### js_mine
- **Summary**: JavaScript mining did not expose any secrets, source maps, or application-specific artifacts, but it identified numerous analytics and social-widget endpoints referenced by the target page. The observed JavaScript footprint is dominated by Google Analytics Universal and Twitter/X widget integrations rather than custom application logic, suggesting limited immediate exploitability from client-side code. The most interesting items are target-relative paths such as /analytics, /collect, /g,, /j/collect, /plugins/, /plugins/ua/, and /widgets/*, which should be manually verified to determine whether they are real server-side routes, static assets, or third-party tracking artifacts rewritten as local paths.
- **Evidence**: `js_mine reported success and returned endpoints including target-relative paths: http://scanme.nmap.org/analytics, http://scanme.nmap.org/collect, http://scanme.nmap.org/g,, http://scanme.nmap.org/j/collect, http://scanme.nmap.org/plugins/, http://scanme.nmap.org/plugins/ua/, http://scanme.nmap.org/`
- **Time**: 2026-07-21 04:19:30

### cms_detect
- **Summary**: CMS/framework detected: Go ahead and ScanMe!
- **Evidence**: `title: Go ahead and ScanMe!`
- **Time**: 2026-07-21 04:32:33

### cms_detect
- **Summary**: CMS/framework detected: Index of /images
- **Evidence**: `title: Index of /images`
- **Time**: 2026-07-21 04:32:33

### arjun
- **Summary**: Arjun completed successfully against http://scanme.nmap.org but returned an empty result set, meaning it did not identify any reflected or discoverable HTTP GET/POST parameter names from the tested target surface. In the current reconnaissance context, this supports the assessment that the site is primarily static Apache-hosted content rather than a parameter-driven web application. The lack of parameters reduces immediate likelihood of classic parameter-based issues such as SQL injection, LFI, IDOR, and reflected XSS on the tested URLs, but prior findings such as exposed Subversion metadata and Apache autoindex remain more valuable attack leads.
- **Evidence**: `Arjun target: http://scanme.nmap.org; Success: True; Tool output: {}. The empty JSON object indicates no parameters were discovered by this run. Session context additionally reports a mostly static Apache-hosted site, Apache httpd 2.4.7 on Ubuntu, Apache mod_autoindex, an exposed directory listing a`
- **Time**: 2026-07-21 04:33:39

### dns_check
- **Summary**: The DNS recursion/zone-leakage check against scanme.nmap.org found port 53 closed, so this host does not appear to expose a DNS service directly. This reduces the likelihood of DNS-specific attack paths such as open recursion, AXFR zone transfer, or DNS service exploitation on the target host itself. In the broader CTF context, effort should remain focused on the confirmed Apache HTTP surface, exposed directory listing, and previously identified Subversion metadata rather than DNS on this host.
- **Evidence**: `Tool output shows service=dns, purpose=DNS recursion and zone leakage, ports=53, and '53: closed'. This indicates the target host scanme.nmap.org is not listening on DNS port 53 for the tested check. Session context separately identifies the primary exposed surface as Apache httpd 2.4.7 on Ubuntu wi`
- **Time**: 2026-07-21 04:36:21

## Artifacts
| Category | Service | Size | Source | Local Path | Reason |
|---|---:|---:|---|---|---|
| source | web | 2235 | `http://scanme.nmap.org/shared/js/nst.js` | `outputs/scanme.nmap.org/artifacts/js/scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js` | javascript discovered from crawl/target |
| source | web | 2235 | `http://scanme.nmap.org/shared/js/nst.js?v=2` | `outputs/scanme.nmap.org/artifacts/js/scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js` | javascript discovered from crawl/target |
| source | web | 52310 | `http://www.google-analytics.com/analytics.js` | `outputs/scanme.nmap.org/artifacts/js/www.google-analytics.com_analytics.js.f1a61277.js` | javascript discovered from crawl/target |
| source | web | 2235 | `https://nmap.org/shared/js/nst.js?v=2` | `outputs/scanme.nmap.org/artifacts/js/nmap.org_shared_js_nst.js.a0f3b9ad.js` | javascript discovered from crawl/target |
| source | web | 93967 | `https://platform.twitter.com/widgets.js` | `outputs/scanme.nmap.org/artifacts/js/platform.twitter.com_widgets.js.2ba02cd5.js` | javascript discovered from crawl/target |
| source | web | 52310 | `https://www.google-analytics.com/analytics.js` | `outputs/scanme.nmap.org/artifacts/js/www.google-analytics.com_analytics.js.f1a61277.js` | javascript discovered from crawl/target |
| source | web | 125575 | `outputs/scanme.nmap.org/artifacts/js/platform.twitter.com_widgets.js.2ba02cd5.js` | `outputs/scanme.nmap.org/artifacts/js/platform.twitter.com_widgets.js.2ba02cd5.js.beautified.js` | static javascript beautified |
| source | web | 2655 | `outputs/scanme.nmap.org/artifacts/js/nmap.org_shared_js_nst.js.a0f3b9ad.js` | `outputs/scanme.nmap.org/artifacts/js/nmap.org_shared_js_nst.js.a0f3b9ad.js.beautified.js` | static javascript beautified |
| source | web | 2655 | `outputs/scanme.nmap.org/artifacts/js/scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js` | `outputs/scanme.nmap.org/artifacts/js/scanme.nmap.org_shared_js_nst.js.a0f3b9ad.js.beautified.js` | static javascript beautified |
| source | web | 73607 | `outputs/scanme.nmap.org/artifacts/js/www.google-analytics.com_analytics.js.f1a61277.js` | `outputs/scanme.nmap.org/artifacts/js/www.google-analytics.com_analytics.js.f1a61277.js.beautified.js` | static javascript beautified |

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