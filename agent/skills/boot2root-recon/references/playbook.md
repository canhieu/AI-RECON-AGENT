# Boot2Root Recon Playbook

## Table Of Contents

1. Target shape
2. Passive recon
3. Active recon
4. Correlation
5. Decision rules
6. Output standards

## 1. Target Shape

Classify the target before probing.

### Inputs

- IP, CIDR, host, URL, bundle, screenshot, transcript, or partial notes.
- Scope limits, noise limits, time box, and known exclusions.

### Classify

- Single host vs multi-host.
- Web-first vs infra-first vs mixed.
- Public vs internal vs lab-only.
- Static vs dynamic vs authenticated.

### Immediate Questions

- What is live?
- What is reachable?
- What looks unusual?
- What could become the first foothold?

## 2. Passive Recon

Goal: gather evidence without touching the target directly.

### Sources

- DNS:
  - A/AAAA/CNAME/MX/NS/TXT.
  - Reverse DNS.
  - Cert transparency and SANs.
  - Zone-style naming patterns.
- Web footprint:
  - Search snippets.
  - Cached pages and archives.
  - JS bundles and source maps.
  - robots, sitemap, security, .well-known.
- Public artifacts:
  - Repos, package registries, docs, issue trackers, paste-like leaks.
  - Containers, images, manifests, changelogs.
- Identity:
  - Org names, project names, usernames, emails, environments.

### Passive Signals

- Hostnames and aliases.
- Stack hints.
- Version strings.
- Internal paths.
- API route patterns.
- Secret material accidentally exposed.
- Environment names: dev, test, staging, qa, internal, backup.

### Passive Filters

- Keep only reproducible data.
- Mark speculative matches as hypotheses.
- Preserve source and timestamp.

## 3. Active Recon

Goal: verify live surface with controlled probing.

### Order

1. Liveness and routing.
2. Port and service discovery.
3. Banner and version fingerprinting.
4. Hostname and vhost expansion.
5. Web path and parameter discovery.
6. JS/API harvesting.
7. Non-web enumeration.
8. Cross-surface correlation.

### Low-Noise First

- Start with the least invasive request that can answer the question.
- Only increase breadth after a signal.
- Recheck suspicious hosts with alternate Host headers, SNI, schemes, and ports.

### Web Checklist

- Response codes and redirects.
- Headers, cookies, and cache behavior.
- TLS CN/SAN, issuer, expiry, mismatch.
- robots, sitemap, security.txt, well-known.
- Static assets, JS bundles, source maps, inline comments.
- Forms, uploads, search, filters, exports.
- API docs, OpenAPI, GraphQL, websocket, SSE.
- Backup, temp, log, and debug paths.
- Hidden auth and admin surfaces.

### Non-Web Checklist

- SSH, FTP, SMTP, IMAP, POP3.
- SMB, NFS, LDAP, RDP, WinRM.
- Databases, caches, queues, brokers, custom daemons.
- Anonymous or guest access.
- Version banners and pre-auth behavior.

### Hidden Asset Checklist

- Historical URLs.
- Repo references.
- Client-side endpoints.
- Enum patterns in forms and errors.
- Filename leaks from directory listings or exports.

## 4. Correlation

Merge by evidence, not by assumption.

### Correlation Rules

- One hostname may hide many vhosts.
- One port may expose multiple apps.
- One app may have multiple environments.
- One JS bundle may reveal many backends.
- One cert may reveal tenant names or internal aliases.

### Promote To Confirmed Only When

- Reproducible.
- Source-backed.
- Distinct from a duplicate.

## 5. Decision Rules

### When To Expand

- New hostname appears.
- New service banner appears.
- New parameter family appears.
- JS or source map reveals routes.
- Auth, upload, or admin surface appears.
- Secret, token, or internal path appears.

### When To Stop Expanding

- Surface is flat and uninteresting.
- No auth, no data, no custom behavior.
- Repeated scans only return static noise.
- Better lead already exists.

### Lead Ranking

Rank by:

1. Auth or admin exposure.
2. Public secret or internal path.
3. Versioned vulnerable component with proof.
4. Upload, parameter, or deserialization surface.
5. Unusual custom behavior.

## 6. Output Standards

Return a fielded summary.

### Required Fields

- Target shape.
- Passive findings.
- Active findings.
- High-confidence leads.
- Unknowns.
- Next actions.

### Quality Bar

- Short.
- Evidenced.
- Prioritized.
- Actionable.

