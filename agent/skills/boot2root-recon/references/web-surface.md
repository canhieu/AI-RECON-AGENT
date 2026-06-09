# Web Surface

## Goal

Map every web entry point that can matter in a boot2root target.

## Web Priorities

1. Root page behavior.
2. Host header and vhost response differences.
3. Redirects, cookies, and auth.
4. JS bundles and source maps.
5. Historical URLs.
6. Parameter families.
7. Upload, export, import, search, and admin paths.

## High-Signal Probes

- `robots.txt`
- `sitemap.xml`
- `.well-known/*`
- `security.txt`
- `favicon.ico`
- `/api`
- `/graphql`
- `/swagger`
- `/openapi.json`
- `/docs`
- `/admin`
- `/login`
- `/upload`
- `/debug`
- `/backup`

## What To Extract

- Route names.
- Hostnames embedded in JS.
- API base URLs.
- Feature flags.
- Environment names.
- File and object names.
- Parameter families: `id`, `user`, `file`, `path`, `url`, `redirect`, `next`, `token`, `key`.

## Common Expansion Patterns

- Root page differs by Host header.
- JS bundle reveals hidden route constants.
- API calls reveal deeper object IDs.
- Search, filter, export, and report features leak structure.
- Upload flows expose filename handling and backend storage patterns.

## Evidence To Keep

- URL.
- Response code.
- Title or key text.
- Host header used.
- Relevant headers.
- Matching JS path or API path.

