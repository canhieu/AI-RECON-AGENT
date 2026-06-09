# Scoring

## Goal

Use a quick score to decide where to spend time.

## Default Score

Start at 0. Add what applies.

- Multi-host or multi-tenant target: +2
- Web app with auth: +2
- Upload, API, GraphQL, or custom backend: +2
- Internal/admin/debug exposure: +2
- Versioned service banner: +1
- Known public artifact leak: +2
- Staging/dev/backup environment exposed: +2
- Source maps or JS route leak: +1
- Clear vhost or tenant separation: +1
- Strong signal from passive recon: +1

## Go / No-Go

- 0-2: low value, verify only.
- 3-5: light recon only.
- 6-8: good target, expand carefully.
- 9+: high-priority target, do full surface mapping.

## Kill Signals

- Static landing only.
- No auth, no forms, no API, no hidden paths.
- Everything resolves to a generic default page.
- Repeated checks add no new signal.
- Target has no exploitable differentiation after basic verification.

## Boosters

- Fresh deployment.
- Multiple environments.
- Internal naming leaks.
- Custom admin or support endpoints.
- JS bundles with route strings.
- Large app with many user workflows.

## Deprioritizers

- Static marketing site only.
- No session or state.
- No parameterized paths.
- No non-default services.
- Repeated dead ends.

