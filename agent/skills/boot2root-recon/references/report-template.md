# Findings Template

This template is aspirational. Actual output from `reporter.py` uses a different format (Markdown sections: recon summary, findings by severity, service map, web routes, JS/API/fuzz routes, artifact table, attack leads, recommendations). See `agent/reporter.py` for exact output.

Use this for the final recon handoff.

## Target

- Primary target:
- Scope:
- Target type:
- Time box:

## Shape

- Single host / multi-host:
- Web / non-web / mixed:
- Public / internal / lab:
- Static / dynamic / authenticated:

## Passive Findings

- Domains:
- Subdomains:
- Aliases:
- Cert data:
- Public artifacts:
- Stack hints:
- Environment markers:

## Active Findings

- Open ports:
- Services:
- Versions:
- Web apps:
- APIs:
- Auth surfaces:
- Upload surfaces:
- Admin/debug surfaces:
- Non-web exposures:

## High-Confidence Leads

For each lead:

- Lead:
- Why it matters:
- Evidence:
- Confidence:
- Next probe:

## Unknowns

- Missing data:
- Why it blocks progress:
- Next probe:

## Rank

1. Best lead:
2. Secondary lead:
3. Tertiary lead:

## Next Actions

1. ...
2. ...
3. ...

