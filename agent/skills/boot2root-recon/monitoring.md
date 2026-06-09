# Monitoring

## Goal

Keep recon fresh when the target changes over time.

## Use When

- Long boot2root lab.
- Competition target with evolving surface.
- Target with multiple services or deployments.
- User asks for follow-up monitoring.

## Watch Items

- New subdomains.
- DNS changes.
- Cert changes.
- New open ports.
- New JS bundles.
- Route changes.
- Repo or release changes.
- New admin/debug surfaces.

## Cadence

- Daily for DNS or host changes.
- Weekly for cert, bundle, and repo drift.
- After any visible deployment or version bump.

## Output

- What changed.
- Why it matters.
- What to probe next.

