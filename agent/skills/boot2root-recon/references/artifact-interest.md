# Artifact Interest

Use this taxonomy to decide what to read/download from exposed web, FTP, SMB, NFS, Redis, and similar services.

## Always High Value

- Proof-like sensitive files: `flag.txt`, `user.txt`, `root.txt`, `proof.txt` treated as sensitive artifacts, not special objectives; redact raw values in UI/report.
- Credentials/secrets: `password`, `passwd`, `cred`, `secret`, `token`, `api_key`, `id_rsa`, `authorized_keys`, `shadow`.
- Config/env: `.env`, `config.php`, `wp-config.php`, `settings.py`, `database.yml`, `application.properties`.
- Database/dumps: `.sql`, `.sqlite`, `.db`, `dump.rdb`, `appendonly.aof`.
- Backups/archives: `.bak`, `.old`, `.orig`, `.zip`, `.tar.gz`, `.7z`, `.rar`.
- VCS leaks: `.git`, `.svn`, `.hg`.
- Cloud/CI: AWS credentials, kubeconfig, Terraform state, `.gitlab-ci.yml`, Jenkins, Docker files.
- Logs/source/package files: app logs, error logs, `package.json`, `composer.json`, `requirements.txt`, source files.

## Mandatory Suspicious Text Review

Any suspicious readable text artifact must be reviewed before reporting. Do not rely only on filename. If the file can be safely read within limits, inspect content, classify it, extract indicators, redact sensitive values in UI/report, and save an analysis finding. If it cannot be read or downloaded, save a blocked-analysis finding with the reason.

Review these text-like artifacts:

- Extensions: `.txt`, `.log`, `.conf`, `.cfg`, `.ini`, `.env`, `.bak`, `.old`.
- Names: `note`, `readme`, `todo`, `hint`, `backup`, `users`, `creds`, `credentials`, `password`, `secret`, `token`, `key`, `admin`, `config`, `db`, `database`, `dump`, `private`, `internal`, `debug`.
- Paths: `/home`, `/root`, `/var/www`, `/backup`, `/config`, `/admin`, `/private`, `/tmp`, `/opt`, app directories, FTP roots, SMB shares, exposed web directories.
- Context: unknown small text files from anonymous/public service roots, writable shares, backups, or directory listings.

Extract credentials, usernames, emails, internal hosts/IPs/URLs, ports, paths, database strings, commands, deployment notes, debug traces, private keys, hashes, JWTs, bearer tokens, cloud keys, and proof-like sensitive values.

Redact raw sensitive values in dashboard/report by default:

- `PASSWORD=value` -> `PASSWORD=[REDACTED]`
- `TOKEN=value` -> `TOKEN=[REDACTED]`
- `SECRET=value` -> `SECRET=[REDACTED]`
- private key body -> `[REDACTED_PRIVATE_KEY]`
- proof-like value -> `[REDACTED_PROOF]`

Raw content remains only in the saved local artifact file.

## Documents

Download PDF/doc/docx/xls/xlsx only when the filename contains high-signal words:

- `note`
- `report`
- `secret`
- `backup`
- `user`
- `root`
- `flag`
- `proof`
- `credential`
- `password`

## Default Limits

- Max 50 files per service.
- Max 10MB per file.
- Max 100MB total per target.
- Max recursion depth 7.
- Skip common static/media files unless filename is clearly high value.

Limits control runtime and disk use. They are not safety restrictions.
