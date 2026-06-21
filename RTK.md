# RTK - Rust Token Killer (Project)

RTK is installed for this project to keep shell output compact.

## Rule

Prefer `rtk` wrappers for file/system/dev inspection commands when they reduce noise.

Use RTK for:

```bash
rtk git status
rtk git diff
rtk ls
rtk read path/to/file
rtk grep pattern path
rtk pytest -q
rtk npm run build
rtk json file.json
```

Do not wrap core recon binaries or the agent runner. These need raw output and exact behavior:

```bash
agentrecon <target>
python agent/main.py --target <target>
nmap ...
masscan ...
nc ...
ffuf ...
nuclei ...
whatweb ...
httpx ...
katana ...
```

If raw command output is required but savings should be tracked:

```bash
rtk proxy <command>
```

## Meta Commands

```bash
rtk gain
rtk gain --history
rtk --version
which rtk
```

## Project Policy

- Use `rtk` for local codebase inspection, git summaries, dependency checks, tests, logs, and compact JSON.
- Do not use `rtk` inside registered recon tool builders.
- Keep report evidence based on raw recon tool output, not RTK summaries.
