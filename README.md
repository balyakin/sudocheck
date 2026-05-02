# sudocheck

**One command. Real Linux privilege escalation paths. Exploits explained. Fixes included.**

sudocheck scans Linux systems for privilege escalation vectors in sudo rules, SUID/SGID files and Linux
capabilities, then maps findings to GTFOBins-style exploitation notes and defensive remediation.

It never runs exploit commands. It only explains what an attacker could do and what should be fixed.

## Install

```sh
curl -sSL https://raw.githubusercontent.com/balyakin/sudocheck/main/install.sh | sh
```

From source:

```sh
go install github.com/balyakin/sudocheck@latest
```

## Quick Start

```sh
sudocheck
sudocheck scan --json
sudocheck scan --format sarif --report sudocheck.sarif
sudocheck scan --severity info
sudocheck scan --defensive
sudocheck lookup tcpdump
sudocheck demo
```

Default scan output shows medium severity and higher. Use `--severity info` for the full inventory.

## Why sudocheck?

| Feature | linPEAS | suid3num | sudocheck |
|---|---:|---:|---:|
| Sudo rules | yes | no | yes |
| SUID/SGID binaries | yes | yes | yes |
| Capabilities | yes | no | yes |
| GTFOBins mapping | partial | partial | yes |
| Exploit commands | noisy | partial | focused |
| Fix commands | no | no | yes |
| JSON output | no | no | yes |
| SARIF output | no | no | yes |
| Baseline / ignore | no | no | yes |

## CI

```yaml
- name: Privilege escalation audit
  run: |
    curl -sSL https://raw.githubusercontent.com/balyakin/sudocheck/main/install.sh | sh
    sudocheck scan --quiet --fail-on high
```

For legacy hosts, create a baseline first:

```sh
sudocheck baseline init --output sudocheck.baseline.json
sudocheck scan --baseline sudocheck.baseline.json --fail-on high
```

## SARIF

```sh
sudocheck scan --format sarif --report sudocheck.sarif
```

SARIF output redacts host and user metadata by default.

## Demo

```sh
sudocheck demo
```

Demo mode uses deterministic fixture data and does not read the real system.

## Responsible Use

sudocheck is intended for systems you own or are explicitly authorized to test. See `DISCLAIMER.md`.

## License

MIT License. Copyright (c) 2026 Evgeny Balyakin.
