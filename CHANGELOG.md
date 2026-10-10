# Changelog

All notable changes to HexSwarm are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Standalone CTF-solving agent and `hexswarm ctf` command: file identification, string
  extraction, binwalk-style embedded-file scanning, hash identification, and a pure-Python
  multi-codec decoder (base64/base32/hex/URL/ROT13/binary), none of which touch the
  network-scope guard since they operate on local files/strings.
- `Tool.local_only` execution path for pure-Python tools that never shell out to a binary.
- `Tool.category` ("pentest" vs "ctf") so the tool registry can serve two separate agent
  tracks from one codebase.
- Finding severity is now inferred from a tool's risk tier and outcome instead of always
  being hardcoded to "info", so `FindingsStore.by_severity()` is actually meaningful.
- `--yes`/`-y` flag and a one-time pre-run authorization confirmation on `hexswarm run`.
- `Dockerfile` for running HexSwarm in an isolated container.
- `pip-audit` and `mypy` added to CI, alongside the existing ruff + pytest + bandit checks.

### Fixed
- `exploit_search`'s "target" is a product/version search string, not a network address; it
  was being forced through the host-scope check and would have rejected every real call.
  Tools now declare `requires_scope_check = False` when their target isn't a network host.
- `ScopeGuard` now extracts the hostname from URL-style targets before matching, so scope
  entries written as domains actually match the full URLs that `web_vuln_scan`,
  `directory_brute`, `sql_injection_scan`, and `http_fingerprint` pass as their target.
  Previously those four tools could never satisfy a domain-based allow rule.
- `linux_privesc_enum` downloaded and piped linpeas.sh straight from GitHub into `bash` on
  the target at runtime. It now expects an operator-staged, pre-vetted script path instead,
  and no longer scope-checks "user@host" (which could never match a plain-host allow rule).
- `windows_privesc_enum`'s `binary` ClassVar didn't match what was actually executed
  (`pwsh`, not `winpeas.exe`), so `is_available()` always reported it as missing even when
  PowerShell remoting was fully usable. Also fixed: the target value was being interpolated
  unescaped into a PowerShell `-Command` string, letting a single quote in the target break
  out and run arbitrary PowerShell locally, before any remote connection was made.
- `metasploit_module_run` now rejects a newline smuggled into `module` or `target`, which
  could otherwise inject extra, unintended lines into the generated msfconsole resource
  script.

## [0.1.0] - 2026-10-10

Initial release: scope-gated recon -> scan -> exploit -> privesc -> report pipeline,
LiteLLM-based model routing, safe-adapter tool layer with simulate mode, CLI, test suite.
