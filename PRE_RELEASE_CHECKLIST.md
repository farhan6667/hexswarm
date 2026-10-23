# Pre-release checklist

Copy this into the release PR/commit description and tick every line honestly before
tagging. "Not applicable, because ___" is a valid answer; a blank line is not. See
`docs/process-notes/2026-10-security-reviews-root-cause.md` for why this exists.

## Every release

- [ ] **Threat model line.** One sentence: what is this release trying to protect against,
      or what does it knowingly not protect against (point to the "Known limits" section of
      SECURITY.md if nothing new).
- [ ] **Tests pass locally** (`pytest -q`), **and on the branch's own CI run**, not just
      "pushed and will check later." Find the run and paste its URL.
- [ ] **Full Python matrix green on the branch, before merging to main.** `ci.yml` runs on
      every push now; confirm the branch's own CI run covered 3.10 through 3.14 and was
      green, not just the version you happened to test locally. This is what the
      `constraints.txt` mistake in 1.1.0 would have caught before it reached `main`.
- [ ] **ruff / mypy / bandit clean.**
- [ ] **New hostile tests for anything security-relevant that changed.** Name them here. If
      a finding has no test, say which one and why (e.g. "documented limit, not fixed").
- [ ] **Dependencies pinned and audited.** `pip-audit` clean; any new or changed bound in
      `pyproject.toml` has a one-line reason (a CVE, an incident, a real compatibility need,
      not just "latest").
- [ ] **Docs/README/release-notes claims checked against the code.** Anything that says
      "every X is checked/validated/tested" is still true after this change, worded no
      stronger than what's actually verified. List anything softened or removed.
- [ ] **CHANGELOG entry written before tagging**, in the same plain, dash-free style as the
      rest of the file.
- [ ] **The user's own direct yes**, in the session doing the push, before `git push`,
      `git tag`, or `gh release create`. A relayed "the user told me" from another session
      doesn't count.

## Security-relevant release only (a scope/auth/input-handling/dependency change)

- [ ] **Independent adversarial pass completed.** A separate session/agent, given only the
      diff and a threat list, tried to break it. List what it found and how each item was
      resolved or documented as a known limit. Skipping this for time pressure is a decision
      to record here, not to make silently.
- [ ] **`tests/test_tool_parameter_coverage.py` updated** if a tool or parameter was added or
      changed, and it still passes (confirms every parameter has a stated classification).
- [ ] **Fuzz tests still pass** (`tests/test_scope_guard_fuzz.py`); if a new kind of input
      handling was added, consider whether it needs its own fuzz coverage too.
