## What this changes and why

<!-- One or two sentences. What problem does this solve, or what does it add? -->

## Checklist

- [ ] `ruff check src tests` is clean
- [ ] `pytest -q` passes
- [ ] New/changed behavior has a test (not just a manual check)
- [ ] If this adds a tool: it sets an honest `risk_level`, and `requires_scope_check = False`
      only if its `target` genuinely isn't a network address
- [ ] If this touches scope matching, tool execution, or privilege escalation: I re-read
      [SECURITY.md](../SECURITY.md) and this doesn't weaken the scope guard

## Anything reviewers should look at closely

<!-- Optional: a tricky part of the diff, a design tradeoff, something you're unsure about -->
