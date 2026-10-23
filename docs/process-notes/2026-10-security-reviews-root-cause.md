# Root cause: three rounds of external review found what our own QA didn't

Written 2026-10-23, after Allen Clark's three review passes found 10+ real issues in
HexSwarm (a scope-matching bypass, a Metasploit RHOSTS override, dash/option injection,
unconfined file paths, unchecked MCP/file-content host fields, redirect-following, an
unbounded `litellm` dependency), while we had been saying "every tool call is checked
against a scope file in code" and had a 197-test suite passing. This is a plain account of
why that gap existed, not an attempt to assign blame to anyone (human or model) who wrote
the original code; the gap was in the *process*, not any one person's carefulness.

## What our 197 tests actually checked

They were "does it work" tests: given a well-formed, cooperative input, does the tool build
the right command, does the scope guard accept an obviously-in-scope target and reject an
obviously-out-of-scope one. Nobody had written a test that started from the question "what
is the worst string someone could hand this field," because nothing in the test-writing
process asked that question. A test suite built entirely by asking "does the happy path
work" will reliably miss "can the unhappy path be weaponized," no matter how many of the
first kind you write.

## Why each bug class was missed

- **The scheme-free glob bypass and the Metasploit RHOSTS override** (round 1): both were in
  code that worked correctly for every input anyone had tried by hand (a bare hostname, a
  full URL, a normal `extra_options` value). The bypass needed someone to deliberately try
  to make the *matching logic* fail, which is adversarial testing, not functional testing.
- **The seven round-2 points** (dash injection, unconfined paths, unchecked MCP/file-content
  fields, redirects, the sandbox defaults, the unpinned dependency): each is a field or a
  code path that was *correctly implemented for its documented purpose* and simply never
  asked "what else could this value be used for." `subdomain_takeover`'s `target` really is
  a file path, and the code for reading it was fine; nobody had asked whether the file's
  *contents* also needed checking. That is exactly the kind of gap a parameter-by-parameter
  classification exercise (now `tests/test_tool_parameter_coverage.py`) is built to force.
- **The `litellm` pin** (its own report): a dependency bound that was reasonable the day it
  was written (`>=1.50.0`) became a liability the day a supply-chain attacker published a
  malicious release above that floor. No amount of testing *our own code* would have caught
  this; it needed a pinned ceiling and an ongoing check, not a one-time review.
- **This release's own mistake** (the `constraints.txt` that broke the 3.10-3.12 matrix):
  the direct cause was generating a lock file from a Python version CI doesn't test, but the
  process cause is the same shape as everything above: `ci.yml` only ran on pushes to `main`
  and on pull requests, so pushing straight to `main` from a local branch (common in this
  project's workflow) meant CI never saw the change before it was already on `main`. Fixed
  as part of this same pass: `ci.yml` now runs on every push to every branch.

## What changes going forward

1. **`tests/test_tool_parameter_coverage.py`**: every tool and every parameter must be
   classified (host / host-in-file / local path / username / free text / safe), and the
   suite fails if a new one isn't. This is what would have caught the unchecked `url`/`host`
   MCP arguments and `extra_options` as soon as they were added, without needing a review to
   notice.
2. **`tests/test_scope_guard_fuzz.py`**: property-based/fuzz tests on the scope matcher and
   the path-confinement helper, so "what's the worst string someone could hand this" is now
   an automated question, not one that depends on a human (internal or external) happening
   to think of the right crafted input.
3. **`ci.yml` runs on every branch**, not just `main` and PRs, so a mistake surfaces before
   a merge, not after.
4. **`PRE_RELEASE_CHECKLIST.md`**: a release doesn't go out without naming its threat model,
   confirming hostile tests exist for what changed, confirming dependencies are pinned and
   audited, and confirming the README/release notes' claims still match the code.
5. **An independent adversarial pass before a security-relevant release** (a separate
   session or agent, given only the diff and a threat list, asked to try to break it) is now
   a standing rule for HexSwarm and for any other security-flavored repo this account
   maintains, not a one-off this review triggered.

None of this claims the result is now unbreakable; it claims the *process* now asks the
adversarial question by default instead of only when someone outside the project asks it
for us.
