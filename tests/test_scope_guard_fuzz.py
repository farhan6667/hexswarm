"""Property-based/fuzz tests for the scope guard and input-validation helpers.

Every reviewer-found bug so far (the unparsed-string glob bypass, the port/trailing-dot
false negatives, the dash-injection paths) was a specific string nobody happened to try by
hand. These tests throw a much wider range of hostile and merely-weird strings at the same
code, under two invariants that must never break: an in-scope host must always still be
admitted (no new false negative), and a value that encodes an out-of-scope host must never
be admitted just because of how it's dressed up (no new bypass). A failing input here is
meant to become its own named regression test in test_scope_guard.py or
test_security_hardening.py, not stay only as a fuzz-discovered case.
"""
import os
import string
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.safety.paths import PathConfinementError, confine_path
from hexswarm.tools.base import reject_leading_dash

IN_SCOPE_HOST = "app.lab.local"
OUT_OF_SCOPE_HOST = "evil.other.com"


def _is_independently_in_scope(host: str) -> bool:
    """Re-implements what 'in scope' means for guard()'s allow list, independently of
    ScopeGuard's own matching code, so asserting against it is a real check and not a
    tautology (calling back into the same function being tested would always pass)."""
    import ipaddress as _ip

    if host.lower().endswith(".lab.local"):
        return True
    try:
        if _ip.ip_address(host) in _ip.ip_network("10.10.10.0/24"):
            return True
    except ValueError:
        pass
    labels = host.lower().split(".")
    return len(labels) == 4 and labels[0] == "10" and labels[1] == "10" and labels[2] == "11"


def guard():
    # Includes a trailing-octet-wildcard entry (10.10.11.*), not just a CIDR: a prior version
    # of this fuzzer used only '*.lab.local' and '10.10.10.0/24', so it could never generate
    # the one shape (10.10.11.evil.com against 10.10.11.*) that broke the real bypass an
    # independent adversarial review later found. See test_security_hardening.py.
    return ScopeGuard(
        engagement_name="t",
        allow=["*.lab.local", "10.10.10.0/24", "10.10.11.*"],
        max_risk_level=ToolRiskLevel.POST_EXPLOIT,
    )


# Printable ASCII plus a slice of Unicode (IDNA-relevant script, RTL override, lookalike
# slashes/dots, zero-width space, non-breaking space), deliberately including URL/authority
# metacharacters so the fuzzer can try to construct a bypass out of them rather than only
# clean hostnames. Written as escapes, not literal characters, so the source file itself
# stays plain ASCII.
_HOSTILE_CODEPOINTS = [0x0430, 0x202E, 0x2044, 0xFF0F, 0x3002, 0x200B, 0x00A0]
_HOSTILE_CHARS = st.sampled_from(
    list(string.ascii_letters + string.digits + "./:@?#%-_~[]")
    + [chr(cp) for cp in _HOSTILE_CODEPOINTS]
)
_HOSTILE_FRAGMENT = st.text(alphabet=_HOSTILE_CHARS, min_size=0, max_size=24)


@given(prefix=_HOSTILE_FRAGMENT, suffix=_HOSTILE_FRAGMENT)
@settings(max_examples=300)
def test_fuzz_cannot_make_an_out_of_scope_host_pass_by_decorating_it(prefix, suffix):
    """No combination of hostile decoration around the OUT-of-scope host's name should let
    it pass, whether or not it also happens to contain the in-scope suffix somewhere."""
    g = guard()
    candidate = f"{prefix}{OUT_OF_SCOPE_HOST}{suffix}"
    try:
        g.check_target(candidate)
    except ScopeViolation:
        return  # rejected, as required
    # It was accepted. That's only legitimate if the host actually extracted from this
    # string is genuinely in scope (e.g. the fragments happened to build a different,
    # in-scope URL around some literal text that merely contains "evil.other.com", such as
    # inside a query string on an in-scope host). Confirm that's really what happened.
    host = ScopeGuard._extract_host(candidate)
    assert host is not None and _is_independently_in_scope(host), (
        f"{candidate!r} was accepted as in scope, but its extracted host was {host!r}"
    )


@given(suffix=_HOSTILE_FRAGMENT)
@settings(max_examples=200)
def test_fuzz_in_scope_host_with_trailing_junk_is_never_silently_admitted_as_a_different_host(suffix):
    """Appending junk after the in-scope host must not flip the result to 'allowed' unless
    the extracted host is still genuinely the in-scope one (guards the inverse direction:
    a value that LOOKS like it starts in-scope but actually names something else)."""
    g = guard()
    candidate = f"{IN_SCOPE_HOST}{suffix}"
    try:
        g.check_target(candidate)
    except ScopeViolation:
        return
    host = ScopeGuard._extract_host(candidate)
    assert host is not None and host.endswith(".lab.local")


@given(value=st.text(min_size=1, max_size=40))
@settings(max_examples=300)
def test_fuzz_reject_leading_dash_never_lets_a_dash_leading_value_through(value):
    if value.strip().startswith("-"):
        try:
            reject_leading_dash(value, "target")
            raise AssertionError(f"{value!r} starts with '-' but was not rejected")
        except ValueError:
            pass
    else:
        reject_leading_dash(value, "target")  # must not raise


@given(host=st.sampled_from(["App.Lab.Local", "APP.LAB.LOCAL", "app.lab.local."]))
def test_case_and_trailing_dot_variants_of_an_in_scope_host_are_admitted(host):
    guard().check_target(host)  # should not raise


_PATH_ESCAPE_FRAGMENT = st.text(
    alphabet=st.sampled_from(list(string.ascii_letters + string.digits + "./\\:~_-")),
    min_size=0, max_size=30,
)


@given(prefix=_PATH_ESCAPE_FRAGMENT, depth=st.integers(min_value=0, max_value=6))
@settings(max_examples=200)
def test_fuzz_confine_path_never_admits_a_path_that_resolves_outside_the_working_dir(prefix, depth):
    with tempfile.TemporaryDirectory() as work_dir:
        old = os.environ.get("HEXSWARM_WORK_DIR")
        os.environ["HEXSWARM_WORK_DIR"] = work_dir
        try:
            candidate = "../" * depth + prefix
            try:
                resolved = confine_path(candidate, "target")
            except (PathConfinementError, OSError, ValueError):
                return  # rejected, as required for anything that escapes
            # Accepted: it must genuinely resolve inside the working directory.
            resolved.relative_to(Path(work_dir).resolve())
        finally:
            if old is None:
                os.environ.pop("HEXSWARM_WORK_DIR", None)
            else:
                os.environ["HEXSWARM_WORK_DIR"] = old
