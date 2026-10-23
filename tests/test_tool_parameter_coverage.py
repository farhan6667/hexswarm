"""Coverage-of-the-promise test: every tool and every parameter it accepts must be
classified as host-naming, a local path, a host hidden inside a file/config, free text, or
safe/fixed. Adding a new tool or a new parameter without updating the classification here
fails the suite, which is exactly the review gap that let the url/host-named MCP arguments
and metasploit_module_run's extra_options go unexamined: nobody had to look at them, because
nothing forced the question "what kind of value does this field actually carry?" to be
answered before the code shipped.

This does not re-verify the actual fix for each classification (the dedicated tests in
test_security_hardening.py, test_scope_guard.py and test_tool_safety_fixes.py do that); it
verifies that every parameter has been LOOKED AT and classified at all.
"""
# Import every tool module so ToolRegistry.all() is fully populated regardless of import order.
import hexswarm.tools.ai_security
import hexswarm.tools.ctf
import hexswarm.tools.exploit
import hexswarm.tools.privesc
import hexswarm.tools.recon
import hexswarm.tools.scan  # noqa: F401
from hexswarm.mcp.client import DEFAULT_HOST_FIELDS
from hexswarm.tools.base import Tool, ToolRegistry

HOST = "host"                 # a network host/IP/CIDR/URL; must be scope-checked
HOST_IN_FILE = "host_in_file"  # a path to a file/config whose CONTENTS name real hosts
PATH = "path"                 # a local file path; must go through confine_path()
SSH_USER = "ssh_user"         # a username used in a destination string; dash-rejected
FREE_TEXT = "free_text"       # arbitrary text with no host/path meaning
SAFE = "safe"                 # an enum-like/int/bounded value with no injection surface

CLASSIFICATION: dict[str, dict[str, str]] = {
    "whois_lookup": {"target": HOST},
    "dns_enum": {"target": HOST},
    "port_scan": {"target": HOST, "ports": SAFE},
    "http_fingerprint": {"target": HOST},
    "http_probe": {"target": HOST},
    "fast_port_scan": {"target": HOST},
    "web_crawl": {"target": HOST},
    "dns_resolve": {"target": HOST},
    "subdomain_enum": {"target": HOST},
    "osint_harvest": {"target": HOST, "sources": SAFE},
    "subdomain_takeover": {"target": HOST_IN_FILE},
    "web_vuln_scan": {"target": HOST},
    "directory_brute": {"target": HOST, "wordlist": PATH},
    "sql_injection_scan": {"target": HOST},
    "password_brute_force": {"target": HOST, "service": SAFE, "userlist": PATH, "passlist": PATH},
    "xss_scan": {"target": HOST},
    "exploit_search": {"target": FREE_TEXT},
    "metasploit_module_run": {"target": HOST, "module": FREE_TEXT, "extra_options": FREE_TEXT},
    "linux_privesc_enum": {"target": HOST, "ssh_user": SSH_USER, "remote_script_path": FREE_TEXT},
    "windows_privesc_enum": {"target": HOST, "remote_script_path": FREE_TEXT},
    "file_identify": {"target": PATH},
    "string_extract": {"target": PATH},
    "binwalk_scan": {"target": PATH},
    "hash_identify": {"target": FREE_TEXT},
    "decode_text": {"target": FREE_TEXT},
    "prompt_injection_probe": {"target": HOST, "request_field": SAFE, "response_field": SAFE},
    "llm_scan": {"target": FREE_TEXT, "model_type": SAFE, "config": HOST_IN_FILE, "probes": SAFE, "generations": SAFE},
}

# Tools whose run() override reads host(s) out of a file/config's CONTENTS, rather than (or
# in addition to) a 'target' kwarg that is itself a host. Checked structurally below: each
# must actually override Tool.run, not just inherit the base implementation.
HOST_IN_FILE_TOOLS = {"subdomain_takeover", "llm_scan"}


def test_every_registered_tool_is_classified():
    registered = set(ToolRegistry.all())
    classified = set(CLASSIFICATION)
    missing = registered - classified
    assert not missing, (
        f"Tool(s) {sorted(missing)} registered but not classified in CLASSIFICATION. "
        "A new tool must state what kind of value every parameter carries before it ships."
    )
    stale = classified - registered
    assert not stale, f"CLASSIFICATION lists tool(s) {sorted(stale)} that are no longer registered; remove them."


def test_every_parameter_of_every_tool_is_classified():
    for name, tool in sorted(ToolRegistry.all().items()):
        props = set(tool.parameters_schema.get("properties", {}))
        classified = set(CLASSIFICATION.get(name, {}))
        missing = props - classified
        assert not missing, (
            f"'{name}' accepts parameter(s) {sorted(missing)} with no classification. "
            "Add each to CLASSIFICATION as host/host_in_file/path/ssh_user/free_text/safe."
        )
        stale = classified - props
        assert not stale, f"CLASSIFICATION lists parameter(s) {sorted(stale)} for '{name}' that it no longer accepts."


def test_every_host_classified_tool_is_scope_checked():
    # A parameter classified HOST is the field base Tool.run() authorizes; if the tool
    # opted out of that (requires_scope_check=False) its 'target' cannot really be a host,
    # contradicting the classification, so this is a tautology check catching a stale label.
    for name, fields in CLASSIFICATION.items():
        if "target" in fields and fields["target"] == HOST:
            tool = ToolRegistry.get(name)
            assert tool.requires_scope_check is True, (
                f"'{name}' classifies 'target' as {HOST} but requires_scope_check is False; "
                "either the classification or the tool's own flag is wrong."
            )


def test_every_host_in_file_tool_overrides_run():
    # A HOST_IN_FILE classification is only honest if the tool actually reads the file and
    # scope-checks its contents itself (see test_security_hardening.py for the behavior);
    # this just confirms the override exists at all, i.e. it isn't silently inheriting the
    # base Tool.run(), which would do nothing with the file's contents.
    for name in HOST_IN_FILE_TOOLS:
        tool = ToolRegistry.get(name)
        assert type(tool).run is not Tool.run, (
            f"'{name}' is classified host_in_file but does not override run(); its file/config "
            "contents are never scope-checked."
        )


def test_mcp_default_host_fields_are_the_ones_remote_tools_actually_use():
    # Guards against DEFAULT_HOST_FIELDS silently losing an entry (e.g. during a refactor)
    # without anyone noticing it no longer matches real-world MCP tool conventions.
    assert set(DEFAULT_HOST_FIELDS) >= {"target", "url", "host", "hostname"}
