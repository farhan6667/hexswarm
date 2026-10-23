"""CTF-solving tools: file, string, and encoding analysis.

These are a different animal from the pentest tool tiers: there's no network
target to authorize, no host to scope-check (requires_scope_check=False on
every tool here), and most of them are read-only by nature (reading and
decoding a file you already have doesn't touch anyone else's system). They
feed the separate CTF agent (see agents/specialized.py, `hexswarm ctf`)
rather than the recon -> scan -> exploit -> privesc pipeline.

"target" here means a local file path or a raw string to analyze, not a
network address. See each tool's own description for its exact meaning.
"""
from __future__ import annotations

import base64
import binascii
import codecs
from typing import Any, ClassVar
from urllib.parse import unquote

from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.safety.paths import confine_path
from hexswarm.tools.base import Tool, ToolRegistry


class FileIdentify(Tool):
    name: ClassVar[str] = "file_identify"
    description: ClassVar[str] = (
        "Identifies the type of a local file (ELF/PE binary, archive, image, etc.) using the "
        "'file' command's magic-byte detection. Use this first on any unknown CTF artifact."
    )
    binary: ClassVar[str] = "file"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    requires_scope_check: ClassVar[bool] = False
    category: ClassVar[str] = "ctf"
    timeout_seconds: ClassVar[int] = 30
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Path to the local file to identify."},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        # 'target' here is a file path, not a network host, so the scope guard never checks
        # it (requires_scope_check=False above): confine it to the working directory instead,
        # so it can't be pointed at an arbitrary local file (e.g. ~/.aws/credentials) whose
        # contents would otherwise come straight back as this tool's own output.
        return [self.binary, "--brief", str(confine_path(kwargs["target"], "target"))]


class StringExtract(Tool):
    name: ClassVar[str] = "string_extract"
    description: ClassVar[str] = (
        "Extracts printable strings (ASCII, minimum length 4) from a local binary file. Use "
        "this to look for flags, embedded paths, hardcoded credentials, or format hints."
    )
    binary: ClassVar[str] = "strings"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    requires_scope_check: ClassVar[bool] = False
    category: ClassVar[str] = "ctf"
    timeout_seconds: ClassVar[int] = 30
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Path to the local binary file."},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-n", "4", str(confine_path(kwargs["target"], "target"))]


class BinwalkScan(Tool):
    name: ClassVar[str] = "binwalk_scan"
    description: ClassVar[str] = (
        "Scans a local file for embedded files, firmware images, and compressed/archived data "
        "using binwalk's signature scanning. Use this on images, firmware dumps, and any file "
        "that might be hiding another file inside it (classic steganography/forensics CTF move)."
    )
    binary: ClassVar[str] = "binwalk"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    requires_scope_check: ClassVar[bool] = False
    category: ClassVar[str] = "ctf"
    timeout_seconds: ClassVar[int] = 120
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Path to the local file to scan."},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, str(confine_path(kwargs["target"], "target"))]


class HashIdentify(Tool):
    name: ClassVar[str] = "hash_identify"
    description: ClassVar[str] = (
        "Identifies the likely algorithm(s) that produced a given hash string (MD5, SHA family, "
        "NTLM, bcrypt, etc.) based on its format, using hashid."
    )
    binary: ClassVar[str] = "hashid"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    requires_scope_check: ClassVar[bool] = False
    category: ClassVar[str] = "ctf"
    timeout_seconds: ClassVar[int] = 15
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "The hash string to identify, e.g. a hex digest."},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, kwargs["target"]]


class DecodeText(Tool):
    name: ClassVar[str] = "decode_text"
    description: ClassVar[str] = (
        "Tries a battery of common CTF text encodings (Base64, Base32, hex, URL-encoding, "
        "ROT13, binary-as-ASCII) against a string and returns every decoding that produced "
        "printable output, so you don't have to guess the encoding yourself. Pure Python: no "
        "external binary, always available."
    )
    binary: ClassVar[str] = ""  # unused: local_only tools never shell out
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    requires_scope_check: ClassVar[bool] = False
    category: ClassVar[str] = "ctf"
    local_only: ClassVar[bool] = True
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "The encoded string to decode."},
        },
        "required": ["target"],
    }

    @staticmethod
    def _is_mostly_printable(s: str) -> bool:
        if not s:
            return False
        printable = sum(1 for c in s if c.isprintable())
        return printable / len(s) > 0.85

    def run_local(self, **kwargs: Any) -> str:
        text = kwargs["target"]
        results: list[str] = []

        def try_add(label: str, fn) -> None:
            try:
                decoded = fn(text)
            except Exception:  # noqa: BLE001 - any codec failure just means "not this encoding"
                return
            # A "decoding" identical to the input (e.g. rot13 on a string with no letters,
            # or url-unquote on a string with no %-escapes) isn't informative; skip it.
            if decoded and decoded != text and self._is_mostly_printable(decoded):
                results.append(f"[{label}] {decoded}")

        try_add("base64", lambda t: base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", errors="strict"))
        try_add("base32", lambda t: base64.b32decode(t.upper() + "=" * (-len(t) % 8)).decode("utf-8", errors="strict"))
        try_add("hex", lambda t: binascii.unhexlify(t.strip()).decode("utf-8", errors="strict"))
        # unquote() on a string with no %-escapes is a no-op; that's not a "decoding", just noise.
        if "%" in text:
            try_add("url", unquote)
        try_add("rot13", lambda t: codecs.decode(t, "rot_13"))

        if set(text.strip()) <= {"0", "1", " "}:
            try_add(
                "binary",
                lambda t: "".join(chr(int(b, 2)) for b in t.split() if b),
            )

        if not results:
            return "No printable result from base64/base32/hex/url/rot13/binary. Not one of the common encodings, or it's multi-layered (try decode_text again on a result)."
        return "\n".join(results)


ToolRegistry.register(FileIdentify())
ToolRegistry.register(StringExtract())
ToolRegistry.register(BinwalkScan())
ToolRegistry.register(HashIdentify())
ToolRegistry.register(DecodeText())
