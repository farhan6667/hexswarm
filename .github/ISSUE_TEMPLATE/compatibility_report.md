---
name: Compatibility report
about: Tell us how a real run went on a real pentest host
labels: help wanted, compatibility
---

This is the most useful kind of report. Most of HexSwarm was built and tested in simulate mode, so a real run with the real toolchain installed is what's missing. Please use an authorized lab target only, and share sanitized output: no real client names, hosts or credentials.

**Host and toolchain**
<!-- Kali / hardened Linux / WSL, which tools were actually installed (nmap, Nuclei, gobuster, sqlmap, Hydra, Metasploit, searchsploit, PEASS-ng, ...) -->

**Model used**
<!-- Which provider and model string, e.g. anthropic/claude-sonnet-5 or ollama/llama3.1 -->

**Command you ran**
<!-- hexswarm run / hexswarm ctf, with the goal and scope file (redact the real target) -->

**What you expected, and what happened**

**Sanitized findings report or log excerpt**
