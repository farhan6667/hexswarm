# HexSwarm, containerized.
#
# Running offensive-security tooling directly on your own machine is a bad
# default: nmap/sqlmap/hydra/metasploit all want root-ish privileges and
# network access, and a bug in a tool adapter (or a misbehaving LLM) having
# direct access to your real filesystem and network stack is a worse blast
# radius than it needs to be. This image gives HexSwarm and its toolchain a
# disposable, isolated place to run instead.
#
# Build:   docker build -t hexswarm .
# Run:     docker run --rm -it -v "$(pwd)/examples:/work" --env-file .env \
#              hexswarm run --goal "..." --target ... --scope /work/scope.example.yaml
#
# This image intentionally does NOT bundle nmap/sqlmap/hydra/metasploit/etc:
# that toolchain is large, changes often, and belongs on a maintained
# pentest base image (kalilinux/kali-rolling and similar) rather than
# reinvented here. Without them, every tool call runs in HexSwarm's own
# simulate mode, same as on a plain dev machine. Build on top of a pentest
# base image (see the commented FROM line below) to get real tool execution
# inside the container too.

FROM python:3.14-slim AS base
LABEL org.opencontainers.image.source="https://github.com/farhan6667/hexswarm"       org.opencontainers.image.description="A swarm-of-agents framework for AI-driven offensive security research, pentesting labs, and CTF solving."       org.opencontainers.image.licenses="MIT"       org.opencontainers.image.authors="Syed Farhan Ahmed (SFA), NexaForge"
# To run real tools inside the container instead of simulate mode, swap the
# line above for a pentest-toolchain base image, e.g.:
#   FROM kalilinux/kali-rolling
#   RUN apt-get update && apt-get install -y python3 python3-pip nmap nuclei \
#       gobuster sqlmap hydra exploitdb metasploit-framework whois subfinder whatweb

RUN useradd --create-home --shell /bin/bash hexswarm
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER hexswarm
WORKDIR /work

ENTRYPOINT ["hexswarm"]
CMD ["--help"]
