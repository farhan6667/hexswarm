"""Per-tool-call Docker sandboxing.

By default every tool runs as a plain subprocess on the host, same as
before. Setting `HEXSWARM_SANDBOX=docker` switches every *non-local-only*
tool call to run inside its own disposable container instead: a fresh
`docker run --rm` per call, not one long-lived container for the whole
engagement, so one tool call can't see another's state and a hung or
misbehaving command can't touch anything outside it.

This is a meaningfully different safety posture than "the whole HexSwarm
process happens to run inside a Dockerfile": that only isolates HexSwarm
itself from the host, while this isolates the actual nmap/sqlmap/hydra/etc.
subprocess from HexSwarm, from the operator's host, and from every other
tool call in the same run.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SandboxConfig:
    mode: str = "host"  # "host" | "docker"
    image: str = "ghcr.io/farhan6667/hexswarm-toolchain:latest"
    network: str = "none"  # "none" blocks all network access by default; override per need
    extra_args: list[str] | None = None

    @property
    def is_docker(self) -> bool:
        return self.mode == "docker"


_config = SandboxConfig()


def configure_sandbox(
    mode: str = "host",
    image: str | None = None,
    network: str | None = None,
    extra_args: list[str] | None = None,
) -> None:
    """Sets the process-wide sandbox mode every Tool.run() call consults.

    Called once at startup (CLI/MCP server entry points), not per call.
    """
    global _config
    _config = SandboxConfig(
        mode=mode,
        image=image or _config.image,
        network=network if network is not None else _config.network,
        extra_args=extra_args,
    )


def current_sandbox() -> SandboxConfig:
    return _config


def wrap_command(command: list[str]) -> list[str]:
    """Wraps a tool's argv in `docker run --rm ...` when sandboxing is enabled.

    Returns the command unchanged in host mode. The target command and its
    arguments are passed to Docker as a single argv list, never through a
    shell, so this introduces no new injection surface beyond what the host
    path already has.
    """
    cfg = current_sandbox()
    if not cfg.is_docker:
        return command

    docker_cmd = ["docker", "run", "--rm", "--network", cfg.network]
    if cfg.extra_args:
        docker_cmd.extend(cfg.extra_args)
    docker_cmd.append(cfg.image)
    docker_cmd.extend(command)
    return docker_cmd
