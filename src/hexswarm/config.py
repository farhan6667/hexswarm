"""Runtime configuration: model selection and provider credentials.

HexSwarm never hardcodes a provider SDK. Model strings follow LiteLLM's
"provider/model" convention, so switching from a cloud model to a local
Ollama model is a one-line config change, not a code change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    primary_model: str = field(
        default_factory=lambda: os.getenv("HEXSWARM_PRIMARY_MODEL", "ollama/llama3.1")
    )
    fallback_models: list[str] = field(
        default_factory=lambda: [
            m.strip()
            for m in os.getenv("HEXSWARM_FALLBACK_MODELS", "").split(",")
            if m.strip()
        ]
    )
    human_in_the_loop: bool = field(
        default_factory=lambda: os.getenv("HEXSWARM_HITL", "false").lower() == "true"
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("HEXSWARM_TEMPERATURE", "0.2"))
    )
    max_steps_per_phase: int = field(
        default_factory=lambda: int(os.getenv("HEXSWARM_MAX_STEPS", "6"))
    )
    sandbox_mode: str = field(
        default_factory=lambda: os.getenv("HEXSWARM_SANDBOX", "host")
    )
    sandbox_image: str = field(
        default_factory=lambda: os.getenv(
            "HEXSWARM_SANDBOX_IMAGE", "ghcr.io/farhan6667/hexswarm-toolchain:latest"
        )
    )
    sandbox_network: str = field(
        default_factory=lambda: os.getenv("HEXSWARM_SANDBOX_NETWORK", "none")
    )


def load_settings() -> Settings:
    return Settings()
