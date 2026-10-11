"""Test-suite setup.

Force LiteLLM to use its bundled, local model-cost map instead of fetching the
remote one. The cost-tracking tests call litellm.completion_cost(), which can
otherwise reach out to the network on first use; pinning it local keeps the
whole suite offline and deterministic, with no dependency on a reachable host.
"""
import os

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
