"""
FreeLLMAPI provider - one unified API key for many free LLM providers.

FreeLLMAPI (https://freellmapi.co / github.com/tashfeenahmed/freellmapi)
aggregates dozens of free LLM provider tiers behind a single OpenAI-compatible
endpoint. You paste your provider keys into its dashboard once, grab the
unified `freellmapi-...` key, and point this provider at it:

    FREELLMAPI_API_KEY=freellmapi-your-unified-key
    FREELLMAPI_BASE_URL=http://localhost:3001/v1   # self-hosted default
    FREELLMAPI_MODEL=auto                          # router picks the best model

Because the gateway speaks the OpenAI `/chat/completions` protocol, this
provider is a thin subclass of OpenAICompatProvider that reuses the exact
wire logic (tool calling included) and logs which upstream provider actually
served each call via the `X-Routed-Via` response header.
"""
from __future__ import annotations
import sys

from config import cfg
from llm.base import LLMResponse
from llm.openai_compat_provider import OpenAICompatProvider

DEFAULT_BASE_URL = "http://localhost:3001/v1"  # FreeLLMAPI self-hosted gateway
DEFAULT_MODEL = "auto"  # let the router pick; or auto:fast / auto:smart / profile / model id


class FreeLLMAPIProvider(OpenAICompatProvider):
    name = "freellmapi"

    def __init__(self):
        self._api_key = cfg.FREELLMAPI_API_KEY
        self._base_url = (cfg.FREELLMAPI_BASE_URL or DEFAULT_BASE_URL).rstrip("/")
        self.last_routed_via: str | None = None

    def _model(self) -> str:
        return cfg.FREELLMAPI_MODEL or DEFAULT_MODEL

    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        resp = self._post(self._build_payload(
            system=system, messages=messages, tools=tools, max_tokens=max_tokens,
        ))
        routed = resp.headers.get("x-routed-via")
        if routed:
            self.last_routed_via = routed
            print(f"[freellmapi] routed via: {routed}", file=sys.stderr)
        return self._parse_response(resp)