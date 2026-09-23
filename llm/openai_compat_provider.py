"""
OpenAI-compatible chat completions provider.

Works with any server that speaks the OpenAI `/chat/completions` protocol:
OpenAI, OpenRouter, Azure OpenAI, Ollama, vLLM, LM Studio, DeepSeek, Together,
Groq, ... Just point OPENAI_BASE_URL at it. Implemented with plain `requests`
so no extra SDK dependency is required.
"""
from __future__ import annotations

import json
import random
import time
from typing import Any

import requests

from config import cfg
from llm.base import LLMProvider, LLMResponse, ToolCall


def to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonical tool shape -> OpenAI 'function' tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        }
        for t in tools
    ]


def to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalized -> OpenAI chat message list."""
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "user":
            out.append({"role": "user", "content": m["content"]})
        elif role == "assistant":
            msg: dict[str, Any] = {"role": "assistant"}
            msg["content"] = m.get("content") or None
            tool_calls = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": json.dumps(tc["input"])},
                }
                for tc in m.get("tool_calls") or []
            ]
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            raise ValueError(f"unknown normalized message role: {role}")
    return out


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(self):
        self._api_key = cfg.OPENAI_API_KEY
        self._base_url = cfg.OPENAI_BASE_URL.rstrip("/")

    def _model(self) -> str:
        return cfg.OPENAI_MODEL or cfg.AGENT_MODEL

    # --- small hooks so subclasses (e.g. FreeLLMAPI) can reuse the exact
    #     wire logic while swapping endpoints/models or adding observability.
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _build_payload(self, *, system, messages, tools, max_tokens) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model(),
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}] + to_openai_messages(messages),
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        return payload

    def _post(self, payload: dict[str, Any]) -> requests.Response:
        """POST /chat/completions with retry/backoff for transient failures.

        Free gateways (FreeLLMAPI, OpenRouter free tier, ...) throw 429s and
        occasional 5xx under load; one failed call should not kill a whole
        triage batch. Retries on 429/5xx + `requests` network errors with
        exponential backoff and jitter (see LLM_MAX_RETRIES /
        LLM_RETRY_BACKOFF_BASE). The last error is re-raised when retries are
        exhausted so callers still see a clear failure.
        """
        last_exc: Exception | None = None
        for attempt in range(cfg.LLM_MAX_RETRIES + 1):
            if attempt:
                time.sleep(cfg.LLM_RETRY_BACKOFF_BASE ** attempt + random.uniform(0, 0.5))
            try:
                return self._post_once(payload)
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if status not in (429, 500, 502, 503, 504):
                    raise  # don't retry auth errors (401/403) etc.
                last_exc = e
            except requests.RequestException as e:
                last_exc = e
        if last_exc is not None:  # pragma: no cover - always set here
            raise last_exc
        raise RuntimeError("unreachable")  # pragma: no cover

    def _post_once(self, payload: dict[str, Any]) -> requests.Response:
        resp = requests.post(
            f"{self._base_url}/chat/completions",
            headers=self._headers(),
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp

    def _parse_response(self, resp: requests.Response) -> LLMResponse:
        msg = resp.json()["choices"][0]["message"]

        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                arguments = json.loads(tc["function"]["arguments"] or "{}")
            except json.JSONDecodeError:
                arguments = {}
            calls.append(ToolCall(id=tc["id"], name=tc["function"]["name"], input=arguments))
        return LLMResponse(content=msg.get("content") or "", tool_calls=calls)

    # ------------------------------------------------------------------ #
    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        return self._parse_response(
            self._post(self._build_payload(
                system=system, messages=messages, tools=tools, max_tokens=max_tokens,
            ))
        )