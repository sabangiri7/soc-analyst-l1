"""
Provider-agnostic LLM layer.

The rest of the codebase talks to a single interface (`LLMProvider.chat`) and
never sees provider-specific wire formats. Adding a new provider (or swapping
the default) touches nothing outside this package.

Normalized (provider-agnostic) message format - what callers pass in and what
the agent loop builds:

- User message:      {"role": "user", "content": "<text>"}
- Assistant message: {"role": "assistant", "content": "<text>",
                      "tool_calls": [{"id", "name", "input"}, ...]}   # optional
- Tool result:       {"role": "tool", "tool_call_id": "<id>", "content": "<json str>"}

Tool definitions are kept in one canonical shape across providers:
    {"name": str, "description": str, "input_schema": {...json schema...}}
Each provider translates that canonical shape (and the messages above) into
its own wire format and back.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    """What a provider returns for one model call."""

    content: str = ""  # free text; empty when the model only made tool calls
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.content


class LLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    def chat(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> LLMResponse:
        """Send a chat completion with optional tool calling.

        `tools` uses the canonical shape above. `messages` uses the normalized
        format described in this module's docstring.
        """

    def chat_text(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ) -> str:
        """Chat completion without tools - returns just the text.

        Convenience for free-text calls (lesson distillation etc.). Raises if
        the model tries to call a tool anyway.
        """
        resp = self.chat(system=system, messages=messages, tools=[], max_tokens=max_tokens)
        if resp.tool_calls:
            raise RuntimeError(
                f"{self.name} provider returned a tool call in a no-tools call: "
                f"{[tc.name for tc in resp.tool_calls]}"
            )
        return resp.content