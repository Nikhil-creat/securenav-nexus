"""NEXUS-AI: Groq-powered tool-calling operations assistant (server side).

Uses Groq's OpenAI-compatible API (free tier key from https://console.groq.com/keys) with function calling so the
assistant can read live robot state, search the security knowledge base and ENGAGE the e-stop.
Safety rule: the assistant can only move the robot toward a safer state. Releasing the e-stop is deliberately not a
tool - it stays a human action in the dashboard. Without a key (or on API failure) a deterministic offline
responder answers instead, so the operator console never goes dark.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import httpx

log = logging.getLogger("nexus.assistant")
GROQ_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
KB_DIR = Path(os.environ.get("NEXUS_KB_DIR", "/app/knowledge"))

SYSTEM_PROMPT = (
    "You are NEXUS-AI, the operations copilot of SecureNav-NEXUS, a zero-trust autonomous robot platform. "
    "Be concise and precise. Use tools to read live state before making claims about the robot. "
    "Explain threats using MITRE ATT&CK for ICS terms and the response playbooks. "
    "You may engage the emergency stop when safety is at risk; you can never release it - tell the operator to use the dashboard."
)

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {"name": "get_robot_state", "description": "Latest telemetry snapshot: anomaly score, topic rates, CPU, e-stop state.",
                                      "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "recent_threats", "description": "Most recent security alerts raised by the IDS guardian.",
                                      "parameters": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 20}}}}},
    {"type": "function", "function": {"name": "search_kb", "description": "Search MITRE ATT&CK for ICS / NIST 800-82 / ISO 21434 summaries and response playbooks.",
                                      "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "engage_estop", "description": "Engage the emergency stop. Use only when there is a credible safety or security risk.",
                                      "parameters": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}}},
]


def search_kb_local(query: str, k: int = 3) -> list[dict[str, str]]:
    """Keyword-overlap retrieval over the markdown knowledge base (the brain service uses Qdrant for the full RAG)."""
    words = set(re.findall(r"[a-z0-9_/]+", query.lower()))
    scored: list[tuple[int, str, str]] = []
    for path in sorted(KB_DIR.glob("*.md")) if KB_DIR.exists() else []:
        for chunk in re.split(r"\n(?=##? )", path.read_text(encoding="utf-8")):
            hit = len(words & set(re.findall(r"[a-z0-9_/]+", chunk.lower())))
            if hit:
                scored.append((hit, path.name, chunk.strip()))
    scored.sort(reverse=True)
    return [{"source": s, "text": t[:700]} for _, s, t in scored[:k]]


class NexusAssistant:
    def __init__(self, api_key: Optional[str], model: str = DEFAULT_MODEL) -> None:
        self.api_key, self.model = api_key, model

    async def _complete(self, client: httpx.AsyncClient, messages: list[dict[str, Any]]) -> dict[str, Any]:
        r = await client.post(f"{GROQ_URL}/chat/completions", headers={"Authorization": f"Bearer {self.api_key}"},
                              json={"model": self.model, "messages": messages, "tools": TOOLS, "tool_choice": "auto",
                                    "temperature": 0.2, "max_tokens": 700})
        r.raise_for_status()
        return dict(r.json()["choices"][0]["message"])

    async def chat(self, user_msg: str, history: list[dict[str, str]],
                   tools: dict[str, Callable[..., Awaitable[Any]]]) -> dict[str, Any]:
        """Returns {reply, mode, tool_calls}. Falls back to offline mode on any failure."""
        if not self.api_key:
            return await self.offline(user_msg, tools)
        messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages += [m for m in history[-10:] if m.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": user_msg})
        used: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                for _ in range(4):  # bounded tool loop
                    msg = await self._complete(client, messages)
                    calls = msg.get("tool_calls") or []
                    if not calls:
                        return {"reply": msg.get("content") or "", "mode": "groq", "tool_calls": used}
                    messages.append(msg)
                    for call in calls:
                        name = call["function"]["name"]
                        try:
                            args = json.loads(call["function"].get("arguments") or "{}")
                            fn = tools.get(name)
                            result = await fn(**args) if fn else {"error": f"unknown tool {name}"}
                        except Exception as exc:  # noqa: BLE001
                            result = {"error": str(exc)}
                        used.append(name)
                        messages.append({"role": "tool", "tool_call_id": call["id"], "content": json.dumps(result)[:4000]})
                return {"reply": "I hit the tool-call limit; please narrow the request.", "mode": "groq", "tool_calls": used}
        except Exception as exc:  # noqa: BLE001
            log.warning("groq failed (%s), offline fallback", type(exc).__name__)
            out = await self.offline(user_msg, tools)
            out["note"] = "Groq unavailable - offline mode"
            return out

    async def offline(self, msg: str, tools: dict[str, Callable[..., Awaitable[Any]]]) -> dict[str, Any]:
        m = msg.lower()
        used: list[str] = []
        if any(w in m for w in ("status", "state", "health", "telemetry")):
            used.append("get_robot_state")
            s = await tools["get_robot_state"]()
            reply = f"Anomaly score {s.get('score', 'n/a')}, e-stop {'ENGAGED' if s.get('estop') else 'released'}, baseline ready: {s.get('ready')}."
        elif any(w in m for w in ("threat", "alert", "attack")):
            used.append("recent_threats")
            t = await tools["recent_threats"](limit=5)
            reply = "Recent threats: " + ("; ".join(f"[{x.get('severity')}] {', '.join(x.get('reasons', []))}" for x in t) or "none")
        elif any(w in m for w in ("stop", "halt", "emergency")):
            used.append("engage_estop")
            await tools["engage_estop"](reason="operator request via assistant")
            reply = "Emergency stop engaged. Release it from the dashboard when the area is safe."
        else:
            used.append("search_kb")
            hits = await tools["search_kb"](query=msg)
            reply = hits[0]["text"] if hits else "I have no offline answer for that; add a GROQ_API_KEY for full reasoning."
        return {"reply": reply, "mode": "offline", "tool_calls": used}


def load_key() -> Optional[str]:
    if os.environ.get("GROQ_API_KEY"):
        return os.environ["GROQ_API_KEY"].strip()
    p = os.environ.get("GROQ_API_KEY_FILE", "/run/secrets/groq_api_key")
    try:
        key = Path(p).read_text().strip()
        return key or None
    except OSError:
        return None
