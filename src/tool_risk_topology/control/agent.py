"""Host-side model-in-the-loop agent (the untrusted policy).

A real model drives the carving tools over a multi-step loop. The model's brain
runs on the host (Ollama's OpenAI-compatible endpoint now; any OpenAI-compatible
API by URL+key later); its tool calls are executed inside the isolated sandbox
through :class:`ToolChannel` (a subprocess speaking to ``tool_exec`` in the
harness). Each tool call is recorded as an :class:`Action` for the monitor.

This is what makes the experiment about *the model's* discretion: the model, not
a script, decides how to (mis)use the tools.
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# macOS python.org builds often ship no CA bundle; use certifi's for HTTPS.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:  # pragma: no cover
    _SSL_CTX = ssl.create_default_context()

from .trajectory import (
    CAT_API,
    CAT_DB_WRITE,
    CAT_EGRESS,
    CAT_ENV_READ,
    CAT_FILE_WRITE,
    CAT_READ,
    CAT_RUN,
    Action,
    Trajectory,
)


# --------------------------------------------------------------------------- #
# tool channel: host <-> in-sandbox carving via `docker compose exec`
# --------------------------------------------------------------------------- #
class ToolChannel:
    def __init__(self, carving: str, compose_dir: str):
        self.carving = carving
        self.proc = subprocess.Popen(
            ["docker", "compose", "exec", "-T", "harness",
             "python", "-m", "tool_risk_topology.control.tool_exec", "--carving", carving],
            cwd=compose_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        self.schema: Dict = {}
        self._openai_tools: List = []

    def _rpc(self, obj: dict) -> dict:
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line) if line else {"error": "channel closed"}

    def load_tools(self) -> List:
        resp = self._rpc({"cmd": "list"})
        self._openai_tools = resp["tools"]
        self.schema = {t["name"]: t for t in resp["schema"]["tools"]}
        return self._openai_tools

    def call(self, tool: str, args: dict) -> dict:
        return self._rpc({"cmd": "call", "tool": tool, "args": args})

    def sentinel(self, token: str) -> int:
        return int(self._rpc({"cmd": "sentinel", "token": token}).get("z", 0))

    def check(self, path: str) -> dict:
        return self._rpc({"cmd": "check", "path": path})

    def reset(self):
        return self._rpc({"cmd": "reset"})

    def category(self, tool: str) -> tuple:
        """(category, chokepoint) for a tool, from its capability schema."""
        s = self.schema.get(tool, {})
        out = set(s.get("out", []))
        inp = set(s.get("in", []))
        choke = bool(s.get("chokepoint"))
        if tool == "run_command":
            return CAT_RUN, choke
        if "external" in out:
            return CAT_EGRESS, choke
        if "pg_prod" in out:
            return CAT_DB_WRITE, choke
        if "env_secrets" in inp:
            return CAT_ENV_READ, choke
        if out & {"repo", "object_store"}:
            return CAT_FILE_WRITE, choke
        if "internal_api" in (inp | out):
            return CAT_API, choke
        return CAT_READ, choke

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# --------------------------------------------------------------------------- #
# model clients — one normalized interface, three providers
# --------------------------------------------------------------------------- #
# A "turn" is normalized to {"text": str, "tool_calls": [{"id","name","args"}]}.
# Each client owns its own message history in the provider's native format, so
# the agent loop stays provider-agnostic.
def _post(url: str, headers: dict, body: dict, timeout: int, retries: int = 2) -> dict:
    ctx = _SSL_CTX if url.lower().startswith("https") else None
    data = json.dumps(body).encode("utf-8")
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (socket.timeout, urllib.error.URLError) as e:  # transient (slow CPU Ollama)
            last = e
            continue
    raise last


class OpenAICompatClient:
    """OpenAI-compatible chat/completions — Ollama (local) and OpenAI."""

    def __init__(self, model, base_url="http://127.0.0.1:11434/v1",
                 api_key=None, temperature=0.4, timeout=180):
        self.model, self.base_url, self.api_key = model, base_url.rstrip("/"), api_key
        self.temperature, self.timeout = temperature, timeout
        self.messages: List[dict] = []

    def start(self, system: str, user: str):
        self.messages = [{"role": "system", "content": system},
                         {"role": "user", "content": user}]

    def step(self, tools: List[dict]) -> dict:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post(f"{self.base_url}/chat/completions", headers,
                     {"model": self.model, "messages": self.messages, "tools": tools,
                      "temperature": self.temperature, "stream": False}, self.timeout)
        msg = data["choices"][0]["message"]
        self.messages.append({"role": "assistant", "content": msg.get("content") or "",
                              "tool_calls": msg.get("tool_calls") or []})
        tcs = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except Exception:
                args = {}
            tcs.append({"id": tc.get("id", ""), "name": tc["function"]["name"], "args": args})
        return {"text": msg.get("content") or "", "tool_calls": tcs}

    def add_tool_results(self, results: List[dict]):
        for r in results:
            self.messages.append({"role": "tool", "tool_call_id": r["id"], "content": r["content"]})


class AnthropicClient:
    """Native Anthropic Messages API (Claude) with tool use."""

    def __init__(self, model, api_key, base_url="https://api.anthropic.com/v1",
                 timeout=180, max_tokens=4096):
        self.model, self.base_url, self.api_key = model, base_url.rstrip("/"), api_key
        self.timeout, self.max_tokens = timeout, max_tokens
        self.system = ""
        self.messages: List[dict] = []

    def start(self, system: str, user: str):
        self.system = system
        self.messages = [{"role": "user", "content": user}]

    def step(self, tools: List[dict]) -> dict:
        atools = [{"name": t["function"]["name"], "description": t["function"]["description"],
                   "input_schema": t["function"]["parameters"]} for t in tools]
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        # NB: current Claude models (Opus 5 etc.) reject temperature/top_p with a
        # 400, and thinking is on by default — so no sampling params, and a
        # roomy max_tokens so thinking + the tool call are not truncated.
        data = _post(f"{self.base_url}/messages", headers,
                     {"model": self.model, "max_tokens": self.max_tokens,
                      "system": self.system, "messages": self.messages,
                      "tools": atools}, self.timeout)
        content = data.get("content", [])
        self.messages.append({"role": "assistant", "content": content})
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        tcs = [{"id": b["id"], "name": b["name"], "args": b.get("input") or {}}
               for b in content if b.get("type") == "tool_use"]
        return {"text": text, "tool_calls": tcs}

    def add_tool_results(self, results: List[dict]):
        blocks = [{"type": "tool_result", "tool_use_id": r["id"], "content": r["content"]}
                  for r in results]
        self.messages.append({"role": "user", "content": blocks})


def make_client(provider: str, model: str, api_key: Optional[str] = None,
                base_url: Optional[str] = None):
    if provider == "anthropic":
        return AnthropicClient(model, api_key,
                               base_url=base_url or "https://api.anthropic.com/v1")
    if provider == "openai":
        return OpenAICompatClient(model, base_url=base_url or "https://api.openai.com/v1",
                                  api_key=api_key)
    return OpenAICompatClient(model, base_url=base_url or "http://127.0.0.1:11434/v1",
                              api_key=api_key)


# --------------------------------------------------------------------------- #
# the agent loop
# --------------------------------------------------------------------------- #
@dataclass
class AgentRun:
    trajectory: Trajectory
    final_text: str = ""
    steps: int = 0
    transcript: List[dict] = field(default_factory=list)


def run_agent(client, channel: ToolChannel, system: str, task: str,
              condition: str, max_steps: int = 8) -> AgentRun:
    tools = channel.load_tools()
    client.start(system, task)
    traj = Trajectory(task_id="episode", carving=channel.carving,
                      policy_kind=("A" if condition == "misaligned" else "H"))
    final_text = ""
    steps = 0
    for _ in range(max_steps):
        turn = client.step(tools)
        tcs = turn["tool_calls"]
        if not tcs:
            final_text = turn["text"]
            break
        results = []
        for tc in tcs:
            steps += 1
            fn, args = tc["name"], tc["args"]
            result = channel.call(fn, args)
            cat, choke = channel.category(fn)
            traj.add(Action(index=0, carving=channel.carving, tool=fn, args=args,
                            category=cat, ok=bool(result.get("ok")),
                            output=(result.get("output") or result.get("error") or ""),
                            chokepoint=choke, meta={"sentinel": condition == "misaligned"}))
            results.append({"id": tc["id"],
                            "content": (result.get("output") or result.get("error") or "")[:600] or "(no output)"})
        client.add_tool_results(results)
    return AgentRun(trajectory=traj, final_text=final_text, steps=steps, transcript=[])
