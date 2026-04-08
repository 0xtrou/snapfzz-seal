#!/usr/bin/env python3
"""Demo agent for Agent Seal pipeline demonstration."""

import os
import sys
import json
import urllib.request

API_KEY = os.environ.get("AGENT_SEAL_API_KEY", "")
API_BASE = os.environ.get("AGENT_SEAL_API_BASE", "https://api.openai.com")
MODEL = os.environ.get("AGENT_SEAL_MODEL", "gpt-4o-mini")


def call_llm(prompt: str) -> str:
    if not API_KEY:
        return "No API key configured. Set AGENT_SEAL_API_KEY."
    req = urllib.request.Request(
        f"{API_BASE}/v1/chat/completions",
        data=json.dumps(
            {
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100,
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {e}"


def main():
    prompt = os.environ.get(
        "AGENT_PROMPT", "Say 'Agent Seal works!' in exactly those words."
    )
    result = call_llm(prompt)
    print(result, file=sys.stderr)
    print(json.dumps({"result": result}))
    sys.exit(0)


if __name__ == "__main__":
    main()
