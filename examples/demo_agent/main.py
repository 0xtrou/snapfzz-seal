#!/usr/bin/env python3
"""Demo agent for Agent Seal pipeline demonstration."""

import os
import sys
import json
import urllib.request

PROXY_URL = os.environ.get("AGENT_SEAL_PROXY_URL", "http://localhost:8080")


def call_llm(prompt: str) -> str:
    req = urllib.request.Request(
        f"{PROXY_URL}/v1/chat/completions",
        data=json.dumps(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100,
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('AGENT_SEAL_API_KEY', '')}",
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
