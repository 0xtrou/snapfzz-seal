#!/usr/bin/env python3
"""
AgentScope Chat Agent - A conversational agent using BYOK LLM API.
"""

import os
import sys
import json
import subprocess

API_KEY = os.environ.get("SNAPFZZ_SEAL_API_KEY", "")
API_BASE = os.environ.get("SNAPFZZ_SEAL_API_BASE", "https://llm.solo.engineer/v1")
MODEL = os.environ.get("SNAPFZZ_SEAL_MODEL", "bcp/qwen3.6-plus")
SYSTEM_PROMPT = os.environ.get("AGENT_SYSTEM_PROMPT", "You are a helpful AI assistant.")
MAX_TOKENS = int(os.environ.get("AGENT_MAX_TOKENS", "2048"))
TEMPERATURE = float(os.environ.get("AGENT_TEMPERATURE", "0.7"))


def call_llm(messages):
    if not API_KEY:
        return "ERROR: SNAPFZZ_SEAL_API_KEY not set"
    
    payload = {
        "model": MODEL,
        "messages": messages,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "stream": True,
    }
    
    cmd = [
        "curl", "-s", "-X", "POST",
        f"{API_BASE}/chat/completions",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {API_KEY}",
        "-d", json.dumps(payload),
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout
        
        content_parts = []
        for line in output.split("\n"):
            if line.startswith("data: ") and line != "data: [DONE]":
                try:
                    chunk = json.loads(line[6:])
                    if "choices" in chunk and len(chunk["choices"]) > 0:
                        delta = chunk["choices"][0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            content_parts.append(content)
                except json.JSONDecodeError:
                    continue
        
        return "".join(content_parts) if content_parts else "No response"
    
    except subprocess.TimeoutExpired:
        return "Error: Request timed out"
    except Exception as e:
        return f"Error: {e}"


def main():
    prompt = os.environ.get("AGENT_PROMPT", "Hello! Introduce yourself in 1 sentence.")
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    
    response = call_llm(messages)
    
    result = {"prompt": prompt, "response": response, "model": MODEL}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
