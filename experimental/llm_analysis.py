"""
Optional LLM-assisted incident summarization.

Not part of the detection decision path — see experimental/README.md.
This module takes an already-scored detection record and asks a local
Ollama model for a human-readable summary. It cannot change a score,
a severity label, or an active-response outcome; it runs strictly
after those decisions have been made elsewhere.

Disabled by default: returns an explanatory error string if
config.settings.OLLAMA_URL is not set, rather than silently failing
or blocking the caller.
"""

import requests

from config import settings

_PROMPT_TEMPLATE = """You are a SOC analyst assistant. Use ONLY the data given below.
Do not invent facts, tools, or context not present in the input.

Incident:
  Source IP: {ip}
  Fusion threat score: {score}
  Detected stages: {stages}

Respond in this exact structure:

[Attack Summary]
<one line>

[Attack Stage]
<Reconnaissance / Initial Access / Lateral Movement / Unknown>

[Threat Assessment]
<based only on the score and stages above>

[Suggested Analyst Actions]
- Review traffic from {ip}
- Cross-check {ip} against other detections in this run
- Escalate if severity is HIGH or CRITICAL

[Confidence]
<low / medium / high>
"""


def summarize_incident(detection: dict, timeout: int = 60) -> str:
    if not settings.OLLAMA_URL:
        return "[LLM analysis disabled: OLLAMA_URL is not configured]"

    prompt = _PROMPT_TEMPLATE.format(
        ip=detection.get("src_ip", "unknown"),
        score=detection.get("threat_score", 0),
        stages=detection.get("attack_timeline", []),
    )

    try:
        response = requests.post(
            settings.OLLAMA_URL,
            json={
                "model": settings.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json().get("response", "[No response from model]")
    except requests.RequestException as exc:
        return f"[LLM analysis failed: {exc}]"
