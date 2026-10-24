"""
Gemini integration. Design rule: Gemini only *explains* — every risk score and
verdict comes from the local heuristics in security.analyzers. If no API key is
configured or the call fails, we fall back to a template explanation so the app
keeps working (useful on free tiers and in tests).
"""
from __future__ import annotations

import json
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

EXPLAIN_SYSTEM = (
    "You are CyberGuard AI, a friendly cybersecurity teacher for students and everyday users. "
    "You receive the output of a local security scanner. The scanner's risk level is final: never "
    "change, dispute or re-score it. Explain in plain language what the findings mean, why each one "
    "matters, and give 3-5 concrete next steps. Use short Markdown sections with headings "
    "'What we found', 'Why it matters' and 'What to do'. Keep it under 250 words. "
    "Never ask for or repeat passwords, codes or personal data."
)

CHAT_SYSTEM = (
    "You are CyberGuard AI, a cybersecurity tutor inside an educational app. Teach defensive security: "
    "how attacks work conceptually, how to recognise and prevent them, safe habits, privacy, secure "
    "coding, incident response and career/learning guidance. Be accurate, concise and practical; use "
    "Markdown with short paragraphs, lists and code blocks when useful. If the user writes in Urdu, "
    "Roman Urdu or Hinglish, reply in the same style. "
    "Do not provide working malware, exploit code, credential-stealing pages, instructions for "
    "attacking systems the user does not own or have written permission to test, or ways to evade "
    "law enforcement — explain the concept and the defence instead. Never ask users to share "
    "passwords, OTPs or other secrets; if they paste one, tell them to change it."
)


class AIUnavailable(Exception):
    pass


def _client():
    if not settings.GEMINI_API_KEY:
        raise AIUnavailable("GEMINI_API_KEY is not configured.")
    from google import genai
    from google.genai import types

    return genai.Client(
        api_key=settings.GEMINI_API_KEY,
        http_options=types.HttpOptions(timeout=settings.GEMINI_TIMEOUT_SECONDS * 1000),
    )


def _generate(system: str, contents) -> str:
    from google.genai import types

    try:
        response = _client().models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system,
                temperature=0.4,
                max_output_tokens=2048,
            ),
        )
        text = (response.text or "").strip()
    except AIUnavailable:
        raise
    except Exception as exc:  # network errors, quota, safety blocks, bad model name...
        logger.warning("Gemini request failed: %s", exc)
        raise AIUnavailable(str(exc)) from exc
    if not text:
        raise AIUnavailable("Empty response from Gemini.")
    return text


# --- Scan explanations -------------------------------------------------------------------

def safe_payload(kind: str, result: dict) -> dict:
    """Strip anything sensitive before it is sent to the model."""
    keep = {
        "password": ["length", "character_classes", "entropy_bits", "strength_score", "strength_label", "crack_times", "findings"],
        "url": ["normalized_url", "registered_domain", "risk_score", "risk_level", "verdict", "findings"],
        "phishing": ["risk_score", "risk_level", "verdict", "findings", "links", "sender_domain"],
    }[kind]
    payload = {k: result.get(k) for k in keep if k in result}
    if "crack_times" in payload:
        payload["crack_times"] = {k: v["display"] for k, v in payload["crack_times"].items()}
    if "findings" in payload:
        payload["findings"] = [{k: f[k] for k in ("title", "detail", "severity")} for f in payload["findings"]]
    return payload


def explain_scan(kind: str, result: dict) -> tuple[str, str]:
    """Returns (markdown_explanation, source) where source is 'gemini' or 'fallback'."""
    labels = {"password": "password strength check", "url": "URL safety scan", "phishing": "phishing message analysis"}
    prompt = (
        f"Explain this {labels[kind]} result to the user.\n\n"
        f"```json\n{json.dumps(safe_payload(kind, result), indent=2, ensure_ascii=False)}\n```"
    )
    try:
        return _generate(EXPLAIN_SYSTEM, prompt), "gemini"
    except AIUnavailable:
        return fallback_explanation(kind, result), "fallback"


def fallback_explanation(kind: str, result: dict) -> str:
    findings = [f for f in result.get("findings", []) if f.get("severity") != "info"]
    if kind == "password":
        headline = (f"This password is **{result.get('strength_label', 'unknown')}** "
                    f"({result.get('strength_score', 0)}/100).")
    else:
        headline = f"Risk level: **{result.get('risk_level', 'unknown')}** ({result.get('risk_score', 0)}/100). {result.get('verdict', '')}"

    lines = ["### What we found", headline, ""]
    if findings:
        lines += [f"- **{f['title']}** — {f['detail']}" for f in findings[:6]]
    else:
        lines.append("- No significant warning signs were detected.")
    lines += ["", "### What to do"]
    if kind == "password":
        lines += [f"- {tip}" for tip in result.get("suggestions", [])[:4]]
    elif kind == "url":
        lines += [
            "- Type the website address yourself or use a saved bookmark instead of clicking.",
            "- Check the real domain (the part just before the first single `/`).",
            "- Never enter passwords or OTPs on a page you reached from an unexpected link.",
        ]
    else:
        lines += [
            "- Don’t click links or open attachments in the message.",
            "- Contact the organisation using a phone number or website you already trust.",
            "- Never share passwords, PINs or OTP codes — real services never ask for them.",
            "- Report it (e.g. mark as phishing in your email app) and delete it.",
        ]
    lines += ["", "_AI explanations are unavailable right now, so this summary was generated from the scanner’s findings._"]
    return "\n".join(lines)


# --- Chat ------------------------------------------------------------------------------------

def chat_reply(history: list[dict], message: str) -> tuple[str, str]:
    """history: [{'role': 'user'|'assistant', 'content': str}, ...] oldest first."""
    from google.genai import types

    contents = [
        types.Content(role="model" if m["role"] == "assistant" else "user", parts=[types.Part(text=m["content"])])
        for m in history
    ]
    contents.append(types.Content(role="user", parts=[types.Part(text=message)]))
    try:
        return _generate(CHAT_SYSTEM, contents), "gemini"
    except AIUnavailable:
        return (
            "The AI tutor isn’t available right now (the server has no working Gemini API key or the "
            "request failed). The Password Analyzer, URL Scanner and Phishing Detector still work — "
            "they run entirely on local rules. Please try the chat again later."
        ), "fallback"
