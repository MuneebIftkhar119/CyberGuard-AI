"""
Phishing message detector for emails, SMS and chat messages. Pure heuristics:
social-engineering language, sender/reply-to mismatches, risky attachments,
and every link in the message run through the URL scanner.
"""
from __future__ import annotations

import re
from email.utils import parseaddr

from .common import Finding, clamp, risk_level, sort_findings
from .url import analyze_url, _registered_domain

# Each category: (code, title, explanation, severity, weight, patterns)
LANGUAGE_RULES = [
    ("urgency", "Urgency / pressure",
     "Scammers rush you so you act before thinking.", "medium", 12,
     [r"\burgent(ly)?\b", r"\bimmediately\b", r"\bwithin \d+ (hours?|minutes?|days?)\b", r"\bact now\b",
      r"\blast (chance|warning|notice)\b", r"\bexpires? (today|soon|in)\b", r"\bfinal (notice|reminder)\b",
      r"\basap\b", r"\bfori\b", r"\bjaldi\b"]),
    ("threat", "Threat of account loss or penalty",
     "Threats of suspension, legal action or fines are classic fear tactics.", "high", 15,
     [r"\b(account|card|sim|number)\b.{0,30}\b(suspend|suspended|locked|blocked|closed|deactivated|terminated|disabled)\b",
      r"\b(suspend|lock|block|close|deactivate|terminate)\w*\b.{0,30}\b(account|card|sim|number)\b",
      r"\blegal action\b", r"\bpenalt(y|ies)\b", r"\barrest\b", r"\bfir\b", r"\bband ho jayega\b",
      r"\bunauthori[sz]ed (access|activity|login|transaction)\b", r"\bunusual (sign-?in|activity)\b"]),
    ("credentials", "Asks for passwords, PINs or OTP",
     "No real bank, company or service will ask you to send a password, PIN or one-time code.", "critical", 30,
     [r"\b(enter|confirm|verify|provide|send|share|update|reply with)\b.{0,40}\b(password|passcode|pin|otp|one[- ]time (code|password)|verification code|cvv|security code|login details|credentials)\b",
      r"\b(password|pin|otp|cvv)\b.{0,25}\b(share|send|bhej|batain|bata)\w*", r"\bcode bhej\w*\b"]),
    ("verify_account", "“Verify your account” request",
     "Requests to log in via a link to “verify” or “restore” an account are the most common phishing hook.",
     "high", 15,
     [r"\b(verify|validate|confirm|restore|reactivate|unlock|update) (your )?(account|identity|details|information|billing|payment)\b",
      r"\bclick (the |this )?(link|button|here) (below )?to (verify|confirm|login|log in|sign in|restore|unlock|claim)\b"]),
    ("money", "Money, gift cards or crypto requested",
     "Requests for transfers, gift cards or crypto are almost impossible to reverse.", "high", 20,
     [r"\bgift ?cards?\b", r"\bwire (transfer|the money)\b", r"\b(bitcoin|btc|usdt|crypto(currency)?|ethereum)\b",
      r"\b(western union|moneygram)\b", r"\bsend (me |us )?(money|funds|payment)\b", r"\bprocessing fee\b",
      r"\bjazzcash\b.{0,30}\b(send|bhej)", r"\beasypaisa\b.{0,30}\b(send|bhej)", r"\badvance (fee|payment)\b"]),
    ("prize", "Prize, lottery or too-good-to-be-true offer",
     "Unexpected winnings that require you to act or pay first are scams.", "high", 18,
     [r"\byou('ve| have)? won\b", r"\bwinner\b", r"\blottery\b", r"\bjackpot\b", r"\bclaim (your )?(prize|reward|gift)\b",
      r"\bcongratulations\b", r"\bfree (iphone|gift|money|laptop)\b", r"\binaam\b", r"\bbenazir income\b.{0,40}\b(won|amount|rs)",
      r"\b(rs\.?|pkr|\$|usd)\s?\d[\d,]{3,}\b.{0,40}\b(won|prize|reward|credited)\b"]),
    ("generic_greeting", "Generic greeting",
     "Real organisations usually address you by name.", "low", 6,
     [r"^\s*(dear|hello|hi)\s+(customer|user|client|member|account holder|sir/madam|valued customer|beneficiary)\b"]),
    ("secrecy", "Asks you to keep it secret",
     "Being told not to tell anyone or to bypass normal process is a manipulation red flag.", "high", 15,
     [r"\b(keep (this|it) (confidential|secret|between us))\b", r"\bdon'?t tell anyone\b", r"\bkisi ko na bata\w*\b"]),
    ("authority_impersonation", "Claims to be an authority or executive",
     "Impersonating bosses, banks, FIA, police or tax offices is used to make requests feel mandatory.",
     "medium", 10,
     [r"\b(ceo|managing director|your manager)\b.{0,40}\b(request|need|urgent)\b", r"\b(fia|fbr|irs|hmrc|police|customs)\b",
      r"\bstate bank\b", r"\bpta\b.{0,30}\b(block|verify)"]),
]

FREE_MAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "aol.com",
             "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com"}
ORG_WORDS = {"bank", "paypal", "microsoft", "apple", "amazon", "netflix", "support", "security",
             "admin", "it department", "helpdesk", "hr", "payroll", "billing", "fedex", "dhl", "university"}
ATTACHMENT_RE = re.compile(r"\b[\w\-. ]+\.(exe|scr|bat|cmd|js|vbs|jar|ps1|hta|iso|img|zip|rar|7z|docm|xlsm|pptm|html?|apk)\b", re.I)
URL_RE = re.compile(r"""((?:https?://|hxxps?://|www\.)[^\s<>"')\]]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|xyz|top|info|io|ly|co|pk|ru|cn|tk|ml|gq|click|link|site|online|app)(?:/[^\s<>"')\]]*)?)""", re.I)
ANCHOR_RE = re.compile(r"""<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")


def _extract_links(text: str) -> list[str]:
    links = [m.group(1) for m in ANCHOR_RE.finditer(text)]
    links += [m.group(2) for m in MARKDOWN_LINK_RE.finditer(text)]
    links += [m.group(1).rstrip(".,;:!?") for m in URL_RE.finditer(re.sub(r"<[^>]+>", " ", text))]
    seen, unique = set(), []
    for link in links:
        key = link.lower()
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return unique[:15]


def _mismatched_link_text(text: str) -> list[tuple[str, str]]:
    """Anchor text that shows one domain while href points elsewhere."""
    pairs = [(m.group(2), m.group(1)) for m in ANCHOR_RE.finditer(text)]
    pairs += [(m.group(1), m.group(2)) for m in MARKDOWN_LINK_RE.finditer(text)]
    bad = []
    for shown, href in pairs:
        shown_clean = re.sub(r"<[^>]+>", "", shown).strip()
        m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", shown_clean, re.I)
        if not m:
            continue
        shown_domain = _registered_domain(m.group(0).lower())
        href_host = analyze_url(href)["registered_domain"]
        if href_host and shown_domain != href_host:
            bad.append((shown_clean, href_host))
    return bad


def analyze_message(body: str, subject: str = "", sender: str = "", reply_to: str = "") -> dict:
    body = body or ""
    text = f"{subject}\n{body}"
    lowered = text.lower()
    findings: list[Finding] = []
    matched_phrases: dict[str, list[str]] = {}

    for code, title, detail, sev, weight, patterns in LANGUAGE_RULES:
        hits = []
        for pat in patterns:
            for m in re.finditer(pat, lowered, re.I | re.M):
                hits.append(m.group(0).strip())
        if hits:
            unique = list(dict.fromkeys(hits))[:4]
            matched_phrases[code] = unique
            extra = min(len(unique) - 1, 2) * 3
            findings.append(Finding(code, title, f"{detail} Found: “{'”, “'.join(unique)}”.", sev, weight + extra))

    # --- Sender analysis ---------------------------------------------------------------
    display, addr = parseaddr(sender or "")
    sender_domain = addr.split("@")[-1].lower() if "@" in addr else ""
    if sender_domain:
        reg = _registered_domain(sender_domain)
        if reg in FREE_MAIL and any(w in display.lower() for w in ORG_WORDS):
            findings.append(Finding("free_mail_org", "Organisation using a free email account",
                                    f"“{display}” claims to be an organisation but sends from {reg}.", "high", 20))
        claimed = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", display.lower())
        if claimed and _registered_domain(claimed.group(0)) != reg:
            findings.append(Finding("display_domain_mismatch", "Display name shows a different domain",
                                    f"Name shows {claimed.group(0)} but the real address is @{sender_domain}.",
                                    "high", 20))
        sender_url = analyze_url(sender_domain)
        bad = [f for f in sender_url["findings"] if f["code"] in {"typosquat", "brand_in_host", "punycode", "suspicious_tld"}]
        if bad:
            findings.append(Finding("sender_domain_suspicious", "Sender domain looks suspicious",
                                    f"@{sender_domain}: {bad[0]['title']}.", "high", 20))
    if reply_to and sender_domain:
        _, rt_addr = parseaddr(reply_to)
        rt_domain = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""
        if rt_domain and _registered_domain(rt_domain) != _registered_domain(sender_domain):
            findings.append(Finding("reply_to_mismatch", "Replies go to a different domain",
                                    f"Sent from @{sender_domain} but replies go to @{rt_domain}.", "high", 18))

    # --- Attachments / formatting -------------------------------------------------------
    attachments = sorted({m.group(0).strip() for m in ATTACHMENT_RE.finditer(body)})
    if attachments:
        findings.append(Finding("risky_attachment", "Mentions a risky attachment",
                                "Files like " + ", ".join(attachments[:3]) + " can carry malware.", "high", 20))
    if re.search(r"\benable (macros|content|editing)\b", lowered):
        findings.append(Finding("enable_macros", "Asks you to enable macros/content",
                                "“Enable content” in Office documents is how macro malware runs.", "critical", 30))

    letters = [c for c in body if c.isalpha()]
    if len(letters) > 40 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        findings.append(Finding("shouting", "Lots of CAPITAL LETTERS",
                                "Shouting is used to create panic.", "low", 5))
    if body.count("!") >= 5:
        findings.append(Finding("exclamations", "Excessive exclamation marks",
                                "Over-excited tone is common in scams.", "low", 4))

    # --- Links ----------------------------------------------------------------------------
    links = _extract_links(body)
    link_reports = []
    for link in links:
        report = analyze_url(link)
        link_reports.append({
            "url": link,
            "host": report["host"],
            "risk_score": report["risk_score"],
            "risk_level": report["risk_level"],
            "top_findings": [f["title"] for f in report["findings"][:3]],
        })
    for shown, real in _mismatched_link_text(body)[:3]:
        findings.append(Finding("link_text_mismatch", "Link text hides the real destination",
                                f"Shows “{shown}” but actually goes to {real}.", "critical", 30))

    worst_link = max((r["risk_score"] for r in link_reports), default=0)
    if worst_link >= 45:
        findings.append(Finding("malicious_link", "Contains a high-risk link",
                                "At least one link scored high on the URL scanner (see below).", "high",
                                int(worst_link * 0.5)))
    elif worst_link >= 20:
        findings.append(Finding("suspicious_link", "Contains a suspicious link",
                                "At least one link has warning signs (see below).", "medium", int(worst_link * 0.4)))

    # Combination bonus: pressure + an action (link/credentials/money) is the core phishing recipe.
    codes = {f.code for f in findings}
    if codes & {"urgency", "threat"} and codes & {"credentials", "verify_account", "money", "malicious_link", "suspicious_link"}:
        findings.append(Finding("pressure_plus_action", "Pressure combined with a request",
                                "Fear/urgency paired with a request to click, log in or pay is the classic phishing pattern.",
                                "high", 15))

    score = clamp(sum(f.weight for f in findings))
    level = risk_level(score)
    verdicts = {
        "low": "Looks low-risk — but if it asks for anything sensitive, verify through an official channel.",
        "medium": "Some phishing signs — verify with the sender using a contact method you already trust.",
        "high": "Likely phishing — don’t click links, reply, or share any information.",
        "critical": "Almost certainly phishing — delete or report it.",
    }
    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": verdicts[level],
        "findings": sort_findings(findings),
        "links": link_reports,
        "sender_domain": sender_domain,
        "matched_phrases": matched_phrases,
    }
