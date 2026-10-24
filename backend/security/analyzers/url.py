"""
URL risk scanner using offline heuristics only. It never fetches the URL, so
scanning a malicious link is safe and fast.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from .common import Finding, clamp, risk_level, sort_findings

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "loan", "kim", "men", "date", "racing", "review", "stream", "support", "rest", "cam",
    "icu", "buzz", "monster", "cyou", "sbs", "lol", "quest",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "v.gd", "t.ly",
}
BRANDS = {
    "paypal": "paypal.com", "apple": "apple.com", "microsoft": "microsoft.com",
    "office365": "office.com", "outlook": "outlook.com", "google": "google.com",
    "gmail": "google.com", "facebook": "facebook.com", "instagram": "instagram.com",
    "amazon": "amazon.com", "netflix": "netflix.com", "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com", "binance": "binance.com", "coinbase": "coinbase.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "jazzcash": "jazzcash.com.pk",
    "easypaisa": "easypaisa.com.pk", "hbl": "hbl.com", "meezan": "meezanbank.com",
}
# Official domains owned by the brands above that contain a brand name but differ
# from the "main" domain — skip impersonation checks for these.
KNOWN_LEGIT = {
    "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.in", "googleusercontent.com",
    "googleapis.com", "google.com.pk", "microsoftonline.com", "live.com", "office.com",
    "office365.com", "icloud.com", "paypal.me", "fb.com", "fbcdn.net", "netflix.net",
    "apple.com", "google.com", "microsoft.com", "facebook.com", "paypal.com",
    "gmail.com", "outlook.com", "hotmail.com", "youtube.com", "whatsapp.net",
}
LURE_WORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "secure", "update",
    "confirm", "banking", "password", "wallet", "unlock", "suspended", "billing", "invoice",
    "reset", "authenticate", "webscr", "recover", "support", "gift", "prize", "free",
}
RISKY_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".js", ".vbs",
                    ".jar", ".ps1", ".hta", ".iso", ".zip", ".rar", ".7z", ".docm", ".xlsm")
HOMOGLYPH_DIGITS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


def _registered_domain(host: str) -> str:
    """Rough eTLD+1 without a public-suffix dependency (handles .com.pk style)."""
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"com", "co", "org", "net", "gov", "edu", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_url(raw: str) -> str:
    url = (raw or "").strip()
    # Undo common "defanging" used when sharing malicious links: hxxp://, [.], (.)
    url = re.sub(r"^hxxp", "http", url, flags=re.I)
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if re.match(r"^\s*(javascript|data|vbscript|file):", url, re.I):
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def analyze_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    findings: list[Finding] = []

    scheme_match = re.match(r"^\s*(javascript|data|vbscript|file):", url, re.I)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        return _result(url, "", [Finding("dangerous_scheme", f"Dangerous scheme “{scheme}:”",
                                         "This scheme can run code or embed content directly instead of opening a website.",
                                         "critical", 80)])

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return _result(url, "", [Finding("malformed", "Malformed URL",
                                         "The URL could not be parsed, which is itself a red flag.", "high", 40)])

    if not host:
        return _result(url, "", [Finding("no_host", "No hostname",
                                         "There is no valid domain in this link.", "high", 40)])

    scheme = parts.scheme.lower()
    path_q = unquote(f"{parts.path}?{parts.query}").lower()
    full_lower = unquote(url).lower()

    # --- Scheme / transport ----------------------------------------------------------
    if scheme == "http":
        findings.append(Finding("no_https", "Not using HTTPS",
                                "Data sent to this page is unencrypted and can be intercepted.", "medium", 12))

    # --- Host checks ----------------------------------------------------------------
    is_ip = False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        is_ip = True
        findings.append(Finding("ip_host", "Uses a raw IP address",
                                "Legitimate sites use domain names; raw IPs often hide a throwaway server.",
                                "high", 30))
        if ip.is_private or ip.is_loopback:
            findings.append(Finding("private_ip", "Points to a private/local network address",
                                    "Links to internal addresses can be used to attack devices on your network.",
                                    "medium", 10))
    except ValueError:
        pass

    if re.fullmatch(r"\d+", host) or re.fullmatch(r"0x[0-9a-f]+", host):
        findings.append(Finding("encoded_ip", "Obfuscated IP address",
                                "The host is an IP written as a number/hex to disguise it.", "critical", 45))

    registered = host if is_ip else _registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if "xn--" in host:
        findings.append(Finding("punycode", "Internationalized (punycode) domain",
                                "Punycode can make look-alike domains, e.g. Cyrillic “а” posing as Latin “a”.",
                                "high", 25))
    if any(ord(c) > 127 for c in host):
        findings.append(Finding("unicode_host", "Non-ASCII characters in domain",
                                "Look-alike Unicode characters are a common impersonation trick.", "high", 25))

    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding("suspicious_tld", f"High-abuse TLD “.{tld}”",
                                "This top-level domain is cheap and disproportionately used for scams.",
                                "medium", 15))

    if registered in SHORTENERS:
        findings.append(Finding("shortener", "URL shortener",
                                "Shorteners hide the real destination; expand it before trusting it.",
                                "medium", 15))

    if not is_ip:
        subdomain_depth = host.count(".") - registered.count(".")
        if subdomain_depth >= 3:
            findings.append(Finding("many_subdomains", f"{subdomain_depth} levels of subdomains",
                                    "Deep subdomains are used to push the real domain out of view on phones.",
                                    "medium", 12))
        if host.count("-") >= 3:
            findings.append(Finding("many_hyphens", "Many hyphens in domain",
                                    "Domains like secure-login-verify-account are typical of phishing kits.",
                                    "medium", 10))
        if len(host) > 50:
            findings.append(Finding("long_host", "Very long domain",
                                    "Unusually long hostnames are common in generated phishing domains.", "low", 6))
        digits_in_label = sum(c.isdigit() for c in registered.split(".")[0])
        if digits_in_label >= 4:
            findings.append(Finding("digit_heavy", "Domain contains many digits",
                                    "Random-looking digit-heavy domains are often auto-generated.", "low", 6))

        # Brand impersonation: brand appears in host/path but the real domain is different.
        label = registered.split(".")[0]
        normalized_label = label.translate(HOMOGLYPH_DIGITS)
        for brand, official in BRANDS.items():
            if registered in KNOWN_LEGIT:
                break
            official_reg = _registered_domain(official)
            if registered == official_reg:
                continue
            if brand in host:
                findings.append(Finding("brand_in_host", f"Mentions “{brand}” but isn’t {official}",
                                        f"The real domain is {registered}; the brand name is only decoration.",
                                        "high", 30))
                break
            if len(brand) >= 5 and (normalized_label == brand or 0 < _levenshtein(label, brand) <= 1):
                findings.append(Finding("typosquat", f"Look-alike of {official}",
                                        f"“{registered}” is one character away from a well-known brand.",
                                        "critical", 40))
                break
            if brand in path_q and len(brand) >= 5:
                findings.append(Finding("brand_in_path", f"“{brand}” appears in the path",
                                        f"Brand names in the path of {registered} are a classic phishing trick.",
                                        "medium", 12))
                break

    # --- Port / credentials / path --------------------------------------------------
    if port and port not in (80, 443):
        findings.append(Finding("odd_port", f"Non-standard port {port}",
                                "Normal websites don’t need a custom port.", "medium", 10))

    if parts.username or "@" in parts.netloc:
        findings.append(Finding("at_symbol", "“@” in the address",
                                "Everything before @ is ignored, so user@evil.com actually opens evil.com.",
                                "critical", 40))

    lures = sorted({w for w in LURE_WORDS if w in full_lower})
    if lures:
        sev, weight = ("medium", 12) if len(lures) >= 2 else ("low", 6)
        findings.append(Finding("lure_words", "Account/urgency keywords",
                                "Contains: " + ", ".join(lures[:6]) + ".", sev, weight))

    if re.search(r"https?://", path_q) or re.search(r"(redirect|url|next|goto|dest|continue)=", path_q):
        findings.append(Finding("redirect", "Embedded redirect",
                                "The link carries another URL inside it, which can bounce you somewhere else.",
                                "medium", 12))

    if parts.path.lower().endswith(RISKY_EXTENSIONS):
        findings.append(Finding("risky_download", "Direct link to a risky file type",
                                "Opening this may download an executable or macro-enabled file.", "high", 30))

    if url.count("%") >= 6:
        findings.append(Finding("heavy_encoding", "Heavily percent-encoded",
                                "Lots of %XX encoding is used to hide what a URL really contains.", "low", 6))

    if len(url) > 120:
        findings.append(Finding("long_url", "Very long URL",
                                "Long links hide the important part off-screen.", "low", 5))

    return _result(url, host, findings, registered)


def _result(url: str, host: str, findings: list[Finding], registered: str = "") -> dict:
    score = clamp(sum(f.weight for f in findings))
    level = risk_level(score)
    verdicts = {
        "low": "No major red flags found — still check it’s the site you expect.",
        "medium": "Some warning signs — verify the sender and domain before entering anything.",
        "high": "Likely malicious — don’t enter credentials or download anything.",
        "critical": "Very likely malicious — do not open this link.",
    }
    return {
        "normalized_url": url,
        "host": host,
        "registered_domain": registered,
        "risk_score": score,
        "risk_level": level,
        "verdict": verdicts[level],
        "findings": sort_findings(findings),
    }
