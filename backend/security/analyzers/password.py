"""
Password strength analyzer (local heuristics only — the password never leaves
the server and is never stored or logged).

Approach: start from a naive entropy estimate (length x log2(charset)), then
subtract "effective entropy" for patterns attackers try first: dictionary
words, leaked passwords, keyboard walks, sequences, repeats, dates and l33t
substitutions. The remaining bits drive the crack-time estimate and score.
"""
from __future__ import annotations

import math
import re
from functools import lru_cache

from django.contrib.auth.password_validation import CommonPasswordValidator

from .common import Finding, clamp, sort_findings

KEYBOARD_ROWS = [
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "!@#$%^&*()", "qazwsxedc", "1qaz2wsx3edc",
]
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"})
COMMON_WORDS = {
    "password", "admin", "welcome", "login", "letmein", "monkey", "dragon", "master",
    "football", "cricket", "pakistan", "india", "love", "iloveyou", "princess", "sunshine",
    "shadow", "superman", "batman", "secret", "qwerty", "abc", "user", "test", "hello",
    "freedom", "whatever", "trustno1", "computer", "internet", "google", "facebook",
}

# Guess rates used for the crack-time estimates.
GUESS_RATES = {
    "online_throttled": 100 / 3600,      # 100 guesses per hour against a rate-limited login
    "online_unthrottled": 10,            # 10 guesses per second
    "offline_slow_hash": 1e4,            # bcrypt/argon2 on a GPU rig
    "offline_fast_hash": 1e10,           # unsalted MD5/SHA1 on a GPU rig
}


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    # Django ships ~20k leaked passwords; reuse that list instead of bundling our own.
    return frozenset(CommonPasswordValidator().passwords)


def _charset_size(pw: str) -> tuple[int, dict]:
    classes = {
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "digits": bool(re.search(r"\d", pw)),
        "symbols": bool(re.search(r"[^A-Za-z0-9\s]", pw)),
        "spaces": " " in pw,
        "unicode": any(ord(c) > 127 for c in pw),
    }
    size = 0
    size += 26 if classes["lowercase"] else 0
    size += 26 if classes["uppercase"] else 0
    size += 10 if classes["digits"] else 0
    size += 33 if classes["symbols"] else 0
    size += 1 if classes["spaces"] else 0
    size += 100 if classes["unicode"] else 0
    return max(size, 1), classes


def _longest_run(pw: str, predicate) -> int:
    best = run = 1 if pw else 0
    for a, b in zip(pw, pw[1:]):
        run = run + 1 if predicate(a, b) else 1
        best = max(best, run)
    return best


def _keyboard_walk_length(pw: str) -> int:
    low = pw.lower()
    best = 0
    for row in KEYBOARD_ROWS:
        for seq in (row, row[::-1]):
            for size in range(len(seq), 3, -1):
                for i in range(len(seq) - size + 1):
                    if seq[i:i + size] in low:
                        best = max(best, size)
                        break
                if best >= size:
                    break
    return best


WORD_BITS = 16.0  # ~ log2 of a 65k-word attacker dictionary (names, words, brands)


def _is_wordlike(run: str) -> bool:
    # Optional leading capital, then same-case letters, containing a vowel.
    return bool(len(run) >= 3 and re.fullmatch(r"[A-Z]?[a-z]+|[A-Z]+", run) and re.search(r"[aeiouyAEIOUY]", run))


def _pattern_bits(pw: str) -> float | None:
    """
    Estimate entropy the way a rule-based cracker sees the password: split into
    letter/digit/symbol runs and price word-like runs as one dictionary pick
    instead of N random letters. 'summer-river-42' ≈ 2 words + 2 separators + 2 digits.
    Returns None when the password has no word-like part (random strings are
    better measured by the plain charset estimate).
    """
    runs = re.findall(r"[A-Za-z]+|\d+|[^A-Za-z0-9]+", pw)
    if not any(r.isalpha() and _is_wordlike(r) for r in runs):
        return None
    bits = 0.0
    for run in runs:
        if run.isalpha():
            letters_bits = len(run) * math.log2(52 if re.search(r"[A-Z]", run) and re.search(r"[a-z]", run) else 26)
            bits += min(WORD_BITS + (1 if run[0].isupper() else 0), letters_bits) if _is_wordlike(run) else letters_bits
        elif run.isdigit():
            bits += 7 if re.fullmatch(r"(19[5-9]\d|20[0-4]\d)", run) else len(run) * math.log2(10)
        else:
            # Common separators/suffixes cost an attacker very little to try.
            bits += sum(2 if c in " -_.@!" else 5 for c in run)
    return bits


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [("century", 3153600000), ("year", 31536000), ("month", 2592000),
             ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "century" and value > 1000:
                return "longer than the age of the universe" if value > 1.4e8 else "thousands of centuries"
            value = int(value)
            plural = "centuries" if name == "century" and value != 1 else f"{name}{'s' if value != 1 else ''}"
            return f"{value} {plural}"
    return "instantly"


def analyze_password(password: str) -> dict:
    pw = password or ""
    findings: list[Finding] = []
    length = len(pw)
    charset, classes = _charset_size(pw)
    raw_bits = length * math.log2(charset) if length else 0.0
    penalty = 0.0

    lowered = pw.lower()
    deleet = lowered.translate(LEET_MAP)

    # --- Leaked / dictionary checks -------------------------------------------
    common = _common_passwords()
    if lowered in common or deleet in common:
        findings.append(Finding("leaked", "Appears in leaked-password lists",
                                "Attackers try known leaked passwords first, so this would fall in seconds.",
                                "critical", 60))
        penalty = raw_bits  # effectively zero entropy
    else:
        hits = sorted({w for w in COMMON_WORDS if w in deleet}, key=len, reverse=True)
        if hits:
            word = hits[0]
            leet_used = word not in lowered
            findings.append(Finding(
                "dictionary_word", f"Contains the common word “{word}”",
                "Dictionary words are tried early by cracking tools"
                + (", and l33t swaps like @→a or 0→o are tried automatically." if leet_used else "."),
                "high", 20))
            penalty += len(word) * math.log2(charset) * 0.8

    # --- Structural patterns -----------------------------------------------------
    walk = _keyboard_walk_length(pw)
    if walk >= 4:
        findings.append(Finding("keyboard_walk", "Keyboard pattern detected",
                                f"A {walk}-key keyboard run (like qwerty or 1234) is one of the first patterns guessed.",
                                "high", 15))
        penalty += walk * math.log2(charset) * 0.8

    seq = _longest_run(pw, lambda a, b: ord(b) - ord(a) in (1, -1))
    if seq >= 4 and walk < seq:
        findings.append(Finding("sequence", "Sequential characters",
                                f"{seq} characters in alphabetical/numeric order add very little strength.",
                                "medium", 10))
        penalty += seq * math.log2(charset) * 0.7

    rep = _longest_run(pw, lambda a, b: a == b)
    if rep >= 3:
        findings.append(Finding("repeat", "Repeated characters",
                                f"The same character appears {rep} times in a row.",
                                "medium", 8))
        penalty += (rep - 1) * math.log2(charset)

    if length >= 6 and len(set(pw)) <= max(2, length // 4):
        findings.append(Finding("low_variety", "Very few unique characters",
                                "Only a handful of distinct characters are used, which shrinks the search space.",
                                "medium", 10))
        penalty += raw_bits * 0.4

    if re.search(r"(19[5-9]\d|20[0-4]\d)", pw):
        findings.append(Finding("year", "Contains a year",
                                "Years (birth years, graduation years) are a classic guessable pattern.",
                                "low", 5))
        penalty += 4 * math.log2(charset) * 0.6

    shape_cap_bits = None
    shape = re.fullmatch(r"([A-Za-z]+)(\d{1,6})([^A-Za-z0-9]{0,2})", pw)
    if shape:
        word, digits, tail = shape.groups()
        findings.append(Finding("predictable_shape", "Predictable shape (Word + digits + symbol)",
                                "A word or name followed by numbers and a symbol is the most common human pattern, "
                                "and cracking rules target it directly.", "medium", 12))
        # Attackers model this shape directly: a word/name list (~2^20), then digits, then a symbol.
        digit_bits = 7 if re.fullmatch(r"(19[5-9]\d|20[0-4]\d)", digits) else len(digits) * math.log2(10)
        shape_cap_bits = min(len(word) * 4.7, 20) + digit_bits + len(tail) * 5 + (1 if word[0].isupper() else 0)

    # --- Length & variety ---------------------------------------------------------
    if length < 8:
        findings.append(Finding("too_short", "Too short",
                                f"{length} characters is below the 8-character minimum; aim for 12+.", "high", 25))
    elif length < 12:
        findings.append(Finding("short", "Could be longer",
                                "Length is the single biggest factor — 12-16+ characters is the modern target.", "low", 8))

    used = sum(classes[k] for k in ("lowercase", "uppercase", "digits", "symbols"))
    if used <= 1 and 0 < length < 16:
        findings.append(Finding("one_class", "Only one character type",
                                "Mixing cases, digits or symbols (or using a long passphrase) raises strength.",
                                "medium", 10))

    if length >= 16 and " " in pw.strip() and len(pw.split()) >= 4:
        findings.append(Finding("passphrase", "Looks like a passphrase",
                                "Multi-word passphrases are long and memorable — a good approach.", "info", 0))

    bits = max(0.0, raw_bits - penalty)
    if shape_cap_bits is not None:
        bits = min(bits, shape_cap_bits)
    pattern_bits = _pattern_bits(pw)
    if pattern_bits is not None:
        bits = min(bits, pattern_bits)
    guesses = 2 ** bits
    crack_times = {
        name: {"seconds": guesses / 2 / rate, "display": humanize_seconds(guesses / 2 / rate)}
        for name, rate in GUESS_RATES.items()
    }

    # 90 bits -> 100. Label cut-offs line up with crack time against a fast offline attack:
    # <27 bits instant, ~40 bits minutes, ~58 bits years, 76+ bits effectively uncrackable.
    strength = clamp(bits / 90 * 100)
    if any(f.code == "leaked" for f in findings):
        strength = min(strength, 2)
    labels = [(85, "very strong"), (65, "strong"), (45, "fair"), (30, "weak"), (0, "very weak")]
    label = next(name for cutoff, name in labels if strength >= cutoff)
    risk_score = 100 - strength

    suggestions = _suggestions(findings, length, classes)
    return {
        "length": length,
        "character_classes": classes,
        "entropy_bits": round(bits, 1),
        "raw_entropy_bits": round(raw_bits, 1),
        "strength_score": strength,
        "strength_label": label,
        "risk_score": risk_score,
        "crack_times": crack_times,
        "findings": sort_findings(findings),
        "suggestions": suggestions,
    }


def _suggestions(findings: list[Finding], length: int, classes: dict) -> list[str]:
    codes = {f.code for f in findings}
    tips = []
    if "leaked" in codes:
        tips.append("Stop using this password everywhere it appears — it is publicly known.")
    if length < 12:
        tips.append("Make it at least 12–16 characters long.")
    if codes & {"dictionary_word", "keyboard_walk", "sequence", "predictable_shape"}:
        tips.append("Avoid words, keyboard runs and Word123! shapes; use random words or a generator.")
    if "year" in codes:
        tips.append("Leave out birth years, dates and other personal details.")
    if not (classes["uppercase"] and classes["digits"] and classes["symbols"]) and length < 16:
        tips.append("Mix upper/lowercase, digits and symbols — or switch to a 4–5 word passphrase.")
    tips.append("Use a password manager and a unique password for every site, plus 2FA where possible.")
    return tips
