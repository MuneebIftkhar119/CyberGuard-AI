"""Shared helpers for every analyzer: a finding type and score -> risk mapping."""
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    code: str          # machine-readable id, e.g. "ip_host"
    title: str         # short human label
    detail: str        # one-sentence explanation of why it matters
    severity: str      # info | low | medium | high | critical
    weight: int        # contribution to the risk score (0-100 scale)

    def to_dict(self) -> dict:
        return asdict(self)


def risk_level(score: int) -> str:
    """Map a 0-100 risk score to a level. Higher score = more dangerous."""
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def clamp(value: float, low: int = 0, high: int = 100) -> int:
    return int(max(low, min(high, round(value))))


def sort_findings(findings: list[Finding]) -> list[dict]:
    ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], -f.weight))
    return [f.to_dict() for f in ordered]
