from django.conf import settings
from django.db import models


class ScanRecord(models.Model):
    class Kind(models.TextChoices):
        PASSWORD = "password", "Password"
        URL = "url", "URL"
        PHISHING = "phishing", "Phishing"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans")
    kind = models.CharField(max_length=16, choices=Kind.choices)
    # Never the raw password: for passwords this is a masked label like "••••••• (11 chars)".
    target = models.CharField(max_length=300)
    risk_score = models.PositiveSmallIntegerField()
    risk_level = models.CharField(max_length=16)
    result = models.JSONField()
    ai_explanation = models.TextField(blank=True)
    ai_source = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("user", "-created_at")), models.Index(fields=("user", "kind"))]

    def __str__(self):
        return f"{self.get_kind_display()} · {self.risk_level} · {self.target[:40]}"


class ChatMessage(models.Model):
    class Role(models.TextChoices):
        USER = "user", "User"
        ASSISTANT = "assistant", "Assistant"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="chat_messages")
    role = models.CharField(max_length=16, choices=Role.choices)
    content = models.TextField()
    source = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("created_at", "id")
        indexes = [models.Index(fields=("user", "created_at"))]

    def __str__(self):
        return f"{self.role}: {self.content[:50]}"
