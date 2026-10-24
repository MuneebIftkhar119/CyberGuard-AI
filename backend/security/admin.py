from django.contrib import admin

from .models import ChatMessage, ScanRecord


@admin.register(ScanRecord)
class ScanRecordAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "kind", "risk_level", "risk_score", "target", "created_at")
    list_filter = ("kind", "risk_level", "ai_source")
    search_fields = ("target", "user__username")
    readonly_fields = ("created_at",)


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "role", "source", "short", "created_at")
    list_filter = ("role", "source")
    search_fields = ("content", "user__username")

    @admin.display(description="Content")
    def short(self, obj):
        return obj.content[:80]
