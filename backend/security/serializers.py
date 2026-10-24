from rest_framework import serializers

from .models import ChatMessage, ScanRecord


class PasswordInputSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=256, trim_whitespace=False, write_only=True)
    save = serializers.BooleanField(default=True)


class URLInputSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2048)
    save = serializers.BooleanField(default=True)

    def validate_url(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Enter a URL to scan.")
        return value


class PhishingInputSerializer(serializers.Serializer):
    body = serializers.CharField(max_length=20000)
    subject = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")
    sender = serializers.CharField(max_length=320, required=False, allow_blank=True, default="")
    reply_to = serializers.CharField(max_length=320, required=False, allow_blank=True, default="")
    save = serializers.BooleanField(default=True)


class ScanRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRecord
        fields = ("id", "kind", "target", "risk_score", "risk_level", "result",
                  "ai_explanation", "ai_source", "created_at")
        read_only_fields = fields


class ScanListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRecord
        fields = ("id", "kind", "target", "risk_score", "risk_level", "created_at")
        read_only_fields = fields


class ChatInputSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=4000)

    def validate_message(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Message cannot be empty.")
        return value


class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ("id", "role", "content", "source", "created_at")
        read_only_fields = fields
