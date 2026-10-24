from django.db.models import Avg, Count
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from . import ai
from .analyzers import analyze_message, analyze_password, analyze_url
from .models import ChatMessage, ScanRecord
from .serializers import (
    ChatInputSerializer, ChatMessageSerializer, PasswordInputSerializer, PhishingInputSerializer,
    ScanListSerializer, ScanRecordSerializer, URLInputSerializer,
)

CHAT_CONTEXT_MESSAGES = 12


class AIThrottleMixin:
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "ai"


def _save_scan(request, kind, target, result, save):
    if not save:
        return None
    level = result.get("risk_level") or _password_level(result["risk_score"])
    return ScanRecord.objects.create(
        user=request.user, kind=kind, target=target[:300],
        risk_score=result["risk_score"], risk_level=level, result=result,
    )


def _password_level(risk_score: int) -> str:
    from .analyzers.common import risk_level
    return risk_level(risk_score)


def _response(scan, result):
    return Response({"scan_id": scan.id if scan else None, "result": result}, status=status.HTTP_200_OK)


class PasswordAnalyzeView(APIView):
    def post(self, request):
        s = PasswordInputSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        result = analyze_password(s.validated_data["password"])
        result["risk_level"] = _password_level(result["risk_score"])
        # Store only a masked label — the password itself is never persisted.
        target = f"{'•' * min(result['length'], 12)} ({result['length']} chars)"
        scan = _save_scan(request, ScanRecord.Kind.PASSWORD, target, result, s.validated_data["save"])
        return _response(scan, result)


class URLScanView(APIView):
    def post(self, request):
        s = URLInputSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        result = analyze_url(s.validated_data["url"])
        scan = _save_scan(request, ScanRecord.Kind.URL, result["normalized_url"], result, s.validated_data["save"])
        return _response(scan, result)


class PhishingDetectView(APIView):
    def post(self, request):
        s = PhishingInputSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        result = analyze_message(d["body"], subject=d["subject"], sender=d["sender"], reply_to=d["reply_to"])
        preview = d["subject"].strip() or " ".join(d["body"].split())[:120]
        scan = _save_scan(request, ScanRecord.Kind.PHISHING, preview, result, d["save"])
        return _response(scan, result)


class ScanViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin,
                  viewsets.GenericViewSet):
    """History of the current user's scans. ?kind=url|password|phishing filters the list."""

    def get_queryset(self):
        qs = ScanRecord.objects.filter(user=self.request.user)
        kind = self.request.query_params.get("kind")
        if kind in ScanRecord.Kind.values:
            qs = qs.filter(kind=kind)
        return qs

    def get_serializer_class(self):
        return ScanListSerializer if self.action == "list" else ScanRecordSerializer

    @action(detail=True, methods=["post"], throttle_classes=[ScopedRateThrottle])
    def explain(self, request, pk=None):
        scan = self.get_object()
        refresh = str(request.data.get("refresh", "")).lower() in {"1", "true"}
        if scan.ai_explanation and not (refresh and scan.ai_source == "fallback"):
            return Response({"explanation": scan.ai_explanation, "source": scan.ai_source, "cached": True})
        text, source = ai.explain_scan(scan.kind, scan.result)
        scan.ai_explanation, scan.ai_source = text, source
        scan.save(update_fields=["ai_explanation", "ai_source"])
        return Response({"explanation": text, "source": source, "cached": False})

    def get_throttles(self):
        if self.action == "explain":
            self.throttle_scope = "ai"
        return super().get_throttles()

    @action(detail=False, methods=["delete"], url_path="clear")
    def clear(self, request):
        deleted, _ = self.get_queryset().delete()
        return Response({"deleted": deleted})


class StatsView(APIView):
    def get(self, request):
        qs = ScanRecord.objects.filter(user=request.user)
        by_kind = {row["kind"]: row["n"] for row in qs.values("kind").annotate(n=Count("id"))}
        by_level = {row["risk_level"]: row["n"] for row in qs.values("risk_level").annotate(n=Count("id"))}
        avg_pw = qs.filter(kind="password").aggregate(a=Avg("risk_score"))["a"]
        return Response({
            "total": qs.count(),
            "by_kind": {k: by_kind.get(k, 0) for k in ScanRecord.Kind.values},
            "by_level": {k: by_level.get(k, 0) for k in ("low", "medium", "high", "critical")},
            "threats_caught": by_level.get("high", 0) + by_level.get("critical", 0),
            "avg_password_strength": None if avg_pw is None else round(100 - avg_pw),
            "chat_messages": ChatMessage.objects.filter(user=request.user, role="user").count(),
            "recent": ScanListSerializer(qs[:5], many=True).data,
        })


class ChatView(AIThrottleMixin, APIView):
    def get_throttles(self):
        # Only sending a message costs an AI call; reading history shouldn't be throttled as AI.
        if self.request.method != "POST":
            return []
        return super().get_throttles()

    def get(self, request):
        msgs = ChatMessage.objects.filter(user=request.user).order_by("-created_at", "-id")[:100]
        return Response(ChatMessageSerializer(reversed(list(msgs)), many=True).data)

    def post(self, request):
        s = ChatInputSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        text = s.validated_data["message"]
        recent = ChatMessage.objects.filter(user=request.user).order_by("-created_at", "-id")[:CHAT_CONTEXT_MESSAGES]
        history = [{"role": m.role, "content": m.content}
                   for m in reversed(list(recent)) if m.source != "fallback"]
        user_msg = ChatMessage.objects.create(user=request.user, role="user", content=text)
        reply, source = ai.chat_reply(history, text)
        bot_msg = ChatMessage.objects.create(user=request.user, role="assistant", content=reply, source=source)
        return Response({
            "user_message": ChatMessageSerializer(user_msg).data,
            "reply": ChatMessageSerializer(bot_msg).data,
        }, status=status.HTTP_201_CREATED)

    def delete(self, request):
        deleted, _ = ChatMessage.objects.filter(user=request.user).delete()
        return Response({"deleted": deleted})
