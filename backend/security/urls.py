from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ChatView, PasswordAnalyzeView, PhishingDetectView, ScanViewSet, StatsView, URLScanView

router = DefaultRouter()
router.register("scans", ScanViewSet, basename="scan")

urlpatterns = [
    path("analyze/password/", PasswordAnalyzeView.as_view(), name="analyze-password"),
    path("analyze/url/", URLScanView.as_view(), name="analyze-url"),
    path("analyze/phishing/", PhishingDetectView.as_view(), name="analyze-phishing"),
    path("stats/", StatsView.as_view(), name="stats"),
    path("chat/", ChatView.as_view(), name="chat"),
    path("", include(router.urls)),
]
