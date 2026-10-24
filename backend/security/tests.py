from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .analyzers import analyze_message, analyze_password, analyze_url
from .models import ChatMessage, ScanRecord

User = get_user_model()


class PasswordAnalyzerTests(TestCase):
    def test_leaked_password_is_very_weak(self):
        r = analyze_password("P@ssw0rd")
        self.assertEqual(r["strength_label"], "very weak")
        self.assertIn("leaked", [f["code"] for f in r["findings"]])

    def test_name_year_symbol_is_not_strong(self):
        r = analyze_password("Muneeb2004!")
        self.assertIn(r["strength_label"], ("very weak", "weak"))
        codes = [f["code"] for f in r["findings"]]
        self.assertIn("predictable_shape", codes)
        self.assertIn("year", codes)

    def test_random_long_password_is_very_strong(self):
        r = analyze_password("Xk9#mP2$vL8@qR4!")
        self.assertEqual(r["strength_label"], "very strong")

    def test_passphrase_is_strong_without_one_class_warning(self):
        r = analyze_password("correct horse battery staple")
        self.assertIn(r["strength_label"], ("strong", "very strong"))
        self.assertNotIn("one_class", [f["code"] for f in r["findings"]])

    def test_short_word_combos_are_not_very_strong(self):
        for pw in ("Tylex@Office1", "summer-river-42"):
            self.assertNotIn(analyze_password(pw)["strength_label"], ("strong", "very strong"), pw)

    def test_six_word_passphrase_is_very_strong(self):
        r = analyze_password("orbit candle walrus pepper glacier violin")
        self.assertEqual(r["strength_label"], "very strong")

    def test_keyboard_walk_detected(self):
        r = analyze_password("zxcvbnm!X")
        self.assertIn("keyboard_walk", [f["code"] for f in r["findings"]])


class URLAnalyzerTests(TestCase):
    def codes(self, url):
        return [f["code"] for f in analyze_url(url)["findings"]]

    def test_clean_url_low(self):
        r = analyze_url("https://www.google.com/search?q=django")
        self.assertEqual(r["risk_level"], "low")

    def test_typosquat(self):
        self.assertIn("typosquat", self.codes("http://paypa1.com/login"))

    def test_brand_in_subdomain(self):
        r = analyze_url("https://secure-paypal.account-verify.xyz/signin")
        self.assertIn(r["risk_level"], ("high", "critical"))
        self.assertIn("brand_in_host", [f["code"] for f in r["findings"]])

    def test_at_symbol_trick(self):
        self.assertIn("at_symbol", self.codes("https://www.amazon.com@evil.ru/login"))

    def test_ip_and_port(self):
        codes = self.codes("http://45.33.12.9:8080/admin")
        self.assertIn("ip_host", codes)
        self.assertIn("odd_port", codes)

    def test_defanged_url_is_normalized(self):
        r = analyze_url("hxxps://example[.]com/path")
        self.assertEqual(r["host"], "example.com")

    def test_legit_brand_domains_not_flagged(self):
        for url in ("https://mail.google.com", "https://s3.amazonaws.com/x", "https://login.microsoftonline.com"):
            self.assertNotIn("brand_in_host", self.codes(url), url)

    def test_dangerous_scheme(self):
        self.assertEqual(analyze_url("javascript:alert(1)")["risk_level"], "critical")


class PhishingAnalyzerTests(TestCase):
    def test_classic_phish_is_critical(self):
        body = ("Dear Customer, your account has been suspended due to unusual sign-in activity. "
                "Verify your account within 24 hours: http://paypal-secure.login-check.top/verify "
                "and confirm your password.")
        r = analyze_message(body, subject="Urgent", sender="PayPal Security <alerts@gmail.com>")
        self.assertEqual(r["risk_level"], "critical")
        codes = [f["code"] for f in r["findings"]]
        for expected in ("credentials", "threat", "free_mail_org", "malicious_link"):
            self.assertIn(expected, codes)

    def test_normal_message_is_low(self):
        r = analyze_message("Hi, the meeting moved to 3pm. Agenda: https://docs.google.com/document/d/abc",
                            sender="Ali <ali@tylextech.com>")
        self.assertEqual(r["risk_level"], "low")

    def test_roman_urdu_scam(self):
        r = analyze_message("Mubarak ho! Aap ne Rs 50,000 inaam jeeta hai. Apna OTP code bhejein "
                            "aur processing fee jazzcash pe send karein fori.")
        self.assertIn(r["risk_level"], ("high", "critical"))

    def test_link_text_mismatch(self):
        body = 'Login here: <a href="http://evil-site.ru/x">https://www.hbl.com</a>'
        codes = [f["code"] for f in analyze_message(body)["findings"]]
        self.assertIn("link_text_mismatch", codes)

    def test_reply_to_mismatch(self):
        r = analyze_message("Please process the invoice.", sender="CEO <ceo@company.com>",
                            reply_to="ceo.private@protonmail.com")
        self.assertIn("reply_to_mismatch", [f["code"] for f in r["findings"]])


@override_settings(GEMINI_API_KEY="")
class APITests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()  # throttling counters live in the cache
        self.client = APIClient()
        res = self.client.post("/api/auth/register/", {
            "username": "muneeb", "email": "m@example.com", "password": "Str0ng-Passphrase-42"}, format="json")
        self.assertEqual(res.status_code, 201, res.content)
        self.tokens = res.json()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}")

    def test_health_is_public(self):
        self.assertEqual(APIClient().get("/api/health/").status_code, 200)

    def test_requires_auth(self):
        self.assertEqual(APIClient().post("/api/analyze/url/", {"url": "x.com"}).status_code, 401)

    def test_login_refresh_logout(self):
        anon = APIClient()
        res = anon.post("/api/auth/login/", {"username": "muneeb", "password": "Str0ng-Passphrase-42"}, format="json")
        self.assertEqual(res.status_code, 200)
        refresh = res.json()["refresh"]
        self.assertEqual(anon.post("/api/auth/refresh/", {"refresh": refresh}, format="json").status_code, 200)
        # Rotation blacklists the old refresh token.
        self.assertEqual(anon.post("/api/auth/refresh/", {"refresh": refresh}, format="json").status_code, 401)

    def test_weak_registration_password_rejected(self):
        res = APIClient().post("/api/auth/register/", {
            "username": "x", "email": "x@example.com", "password": "password"}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_password_scan_never_stores_password(self):
        secret = "MySecretValue123!"
        res = self.client.post("/api/analyze/password/", {"password": secret}, format="json")
        self.assertEqual(res.status_code, 200)
        scan = ScanRecord.objects.get(id=res.json()["scan_id"])
        self.assertNotIn(secret, scan.target)
        self.assertNotIn(secret, str(scan.result))

    def test_save_false_does_not_store(self):
        res = self.client.post("/api/analyze/url/", {"url": "https://example.com", "save": False}, format="json")
        self.assertIsNone(res.json()["scan_id"])
        self.assertEqual(ScanRecord.objects.count(), 0)

    def test_scan_history_stats_and_explain_fallback(self):
        self.client.post("/api/analyze/url/", {"url": "http://paypa1.com/login"}, format="json")
        res = self.client.post("/api/analyze/phishing/", {"body": "You have won a lottery! Send gift cards."}, format="json")
        scan_id = res.json()["scan_id"]

        history = self.client.get("/api/scans/").json()
        self.assertEqual(history["count"], 2)
        self.assertEqual(self.client.get("/api/scans/?kind=url").json()["count"], 1)

        stats = self.client.get("/api/stats/").json()
        self.assertEqual(stats["total"], 2)
        self.assertGreaterEqual(stats["threats_caught"], 1)

        exp = self.client.post(f"/api/scans/{scan_id}/explain/").json()
        self.assertEqual(exp["source"], "fallback")
        self.assertIn("What to do", exp["explanation"])
        # Second call is served from cache.
        self.assertTrue(self.client.post(f"/api/scans/{scan_id}/explain/").json()["cached"])

    def test_users_cannot_see_each_others_scans(self):
        res = self.client.post("/api/analyze/url/", {"url": "https://example.com"}, format="json")
        scan_id = res.json()["scan_id"]
        other = APIClient()
        tok = other.post("/api/auth/register/", {
            "username": "other", "email": "o@example.com", "password": "Another-Strong-Pass-9"}, format="json").json()
        other.credentials(HTTP_AUTHORIZATION=f"Bearer {tok['access']}")
        self.assertEqual(other.get(f"/api/scans/{scan_id}/").status_code, 404)

    def test_chat_fallback_without_key(self):
        res = self.client.post("/api/chat/", {"message": "What is phishing?"}, format="json")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["reply"]["source"], "fallback")
        self.assertEqual(len(self.client.get("/api/chat/").json()), 2)
        self.client.delete("/api/chat/")
        self.assertEqual(ChatMessage.objects.count(), 0)

    @override_settings(GEMINI_API_KEY="test-key")
    def test_chat_uses_gemini_and_sends_history(self):
        with mock.patch("security.ai._generate", return_value="Phishing is a scam.") as gen:
            self.client.post("/api/chat/", {"message": "first"}, format="json")
            res = self.client.post("/api/chat/", {"message": "second"}, format="json")
        self.assertEqual(res.json()["reply"]["source"], "gemini")
        contents = gen.call_args.args[1]
        self.assertEqual(len(contents), 3)  # first, reply, second

    @override_settings(GEMINI_API_KEY="test-key")
    def test_explain_payload_has_no_password(self):
        res = self.client.post("/api/analyze/password/", {"password": "Hunter2Hunter2!"}, format="json")
        with mock.patch("security.ai._generate", return_value="ok") as gen:
            self.client.post(f"/api/scans/{res.json()['scan_id']}/explain/")
        self.assertNotIn("Hunter2Hunter2!", gen.call_args.args[1])
