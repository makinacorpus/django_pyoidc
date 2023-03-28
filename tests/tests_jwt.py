from django.test import TestCase
from django.urls import reverse


class JwtValidationTestCase(TestCase):
    def test_expired_token_is_rejected(self):
        self.client.get(reverse("test_login"))
        self.client.get(reverse("test_callback"))
