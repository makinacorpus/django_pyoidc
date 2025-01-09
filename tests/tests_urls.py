from unittest import mock

from django.conf import settings
from django.urls import reverse

from tests.utils import OIDCTestCase


class UrlsTestCase(OIDCTestCase):
    def test_reverse_urls_are_defined(self, *args):
        """
        Test that urls defined in our test settings are working.
        """
        self.assertEqual(
            reverse("test_blogout"),
            "/back_channel_logout-xyz/",
        )
        self.assertEqual(
            reverse("test_login"),
            "/login-xyz/",
        )
        self.assertEqual(
            reverse("test_logout"),
            "/logout-xyz/",
        )
        self.assertEqual(
            reverse("test_logout"),
            "/logout-xyz/",
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_callback_path_with_uri_name(self, *args):
        """
        Test that using callback_uri_name we have the right callback path.

        "sso1" definition is not using oidc_callback_path but a named route
        with callback_uri_name instead.
        """
        host = settings.DJANGO_PYOIDC["sso1"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login"),
            data={"next": f"https://{host}/foo/bar"},
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        elements = location.split("?")
        query_string = elements[1]
        arguments = query_string.split("&")
        self.assertIn("client_id=1", arguments)
        self.assertIn(f"redirect_uri=http%3A%2F%2F{host}%2Fcallback-xyz%2F", arguments)

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_callback_path_with_oidc_callback_path(self, *args):
        """
        Test that using only oidc_callback_path we have the right callback path.

        "sso2" definition does not contain callback_uri_name but oidc_callback_path
        instead.
        """
        host = settings.DJANGO_PYOIDC["sso2"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login_2"),
            data={"next": f"https://{host}/foo/bar"},
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        elements = location.split("?")
        query_string = elements[1]
        arguments = query_string.split("&")
        self.assertIn("client_id=2", arguments)
        self.assertIn(f"redirect_uri=http%3A%2F%2F{host}%2Fcallback-wtf%2F", arguments)
