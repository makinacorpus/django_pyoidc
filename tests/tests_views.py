from unittest import mock

from django.conf import settings
from django.urls import reverse

from tests.utils import OIDCTestCase


class LoginViewTestCase(OIDCTestCase):
    @mock.patch("makina_django_oidc.views.Consumer.provider_config")
    @mock.patch(
        "makina_django_oidc.views.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_no_next_params(self, *args):
        """
        Test that without a next parameter we are redirected to 'URI_DEFAULT_SUCCESS'
        """
        response = self.client.get(
            reverse("test_login"),
            SERVER_NAME="test.makina-django-oidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            settings.MAKINA_DJANGO_OIDC["client1"]["URI_DEFAULT_SUCCESS"],
        )

    @mock.patch("makina_django_oidc.views.Consumer.provider_config")
    @mock.patch(
        "makina_django_oidc.views.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_next_to_samesite(self, *args):
        """
        Test that redirecting to a site allowed in 'REDIRECT_ALLOWED_HOSTS' works
        """
        response = self.client.get(
            reverse("test_login"),
            data={
                "next": "https://"
                + settings.MAKINA_DJANGO_OIDC["client1"]["REDIRECT_ALLOWED_HOSTS"][0]
                + "/myview/details"
            },
            SERVER_NAME="test.makina-django-oidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            "https://test.makina-django-oidc.notatld/myview/details",
        )

    @mock.patch("makina_django_oidc.views.Consumer.provider_config")
    @mock.patch(
        "makina_django_oidc.views.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_next_follows_https_requires(self, *args):
        """
        Test that trying to redirect to a non https site when REDIRECT_REQUIRES_HTTPS is set to True does not work
        """
        response = self.client.get(
            reverse("test_login"),
            data={
                "next": "http://"
                + settings.MAKINA_DJANGO_OIDC["client1"]["REDIRECT_ALLOWED_HOSTS"][0]
                + "/myview/details"
            },
            SERVER_NAME="test.makina-django-oidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            settings.MAKINA_DJANGO_OIDC["client1"]["URI_DEFAULT_SUCCESS"],
        )

    @mock.patch("makina_django_oidc.views.Consumer.provider_config")
    @mock.patch(
        "makina_django_oidc.views.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_next_to_disallowed_site(self, *args):
        """
        Test that trying to redirect to a site not allowed in 'REDIRECT_ALLOWED_HOSTS' results in HTTP 400
        """
        response = self.client.get(
            reverse("test_login"),
            data={"next": "test.makina-django-oidc.notatld/myview/details"},
            SERVER_NAME="test.hacker.notatld",
        )
        self.assertEqual(response.status_code, 400)
