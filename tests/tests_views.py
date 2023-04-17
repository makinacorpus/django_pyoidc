from unittest import mock

from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.urls import reverse

from makina_django_oidc.views import OIDClient
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

    @mock.patch("makina_django_oidc.views.Consumer.provider_config")
    def test_oidc_session_is_saved(self, *args):
        """
        Test that the OIDC client is saved on login request, and that the returned session ID allows us to restore the client
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
        self.assertEqual(response.status_code, 302)
        sid = self.client.session["oidc_sid"]
        self.assertIsNotNone(sid)
        client = OIDClient(op_name="client1", session_id=sid)
        self.assertEqual(client.consumer.client_id, "1")


class LogoutViewTestCase(OIDCTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create(
            username="test_user", email="test_user"
        )

    def test_logout_user_not_authenticated(self):
        """
        Test that trying to logout while not being connected redirects
        """
        response = self.client.get(reverse("test_logout"))
        self.assertRedirects(response, "/logoutdone", fetch_redirect_response=False)

    def test_django_user_is_at_least_logged_out(self):
        """
        Test that logging out without any OIDC state at least kills the Django session
        """
        self.client.force_login(self.user)
        response = self.client.get(reverse("test_logout"))
        self.assertRedirects(response, "/logoutdone", fetch_redirect_response=False)
        self.assertFalse(
            SESSION_KEY in self.client.session
        )  # from https://stackoverflow.com/a/6013115

    @mock.patch("makina_django_oidc.views.Consumer.restore")
    @mock.patch("makina_django_oidc.views.Consumer.do_end_session_request")
    def test_logout_triggers_oidc_request_to_sso(
        self, mocked_do_end_session_request, mocked_restore
    ):
        """
        Test that logging out while being connected and having a valid OIDC session triggers an OIDC request to the SSO
        noticing it of the logout.
        """
        self.client.force_login(self.user)

        sid = "test_id_12345"

        session = self.client.session
        session["oidc_sid"] = sid
        session.save()

        response = self.client.get(reverse("test_logout"))
        self.assertRedirects(response, "/logoutdone", fetch_redirect_response=False)
        self.assertFalse(
            SESSION_KEY in self.client.session
        )  # from https://stackoverflow.com/a/6013115
        mocked_do_end_session_request.assert_called_once_with(
            scope=["openid"], state=sid
        )
        mocked_restore.assert_called_once_with(sid)
