from datetime import datetime, timedelta, timezone
from unittest import mock
from unittest.mock import ANY, MagicMock

from django.conf import settings
from django.http import HttpResponse
from django.test import override_settings
from django.urls import reverse
from oic.oauth2 import ASConfigurationResponse
from oic.oauth2.message import Message

from django_pyoidc.models import OIDCSession

# from django_pyoidc.middleware import OIDCSessionExpirationMiddleware
from django_pyoidc.settings import OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango
from tests.utils import OIDCTestCase


class MiddlewareTestCase(OIDCTestCase):
    @mock.patch(
        "django_pyoidc.middleware.OIDCSessionExpirationMiddleware._check_validity",
        return_value=ASConfigurationResponse(),
    )
    @override_settings(
        MIDDLEWARE=(
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            # Our middleware
            "django_pyoidc.middleware.OIDCSessionExpirationMiddleware",
        ),
    )
    def test_middleware_does_nothing_on_anonymous_requests(self, mocked_middleware_check: MagicMock, *args):
        session = self.client.session
        session.flush()
        session.save()
        # request a page not managed by django_pyoidc (no auth required)
        response = self.client.get(
            reverse("test_unmanaged_anonymous"),
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_not_called()
        response = self.client.post(
            reverse("test_unmanaged_anonymous"),
            data={},
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_not_called()

    @override_settings(
        MIDDLEWARE=(
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            # Our middleware
            "django_pyoidc.middleware.OIDCSessionExpirationMiddleware",
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    @mock.patch(
        "django_pyoidc.middleware.OIDCSessionExpirationMiddleware._check_validity",
        return_value=HttpResponse(),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(45645, "https://sso.notatld"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.restore",
        return_value=(45645, "foo"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=(({"state": 45645, "session_state": "5678"}, "", "")),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value=({"access_token": "jwt:___", "id_token": Message(**{}), "refresh_token": "defdef"}),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info",
        return_value=(Message(**{"email": "test@example.com", "sub": "sub"})),
    )
    @mock.patch(
        "django_pyoidc.engine.OIDCEngine.introspect_access_token",
        return_value=({}),
    )
    def test_middleware_does_nothing_on_authorized_requests(
        self,
        mocked_introspection: MagicMock,
        mocked_userinfo: MagicMock,
        mocked_complete: MagicMock,
        mocked_parse_authz: MagicMock,
        mocked_restore: MagicMock,
        mocked_begin: MagicMock,
        mocked_middleware_check: MagicMock,
        mocked_config: MagicMock,
        *args,
    ):
        """
        The middleware should not be active until a valid session is in place.
        """
        self.client.logout()

        # empty the caches
        settings10 = OIDCSettingsFactory.get("sso10")
        cache10 = OIDCCacheBackendForDjango(settings10)
        cache10.clear()

        # Initiate login
        host = settings.DJANGO_PYOIDC["sso10"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login"),
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)
        # Here it MUST NOT be called
        mocked_middleware_check.assert_not_called()
        mocked_restore.assert_not_called()
        mocked_config.assert_called_once()
        mocked_begin.assert_called_once_with(scope=["openid"], response_type=ANY, use_nonce=ANY, path=ANY)

        # Login part 2, OIDCCallbackView
        # mocked_config.reset_mock()
        # mocked_middleware_check.reset_mock()
        mocked_restore.reset_mock()
        mocked_parse_authz.reset_mock()
        mocked_complete.reset_mock()
        mocked_userinfo.reset_mock()
        mocked_introspection.reset_mock()
        response = self.client.get(
            settings10.get("oidc_callback_path"),
            data={},
            SERVER_NAME=host,
        )
        # Here it still MUST NOT be called, session is 'existing'
        # but still in the validation process
        mocked_middleware_check.assert_not_called()
        mocked_restore.assert_called_once()
        mocked_parse_authz.assert_called_once()
        mocked_complete.assert_called_once()
        mocked_userinfo.assert_called_once()
        mocked_introspection.assert_called_once()
        self.assertEqual(response.status_code, 302)

        # Now regular anonymous page will trigger the middleware check
        # because our user is not anonymous even if the page is
        mocked_middleware_check.reset_mock()
        response = self.client.get(
            reverse("test_unmanaged_anonymous"),
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_called()
        # test POST also.
        mocked_middleware_check.reset_mock()
        response = self.client.post(
            reverse("test_unmanaged_anonymous"),
            data={},
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_called()

        # same for authorized-only pages
        mocked_middleware_check.reset_mock()
        response = self.client.get(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_called()
        # test POST also.
        mocked_middleware_check.reset_mock()
        response = self.client.post(
            reverse("test_unmanaged_authentified"),
            data={},
        )
        self.assertEqual(response.status_code, 200)
        mocked_middleware_check.assert_called()

    @override_settings(
        MIDDLEWARE=(
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            # Our middleware
            "django_pyoidc.middleware.OIDCSessionExpirationMiddleware",
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(45645, "https://sso.notatld"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.restore",
        return_value=(45645, "foo"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=(({"state": 45645, "session_state": "5678"}, "", "")),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value=(
            {
                "access_token": "jwt:___",
                "id_token": Message(**{"exp": 100 + int(datetime.now(tz=timezone.utc).timestamp())}),
                "refresh_token": "defdef",
            }
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info",
        return_value=(Message(**{"email": "test@example.com", "sub": "sub"})),
    )
    @mock.patch(
        "django_pyoidc.engine.OIDCEngine.introspect_access_token",
        return_value=({}),
    )
    def test_middleware_detect_expiration(
        self,
        mocked_introspection: MagicMock,
        mocked_userinfo: MagicMock,
        mocked_complete: MagicMock,
        mocked_parse_authz: MagicMock,
        mocked_restore: MagicMock,
        mocked_begin: MagicMock,
        mocked_config: MagicMock,
        *args,
    ):
        """
        The middleware will detect expiration and send an error response for POST.
        """
        self.client.logout()

        # empty the caches
        settings10 = OIDCSettingsFactory.get("sso10")
        cache10 = OIDCCacheBackendForDjango(settings10)
        cache10.clear()

        # Initiate login
        host = settings.DJANGO_PYOIDC["sso10"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login"),
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)

        # Login part 2, OIDCCallbackView
        response = self.client.get(
            settings10.get("oidc_callback_path"),
            data={},
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)

        # Ensure middleware is active and not triggering anything yet
        response = self.client.get(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 200)

        # Get the current recorded expiration and overwite it
        session = OIDCSession.objects.all().first()
        now = datetime.now(tz=timezone.utc)
        op_name = session.op_name
        self.assertEqual(op_name, "sso10")
        expiration = session.expiration
        diff = expiration - now
        lifetime_seconds = int(diff.total_seconds())
        self.assertGreater(lifetime_seconds, 0)
        self.assertLess(lifetime_seconds, 300)
        new_expiration = session.expiration - timedelta(seconds=300)
        session.expiration = new_expiration
        session.save()

        # Now it should fail
        # with a POST we should have a 401
        response = self.client.post(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 401)
        # and we are disconnected
        response = self.client.get(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        self.assertIsNone(session.get("oidc_sid"))

    @override_settings(
        MIDDLEWARE=(
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            # Our middleware
            "django_pyoidc.middleware.OIDCSessionExpirationMiddleware",
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(45645, "https://sso.notatld"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.restore",
        return_value=(45645, "foo"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=(({"state": 45645, "session_state": "5678"}, "", "")),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value=(
            {
                "access_token": "jwt:___",
                "id_token": Message(**{"exp": 100 + int(datetime.now(tz=timezone.utc).timestamp())}),
                "refresh_token": "defdef",
            }
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info",
        return_value=(Message(**{"email": "test@example.com", "sub": "sub"})),
    )
    @mock.patch(
        "django_pyoidc.engine.OIDCEngine.introspect_access_token",
        return_value=({}),
    )
    def test_middleware_detect_expiration_get_mode(
        self,
        mocked_introspection: MagicMock,
        mocked_userinfo: MagicMock,
        mocked_complete: MagicMock,
        mocked_parse_authz: MagicMock,
        mocked_restore: MagicMock,
        mocked_begin: MagicMock,
        mocked_config: MagicMock,
        *args,
    ):
        """
        The middleware will detect expiration and redirect if no refresh tokens are used.
        """
        self.client.logout()

        # empty the caches
        settings10 = OIDCSettingsFactory.get("sso10")
        cache10 = OIDCCacheBackendForDjango(settings10)
        cache10.clear()

        # Initiate login
        host = settings.DJANGO_PYOIDC["sso10"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login"),
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)

        # Login part 2, OIDCCallbackView
        response = self.client.get(
            settings10.get("oidc_callback_path"),
            data={},
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)

        # Ensure middleware is active and not triggering anything yet
        response = self.client.get(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 200)

        # Get the current recorded expiration and overwite it
        session = OIDCSession.objects.all().first()
        now = datetime.now(tz=timezone.utc)
        op_name = session.op_name
        self.assertEqual(op_name, "sso10")
        expiration = session.expiration
        diff = expiration - now
        lifetime_seconds = int(diff.total_seconds())
        self.assertGreater(lifetime_seconds, 0)
        self.assertLess(lifetime_seconds, 300)
        new_expiration = session.expiration - timedelta(seconds=300)
        session.expiration = new_expiration
        session.save()

        # Now it should fail
        # with a GET we should have a redirection to '/' or our login defined in
        # the helper, which should be the case here for sso10 (/sso10-login).
        # but the middleware has no 'namespace' detection for reverse url, so it
        # will currently fail and redirect to '/'
        # maybe we need to get a default namespace in get_namespace for the helper...
        response = self.client.get(
            reverse("test_unmanaged_authentified"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        # and we are disconnected
        session = self.client.session
        self.assertIsNone(session.get("oidc_sid"))
