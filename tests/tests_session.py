from datetime import datetime, timezone
from unittest import mock
from unittest.mock import ANY, MagicMock, call

from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from oic.oauth2 import ASConfigurationResponse
from oic.oauth2.message import Message

from django_pyoidc.client import OIDCClient
from django_pyoidc.models import OIDCSession
from django_pyoidc.settings import OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango
from tests.utils import OIDCTestCase


class SessionTestCase(OIDCTestCase):
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_session_isolation_between_providers(self, mocked_provider_config):
        """
        Test that different SSO providers using same SID do not conflict.
        """
        sso1 = OIDCClient(op_name="sso1")
        sso2 = OIDCClient(op_name="sso2")

        mocked_provider_config.assert_has_calls([call("http://sso1/realms/realm1"), call("http://sso2/uri")])
        self.assertEqual(2, mocked_provider_config.call_count)

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        # no more calls
        mocked_provider_config.assert_has_calls([call("http://sso1/realms/realm1"), call("http://sso2/uri")])
        self.assertEqual(2, mocked_provider_config.call_count)

        client1 = OIDCClient(op_name="sso1", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "1")

        client2 = OIDCClient(op_name="sso2", session_id="1234")

        # no more calls
        mocked_provider_config.assert_has_calls([call("http://sso1/realms/realm1"), call("http://sso2/uri")])
        self.assertEqual(2, mocked_provider_config.call_count)

        self.assertEqual(client2.consumer.client_id, "2")

    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    def test_session_isolation_between_providers_cached(self, mocked_provider_config):
        """
        Test that different SSO providers with active cache using same SID do not conflict
        """

        # empty the caches
        settings1 = OIDCSettingsFactory.get("sso3")
        settings2 = OIDCSettingsFactory.get("sso4")
        cache1 = OIDCCacheBackendForDjango(settings1)
        cache2 = OIDCCacheBackendForDjango(settings2)
        cache1.clear()
        cache2.clear()

        sso1 = OIDCClient(op_name="sso3")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        self.assertEqual(mocked_provider_config.call_count, 1)

        sso2 = OIDCClient(op_name="sso4")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri"), call("http://sso4/uri")])
        self.assertEqual(mocked_provider_config.call_count, 2)

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        client1 = OIDCClient(op_name="sso3", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "3")

        client2 = OIDCClient(op_name="sso4", session_id="1234")
        self.assertEqual(client2.consumer.client_id, "4")

        mocked_provider_config.assert_has_calls([call("http://sso3/uri"), call("http://sso4/uri")])
        self.assertEqual(mocked_provider_config.call_count, 2)

    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(1236, "https://sso.notatld"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.restore",
        return_value=(1236, "foo"),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=(({"state": 1236, "session_state": "5678"}, "foo", "bar")),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value=(
            {
                "access_token": "jwt:abcabc",
                "id_token": Message(**{"exp": 100 + int(datetime.now(tz=timezone.utc).timestamp())}),
                "refresh_token": "defdef",
            }
        ),
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info",
        return_value=(
            Message(
                **{
                    "email": "test@example.com",
                    "sub": "sub",
                    "exp": 250 + int(datetime.now(tz=timezone.utc).timestamp()),
                }
            )
        ),
    )
    @mock.patch(
        "django_pyoidc.engine.OIDCEngine.introspect_access_token",
        return_value=({"foo": "bar", "exp": 100 + int(datetime.now(tz=timezone.utc).timestamp())}),
    )
    @override_settings(MIDDLEWARE=[*settings.MIDDLEWARE, "django.contrib.auth.middleware.LoginRequiredMiddleware"])
    def test_session_expiration_is_recorded_from_userinfo_before_access_token(
        self,
        mocked_intospection: MagicMock,
        mocked_userinfo: MagicMock,
        mocked_complete: MagicMock,
        mocked_parse_authz: MagicMock,
        mocked_restore: MagicMock,
        mocked_begin: MagicMock,
        *args,
    ):
        """
        Test that expiration is recorded with priority on userinfo token expiration.
        """

        # empty the caches
        settings10 = OIDCSettingsFactory.get("sso10")
        cache10 = OIDCCacheBackendForDjango(settings10)
        cache10.clear()

        # Initiate login
        host = settings.DJANGO_PYOIDC["sso10"]["login_uris_redirect_allowed_hosts"][0]
        response = self.client.get(
            reverse("test_login"),
            data={"next": f"https://{host}/foo/bar"},
            SERVER_NAME=host,
        )
        self.assertEqual(response.status_code, 302)
        mocked_begin.assert_called_once_with(scope=["openid"], response_type=ANY, use_nonce=ANY, path=ANY)

        # Login part 2, OIDCCallbackView
        response = self.client.get(
            settings10.get("oidc_callback_path"),
            data={},
            SERVER_NAME=host,
        )
        mocked_restore.assert_called_once()
        mocked_parse_authz.assert_called_once()
        mocked_complete.assert_called_once_with(state=1236, session_state="5678")
        mocked_userinfo.assert_called_once()
        mocked_intospection.assert_called_once()
        self.assertEqual(response.status_code, 302)

        # Fetch OIDCSession record and check it contains expiration
        session = OIDCSession.objects.all().first()
        now = datetime.now(tz=timezone.utc)
        op_name = session.op_name
        self.assertEqual(op_name, "sso10")
        expiration = session.expiration
        diff = expiration - now
        lifetime_seconds = int(diff.total_seconds())
        self.assertGreater(lifetime_seconds, 0)
        # userinfo token: 250s
        # id token: 50s
        # access token: 100s
        # So...
        # else it would mean the default hard coded 300 was used
        self.assertLess(lifetime_seconds, 251)
        # else it would mean the id_token exp was used
        self.assertGreater(lifetime_seconds, 51)
        # else it would mean the userinfo exp was used
        self.assertLess(lifetime_seconds, 241)
        # else it would mean the userinfo exp was used
        self.assertLess(lifetime_seconds, 101)
