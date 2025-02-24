from importlib import import_module
from unittest import mock
from unittest.mock import ANY, call

from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.urls import reverse
from jwt import JWT, jwk_from_dict
from oic.oic import IdToken
from oic.oic.message import OpenIDSchema

from django_pyoidc.client import OIDCClient
from django_pyoidc.models import OIDCSession
from tests.utils import OIDCTestCase

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class LoginViewTestCase(OIDCTestCase):
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_no_next_params(self, *args):
        """
        Test that without a next parameter we are redirected to 'post_logout_redirect_uri'
        """
        response = self.client.get(
            reverse("test_login"),
            SERVER_NAME="test.django-pyoidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            settings.DJANGO_PYOIDC["sso1"]["post_login_uri_success"],
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_next_to_samesite(self, *args):
        """
        Test that redirecting to a site allowed in 'login_uris_redirect_allowed_hosts' works
        """
        response = self.client.get(
            reverse("test_login"),
            data={
                "next": "https://"
                + settings.DJANGO_PYOIDC["sso1"]["login_uris_redirect_allowed_hosts"][0]
                + "/myview/details"
            },
            SERVER_NAME="test.django-pyoidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            "https://test.django-pyoidc.notatld/myview/details",
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    @mock.patch(
        "django_pyoidc.client.Consumer.begin",
        return_value=(1234, "https://sso.notatld"),
    )
    def test_redirect_uri_management_next_follows_https_requires(self, *args):
        """
        Test that trying to redirect to a non https site when login_redirection_requires_https is set to True does not work
        """
        response = self.client.get(
            reverse("test_login"),
            data={
                "next": "http://"
                + settings.DJANGO_PYOIDC["sso1"]["login_uris_redirect_allowed_hosts"][0]
                + "/myview/details"
            },
            SERVER_NAME="test.django-pyoidc.notatld",
        )
        self.assertRedirects(
            response, "https://sso.notatld", fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["oidc_login_next"],
            settings.DJANGO_PYOIDC["sso1"]["post_login_uri_success"],
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_redirect_uri_bad_server_name(self, *args):
        """
        Test that requesting django oidc with bad host name is rejected (HTTP 400).
        """
        response = self.client.get(
            reverse("test_login"),
            data={"next": "test.django-pyoidc.notatld/myview/details"},
            SERVER_NAME="test.hacker.notatld",
        )
        self.assertEqual(response.status_code, 400)

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_redirect_uri_management_next_to_disallowed_site(self, *args):
        """
        Test that trying to redirect to a site not allowed in 'login_uris_redirect_allowed_hosts' results in ignored instruction.

        The library will reject this host and use the 'post_login_uri_success' setting instead.
        """
        response = self.client.get(
            reverse("test_login"),
            data={"next": "http://test.hacker.notatld/myview/details"},
            SERVER_NAME="test.django-pyoidc.notatld",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.client.session["oidc_login_next"],
            settings.DJANGO_PYOIDC["sso1"]["post_login_uri_success"],
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_redirect_uri_management_next_to_disallowed_site2(self, *args):
        """
        Test that trying to redirect to a site not allowed in 'login_uris_redirect_allowed_hosts' results in ignored instruction.

        The library will reject this host and use  "/" instead (as 'post_login_uri_success' is undefined for sso2).
        """
        response = self.client.get(
            reverse("test_login_2"),
            data={"next": "http://test.hacker.notatld/myview/details"},
            SERVER_NAME="test2.django-pyoidc.notatld",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.client.session["oidc_login_next"],
            "/",
        )

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_oidc_session_is_saved(self, *args):
        """
        Test that the OIDC client is saved on login request, and that the returned session ID allows us to restore the client.
        """
        response = self.client.get(
            reverse("test_login"),
            data={
                "next": "https://"
                + settings.DJANGO_PYOIDC["sso1"]["login_uris_redirect_allowed_hosts"][0]
                + "/myview/details"
            },
            SERVER_NAME="test.django-pyoidc.notatld",
        )
        self.assertEqual(response.status_code, 302)
        sid = self.client.session["oidc_sid"]
        self.assertIsNotNone(sid)
        client = OIDCClient(op_name="sso1", session_id=sid)
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
        self.assertRedirects(
            response, "http://testserver/logoutdone", fetch_redirect_response=False
        )

    def test_django_user_is_at_least_logged_out(self):
        """
        Test that logging out without any OIDC state at least kills the Django session
        """
        self.client.force_login(self.user)
        response = self.client.get(reverse("test_logout"))
        self.assertRedirects(
            response, "http://testserver/logoutdone", fetch_redirect_response=False
        )
        self.assertFalse(
            SESSION_KEY in self.client.session
        )  # from https://stackoverflow.com/a/6013115

    @mock.patch("django_pyoidc.client.Consumer.restore")
    @mock.patch(
        "django_pyoidc.client.Consumer.request_info",
        return_value=("http://example.com", "", "", ""),
    )
    def test_logout_generates_oidc_request_to_sso(
        self, mocked_request_info, mocked_restore
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
        self.assertRedirects(
            response, "http://example.com", fetch_redirect_response=False
        )
        self.assertFalse(
            SESSION_KEY in self.client.session
        )  # from https://stackoverflow.com/a/6013115
        mocked_request_info.assert_called_once()
        mocked_restore.assert_called_once_with(sid)


class CallbackViewTestCase(OIDCTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create(
            username="test_user", email="test_user"
        )

    def test_callback_but_no_sid_on_our_side(self):
        """
        Test that receiving a random request without any session states is well handled.
        """
        response = self.client.get(reverse("my_test_callback"))

        self.assertRedirects(response, "/logout_failure", fetch_redirect_response=False)

    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=({"state": ""}, None, None),
    )
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_callback_but_state_mismatch(self, mocked_restore, mocked_parse_authz):
        """
        Test that receiving a callback with a wrong state parameter results in an HTTP 4XX error.
        """
        self.client.force_login(self.user)

        state = "test_id_12345"

        session = self.client.session
        session["oidc_sid"] = state
        session.save()

        response = self.client.get(reverse("my_test_callback"))
        self.assertEqual(response.status_code, 400)
        mocked_restore.assert_called_once_with(state)
        mocked_parse_authz.assert_called_once()

    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=({"state": "test_id_12345"}, None, None),
    )
    @mock.patch("django_pyoidc.engine.get_user_by_email", return_value=None)
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info", return_value=OpenIDSchema()
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value={"id_token": IdToken(iss="fake"), "access_token": "--"},
    )
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_callback_no_session_state_provided_invalid_user(
        self,
        mocked_restore,
        mocked_complete,
        mocked_get_user_info,
        mocked_get_user,
        mocked_parse_authz,
    ):
        """
        Test that receiving a callback for a user that does not get validated by the developer-provided function 'get_user'
        does not get logged in
        """
        self.client.force_login(self.user)

        state = "test_id_12345"

        session = self.client.session
        session["oidc_sid"] = state
        session.save()

        response = self.client.get(reverse("my_test_callback"))
        mocked_restore.assert_called_once_with(state)
        mocked_complete.assert_called_once_with(state=state, session_state=None)
        mocked_parse_authz.assert_called_once()
        mocked_get_user_info.assert_called_once_with(state=state)
        mocked_get_user.assert_called_once_with(
            {
                "info_token_claims": {},
                "access_token_jwt": "--",
                "id_token_claims": {"iss": "fake"},
            }
        )

        self.assertRedirects(response, "/logout_failure", fetch_redirect_response=False)
        self.assertEqual(OIDCSession.objects.all().count(), 0)

    @mock.patch("django_pyoidc.views.OIDCView.call_user_login_callback_function")
    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=({"state": "test_id_12345"}, None, None),
    )
    @mock.patch("django_pyoidc.engine.get_user_by_email")
    @mock.patch("django_pyoidc.client.Consumer.get_user_info")
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value={"id_token": IdToken(iss="fake"), "access_token": "--"},
    )
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_callback_no_session_state_provided_valid_user(
        self,
        mocked_restore,
        mocked_complete,
        mocked_get_user_info,
        mocked_get_user,
        mocked_parse_authz,
        mocked_call_user_login_callback_function,
    ):
        """
        Test that receiving a callback for a user that gets validated by the developer-provided function 'get_user'
        is logged_in
        """
        self.client.force_login(self.user)

        state = "test_id_12345"

        session = self.client.session
        session["oidc_sid"] = state
        session.save()

        user_info = OpenIDSchema(sub="aaaaaeeee")
        user_info_dict = {"sub": "aaaaaeeee"}
        mocked_get_user_info.return_value = user_info

        dummy_user = self.user
        mocked_get_user.return_value = dummy_user

        response = self.client.get(reverse("my_test_callback"))

        with self.subTest("pyoidc calls are performed"):
            mocked_restore.assert_called_once_with(state)
            mocked_complete.assert_called_once_with(state=state, session_state=None)
            mocked_parse_authz.assert_called_once()
            mocked_get_user_info.assert_called_once_with(state=state)

        mocked_get_user.assert_called_once_with(
            {
                "info_token_claims": user_info_dict,
                "access_token_jwt": "--",
                "id_token_claims": {"iss": "fake"},
            }
        )

        self.assertRedirects(
            response, "/default/success", fetch_redirect_response=False
        )
        with self.subTest("Session is created correctly :"):
            self.assertEqual(OIDCSession.objects.all().count(), 1)

            session = OIDCSession.objects.all().first()

            self.assertEqual(session.session_state, None)
            self.assertEqual(session.sub, user_info_dict["sub"])
            self.assertEqual(session.state, state)
            self.assertEqual(session.cache_session_key, self.client.session.session_key)
        mocked_call_user_login_callback_function.assert_called_once()

    @mock.patch("django_pyoidc.views.OIDCView.call_user_login_callback_function")
    @mock.patch("django_pyoidc.client.Consumer.parse_authz")
    @mock.patch("django_pyoidc.engine.get_user_by_email")
    @mock.patch("django_pyoidc.client.Consumer.get_user_info")
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value={"id_token": IdToken(iss="fake"), "access_token": "--"},
    )
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_callback_with_session_state_provided_valid_user(
        self,
        mocked_restore,
        mocked_complete,
        mocked_get_user_info,
        mocked_get_user,
        mocked_parse_authz,
        mocked_call_user_login_callback_function,
    ):
        """
        Test that receiving a callback with a session state (SID) for a user that gets validated by the developer-provided
        function 'get_user' is logged_in
        """
        self.client.force_login(self.user)

        state = "test_id_12345"
        session_state = "fe634"

        session = self.client.session
        session["oidc_sid"] = state
        session.save()

        user_info = OpenIDSchema(sub="aaaaaeeee")
        user_info_dict = {"sub": "aaaaaeeee"}
        mocked_get_user_info.return_value = user_info

        authz = {"state": state, "session_state": session_state}
        mocked_parse_authz.return_value = authz, None, None

        dummy_user = self.user
        mocked_get_user.return_value = dummy_user

        response = self.client.get(reverse("my_test_callback"))

        with self.subTest("pyoidc calls are performed"):
            mocked_restore.assert_called_once_with(state)
            mocked_complete.assert_called_once_with(
                state=state, session_state=session_state
            )
            mocked_parse_authz.assert_called_once()
            mocked_get_user_info.assert_called_once_with(state=state)

        mocked_get_user.assert_called_once_with(
            {
                "info_token_claims": user_info_dict,
                "access_token_jwt": "--",
                "id_token_claims": {"iss": "fake"},
            }
        )

        self.assertRedirects(
            response, "/default/success", fetch_redirect_response=False
        )

        with self.subTest("Session is created correctly :"):
            self.assertEqual(OIDCSession.objects.all().count(), 1)

            session = OIDCSession.objects.all().first()

            self.assertEqual(session.session_state, session_state)
            self.assertEqual(session.sub, user_info["sub"])
            self.assertEqual(session.state, state)
            self.assertEqual(session.cache_session_key, self.client.session.session_key)

        mocked_call_user_login_callback_function.assert_called_once()

    @mock.patch(
        "django_pyoidc.client.Consumer.parse_authz",
        return_value=({"state": "test_id_12345"}, None, None),
    )
    @mock.patch("django_pyoidc.engine.get_user_by_email", return_value=None)
    @mock.patch(
        "django_pyoidc.client.Consumer.get_user_info", return_value=OpenIDSchema()
    )
    @mock.patch(
        "django_pyoidc.client.Consumer.complete",
        return_value={"id_token": IdToken(iss="fake"), "access_token": "--"},
    )
    @mock.patch("django_pyoidc.client.Consumer.restore")
    @mock.patch("tests.e2e.test_app.callback.hook_validate_access_token")
    def test_callback_calling_hook_validate_access_token(
        self,
        mocked_user_access_token_hook,
        mocked_restore,
        mocked_complete,
        mocked_get_user_info,
        mocked_get_user,
        mocked_parse_authz,
    ):
        """
        Test that receiving a callback for a user that does not get validated by the developer-provided function 'get_user'
        does not get logged in
        """
        self.client.force_login(self.user)

        state = "test_id_12345"

        session = self.client.session
        session["oidc_sid"] = state
        session.save()

        # sso2 contains a definition with a hook for access token validation
        response = self.client.get(reverse("my_test_callback_sso2"))
        mocked_restore.assert_called_once_with(state)
        mocked_complete.assert_called_once_with(state=state, session_state=None)
        mocked_parse_authz.assert_called_once()
        mocked_get_user_info.assert_called_once_with(state=state)
        mocked_get_user.assert_called_once()

        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertEqual(OIDCSession.objects.all().count(), 0)
        mocked_user_access_token_hook.assert_called_once()


class BackchannelLogoutTestCase(OIDCTestCase):
    @classmethod
    def setUpTestData(cls):
        """
        To generate an other jwk key : 'jose jwk gen -i '{"alg":"HS256"}' -o oct.jwk'
        """
        cls.signing_key = jwk_from_dict(
            {
                "alg": "HS256",
                "k": "aMQ4QgzeE_XS91lxhixouomrhy_Tymz_xGC1dmwG8Vw",
                "key_ops": ["sign", "verify"],
                "kty": "oct",
            }
        )

    def test_invalid_backchannel_logout_wrong_method_request(self):
        """
        Test that performing a GET on a backchannel logout route results in an HTTP 405
        :return:
        """
        response = self.client.get(reverse("test_blogout"))
        self.assertEqual(response.status_code, 405)

    def test_invalid_backchannel_logout_empty_request(self):
        """
        Test that providing an empty body results in an HTTP 400
        :return:
        """
        response = self.client.post(
            reverse("test_blogout"), content_type="application/x-www-form-urlencoded"
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_encoding(self):
        """
        Test that using something else than 'application/x-www-form-urlencoded' for the content-type is rejected
        """
        response = self.client.post(
            reverse("test_blogout"),
            data="".encode("utf-8"),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 415)

    def test_invalid_backchannel_logout_no_sub_no_sid(self):
        """
        Test that providing an empty body results in an HTTP 400
        """

        payload = {}
        body = JWT().encode(payload, key=self.signing_key)
        request_body = "a" * 13 + body
        response = self.client.post(
            reverse("test_blogout"),
            data=request_body.encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode("utf-8"),
            "Got invalid logout token : sub or sid is missing",
        )

    @mock.patch("django_pyoidc.views.SessionStore.delete")
    @mock.patch("django_pyoidc.client.Consumer.backchannel_logout")
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_valid_backchannel_sub(
        self, mocked_provider_config, mocked_backchannel_logout, mocked_session_delete
    ):
        """
        Test that providing a valid SUB does kill the sessions
        """

        sub = "12333"
        state = "abcde"
        s = SessionStore()
        s["data"] = "data"
        s.create()
        cache_session_key = s.session_key

        OIDCSession.objects.create(
            sub=sub, cache_session_key=cache_session_key, state=state
        )

        payload = {"sub": sub}
        body = JWT().encode(payload, key=self.signing_key)
        request_body = "a" * 13 + body
        response = self.client.post(
            reverse("test_blogout"),
            data=request_body.encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(OIDCSession.objects.all().count(), 0)
        mocked_backchannel_logout.assert_called_once()
        mocked_session_delete.assert_called_once_with(cache_session_key)

    @mock.patch("django_pyoidc.views.SessionStore.delete")
    @mock.patch("django_pyoidc.client.Consumer.backchannel_logout")
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_valid_backchannel_sid(
        self,
        mocked_restore,
        mocked_provider_config,
        mocked_backchannel_logout,
        mocked_session_delete,
    ):
        """
        Test that providing a valid SID does kill the session
        """

        sub = "12333"
        session_state = "sid:58"
        state = "abcde"
        s = SessionStore()
        s["data"] = "data"
        s.create()
        cache_session_key = s.session_key

        OIDCSession.objects.create(
            sub=sub,
            cache_session_key=cache_session_key,
            state=state,
            session_state=session_state,
        )

        mocked_backchannel_logout.return_value = session_state

        payload = {"sid": session_state}
        body = JWT().encode(payload, key=self.signing_key)
        request_body = "a" * 13 + body
        response = self.client.post(
            reverse("test_blogout"),
            data=request_body.encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(OIDCSession.objects.all().count(), 0)
        mocked_backchannel_logout.assert_called_once()
        mocked_session_delete.assert_called_once_with(cache_session_key)
        mocked_restore.assert_called_once_with(session_state)

    @mock.patch("django_pyoidc.views.SessionStore.delete")
    @mock.patch("django_pyoidc.client.Consumer.backchannel_logout")
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    @mock.patch("django_pyoidc.client.Consumer.restore")
    def test_invalid_backchannel_sid(
        self,
        mocked_restore,
        mocked_provider_config,
        mocked_backchannel_logout,
        mocked_session_delete,
    ):
        """
        Test that providing a mismatching sid value results in an HTTP 400
        """

        sub = "12333"
        session_state = "sid:58"
        state = "abcde"
        s = SessionStore()
        s["data"] = "data"
        s.create()
        cache_session_key = s.session_key

        OIDCSession.objects.create(
            sub=sub,
            cache_session_key=cache_session_key,
            state=state,
            session_state=session_state,
        )

        mocked_backchannel_logout.return_value = "invalid_sid"

        payload = {"sid": session_state}
        body = JWT().encode(payload, key=self.signing_key)
        request_body = "a" * 13 + body
        response = self.client.post(
            reverse("test_blogout"),
            data=request_body.encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(OIDCSession.objects.all().count(), 1)
        mocked_backchannel_logout.assert_called_once()
        mocked_session_delete.assert_not_called()
        mocked_restore.assert_called_once_with(session_state)

    @mock.patch("django_pyoidc.views.SessionStore.delete")
    @mock.patch("django_pyoidc.client.Consumer.backchannel_logout")
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_valid_backchannel_sub_multiple_sessions(
        self, mocked_provider_config, mocked_backchannel_logout, mocked_session_delete
    ):
        """
        Test that providing a valid SUB does kill ALL the sessions
        """

        sub = "12333"
        s = SessionStore()
        s["data"] = "data1"
        s.create()
        cache_session_key_1 = s.session_key

        s = SessionStore()
        s["data"] = "data2"
        s.create()
        cache_session_key_2 = s.session_key

        OIDCSession.objects.create(
            sub=sub, cache_session_key=cache_session_key_1, state="1"
        )
        OIDCSession.objects.create(
            sub=sub, cache_session_key=cache_session_key_2, state="2"
        )

        payload = {"sub": sub}
        body = JWT().encode(payload, key=self.signing_key)
        request_body = "a" * 13 + body
        response = self.client.post(
            reverse("test_blogout"),
            data=request_body.encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(OIDCSession.objects.all().count(), 0)
        mocked_backchannel_logout.assert_has_calls(
            [call(request_args=ANY), call(request_args=ANY)]
        )
        mocked_session_delete.assert_has_calls(
            [call(cache_session_key_1), call(cache_session_key_2)]
        )
