import http.client as http_client
import logging
from urllib.parse import parse_qs, urlparse

import requests
from django.test import override_settings
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC

# from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support.ui import WebDriverWait

from tests_e2e.utils import OIDCE2ETestCase, wrap_class

# HTTP debug for requests
http_client.HTTPConnection.debuglevel = 1


class KeycloakTestCase(OIDCE2ETestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        options = Options()
        # options.headless = True
        cls.selenium = WebDriver(options=options)
        # cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()

    def test_00_login_page_redirects_to_keycloak_sso(self, *args):
        """
        Test that accessing login callback redirects to the SSO server.
        """
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        client = requests

        print(f"Running Django on {self.live_server_url}")

        login_url = reverse("test_login")
        response = client.get(
            f"{self.live_server_url}{login_url}", allow_redirects=False
        )
        # we should get something like http://localhost:8080/auth/realms/realm1/protocol/openid-connect/auth
        #   ?client_id=app1
        #   &nonce=YZA...24
        #   &redirect_uri=http%3A%2F%2Ftestserver%2Fcallback
        #   &response_type=code
        #   &scope=openid
        #   &state=fe874.....538e047a0
        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "http")
        self.assertEqual(parsed.netloc, "localhost:8080")
        self.assertEqual(
            parsed.path, "/auth/realms/realm1/protocol/openid-connect/auth"
        )
        self.assertEqual(qs["client_id"][0], "app1")
        self.assertEqual(qs["redirect_uri"][0], f"{self.live_server_url}/callback")
        self.assertEqual(qs["response_type"][0], "code")
        self.assertEqual(qs["scope"][0], "openid")
        self.assertTrue(qs["state"][0])
        self.assertTrue(qs["nonce"][0])

    def _selenium_sso_login(
        self, login_start_url, login_end_url, user, password, active_sso_session=False
    ):
        if not active_sso_session:
            self.selenium.get(login_start_url)
            self.wait.until(EC.url_changes(login_start_url))
            # wait ->
            #   EC.url_changes('a') // anything but a
            #   EC.url_contains('')
            #   EC.url_matches(pattern)
            #   EC.title_contains('')
            #   EC.title_is('')
            #   EC.url_to_be('') // exact

            username_input = self.selenium.find_element(By.NAME, "username")
            username_input.send_keys(user)
            password_input = self.selenium.find_element(By.NAME, "password")
            password_input.send_keys(password)
            self.selenium.find_element(By.ID, "kc-login").click()
        else:
            # current SSO session is still active,
            # so we should redirected directly to success page
            self.selenium.get(login_start_url)
        self.wait.until(EC.url_matches(login_end_url))

    def _selenium_logout(self, end_url):
        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we have the logout link
        self.assertTrue("OIDC-LOGOUT-LINK" in bodyText)
        # click logout
        self.selenium.find_element(By.ID, "oidc-logout-link").click()
        self.wait.until(EC.url_matches(end_url))
        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are NOT logged in
        self.assertTrue("You are logged out" in bodyText)

    def test_01_selenium_sso_login(self, *args):
        """
        Test a complete working OIDC login.
        """
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_sucess")
        start_url = f"{self.live_server_url}{login_url}"
        end_url = f"{self.live_server_url}{success_url}"
        self.wait = WebDriverWait(self.selenium, timeout)
        self._selenium_sso_login(start_url, end_url, "user1", "passwd1")

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are logged in

        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)
        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)

        # check we have the logout link
        self.assertFalse("OIDC-LOGIN-LINK" in bodyText)
        self.assertTrue("OIDC-LOGOUT-LINK" in bodyText)

    def test_02_selenium_sso_login_and_logout(self, *args):
        """
        FIXME : Make this test independant of test #1
        """
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_sucess")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)

        self._selenium_sso_login(
            start_url, middle_url, "user1", "passwd1", active_sso_session=True
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we have the logout link
        self.assertFalse("OIDC-LOGIN-LINK" in bodyText)
        self.assertTrue("OIDC-LOGOUT-LINK" in bodyText)
        # click logout
        self.selenium.find_element(By.ID, "oidc-logout-link").click()

        self.wait.until(EC.url_matches(end_url))

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are NOT logged in
        self.assertFalse("You are logged in as user1@example.com" in bodyText)
        self.assertTrue("You are logged out" in bodyText)

        # Check the new session message is shown
        self.assertTrue("message: post logout view." in bodyText)
        # check we have the login link
        self.assertTrue("OIDC-LOGIN-LINK" in bodyText)
        self.assertFalse("OIDC-LOGOUT-LINK" in bodyText)

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "app1",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "LOGIN_URI_CALLBACK": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGIN_URI_SUCCESS_DEFAULT": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "HOOK_USER_LOGIN": "tests_e2e.test_app.callback:login_callback",
                "HOOK_USER_LOGOUT": "tests_e2e.test_app.callback:logout_callback",
            },
        },
    )
    def test_03_selenium_sso_session_with_callbacks(self, *args):
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_sucess")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)
        # previous test detroyed the SSO session, we need to reconnect
        self._selenium_sso_login(
            start_url, middle_url, "user1", "passwd1", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # print(bodyText)

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)
        # Check the CALLBACK session message is also shown
        self.assertTrue("login_callback for : user1@example.com" in bodyText)

        # check we have the logout link
        self.assertTrue("OIDC-LOGOUT-LINK" in bodyText)
        # click logout
        self.selenium.find_element(By.ID, "oidc-logout-link").click()

        self.wait.until(EC.url_matches(end_url))

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are NOT logged in
        self.assertTrue("You are logged out" in bodyText)

        # Check the new session message is shown
        self.assertTrue("message: post logout view." in bodyText)
        # Check the logout callback message is shown
        self.assertTrue("Logout Callback for user1@example.com." in bodyText)

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "bad_client_id",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "LOGIN_URI_CALLBACK": "/callback",
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGIN_URI_SUCCESS_DEFAULT": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
            },
        },
    )
    def test_04_selenium_sso_failed_login(self, *args):
        """
        Test a failed SSO login (bad client)
        """
        timeout = 30
        login_url = reverse("test_login")
        start_url = f"{self.live_server_url}{login_url}"
        wait = WebDriverWait(self.selenium, timeout)
        # wait ->
        #   EC.url_changes('a') // anything but a
        #   EC.url_contains('')
        #   EC.url_matches(pattern)
        #   EC.title_contains('')
        #   EC.title_is('')
        #   EC.url_to_be('') // exact

        self.selenium.get(start_url)
        # wait for the SSO redirection
        wait.until(EC.url_changes(start_url))

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check the SSO rejected our client id
        self.assertTrue("We are sorry..." in bodyText)
        self.assertTrue("Invalid parameter: redirect_uri" in bodyText)

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "app1",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "LOGIN_URI_CALLBACK": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "POST_LOGIN_URI_SUCCESS_DEFAULT": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "HOOK_GET_USER": "tests_e2e.test_app.callback:get_user",
            },
        },
    )
    def test_05_selenium_audience_checks(self, *args):
        """
        FIXME : make this test independant of test #3
        """
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_sucess")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)
        self._selenium_sso_login(
            start_url, middle_url, "user_app2", "passwd2", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        print(bodyText)

        # Check the session message is shown
        self.assertTrue("message: user_app2@example.com is logged in." in bodyText)

        self._selenium_logout(end_url)

        self._selenium_sso_login(
            start_url, middle_url, "user_app3", "passwd3", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        print(bodyText)

        # Check the session message is shown
        self.assertTrue("message: user_app3@example.com is logged in." in bodyText)

        self._selenium_logout(end_url)

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "app1",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "LOGIN_URI_CALLBACK": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "POST_LOGIN_URI_SUCCESS_DEFAULT": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "HOOK_GET_USER": "tests_e2e.test_app.callback:get_user",
            },
        },
    )
    def test_10_selenium_pyoidc_provider_config_calls(self, *args):
        """
        FIXME:
        Ensure calls to SSO provider configuration is managed with a cache.

        Several logins should not generates a call to provider config each time.
        Provider configuration should be shared between users, at least for a
        short cache lifetime duration.

        FIXME:
        For pyoidc this means the Client must be feed with provider_info data
        to avoid re-requesting it in auto discovery mode.
        i.e. keys client_registration and provider_info in
        ["srv_discovery_url", "client_info", "client_registration", "provider_info"].
        "srv_discovery_url" should only be used when no cache data is available.

        FIXME : make this test independant of test #3
        """
        timeout = 5

        login_url = reverse("test_login")
        success_url = reverse("test_sucess")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        from oic.oauth2 import Client

        with wrap_class(Client, "provider_config") as mocked_provider_config:

            self.wait = WebDriverWait(self.selenium, timeout)
            self._selenium_sso_login(
                start_url, middle_url, "user_app2", "passwd2", active_sso_session=False
            )

            bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
            print(bodyText)

            # Check the session message is shown
            self.assertTrue("message: user_app2@example.com is logged in." in bodyText)

            self._selenium_logout(end_url)

            self._selenium_sso_login(
                start_url, middle_url, "user_app3", "passwd3", active_sso_session=False
            )

            bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
            print(bodyText)

            # Check the session message is shown
            self.assertTrue("message: user_app3@example.com is logged in." in bodyText)

            self._selenium_logout(end_url)

            # oic.oauth2.base.PBase.http_request:
            # expected_call= [
            #     call('http://localhost:8080/auth/realms/realm1/.well-known/openid-configuration', allow_redirects=True)
            # ]
            # print("==================================")
            # print(mocked_provider_config.call_count)
            # print(mocked_provider_config.call_args_list)
            # mocked_provider_config.assert_any_call(expected_calls)

            # Need to set this test alone, maybe with a simplier Keycloak setUp...
            # self.assertEquals( mocked_provider_config.call_count, 1)
            self.assertEquals(mocked_provider_config.call_count, 2)
