import http.client as http_client
import logging
from urllib.parse import parse_qs, urlparse

import requests
from django.test import override_settings
from django.urls import reverse
from selenium.webdriver import FirefoxProfile
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC

# from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support.ui import WebDriverWait

from tests.e2e.utils import OIDCE2EKeycloakTestCase

# HTTP debug for requests
http_client.HTTPConnection.debuglevel = 1


class KeycloakTestCase(OIDCE2EKeycloakTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        options = Options()
        options.add_argument("--private")
        # options.headless = True
        profile = FirefoxProfile()
        profile.set_preference("browser.privatebrowsing.autostart", True)
        cls.selenium = WebDriver(firefox_profile=profile, options=options)
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
        self,
        login_start_url,
        login_end_url,
        user,
        password,
        active_sso_session=False,
        wait_for_success=True,
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
            # so we should be redirected directly to success page
            self.selenium.get(login_start_url)
        if wait_for_success:
            self.wait.until(EC.url_matches(login_end_url))

    def _selenium_anon_logout(self):
        """Like classical logout but we are not connected in local app."""
        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we have the logout link
        self.assertTrue("OIDC-ANON-LOGOUT-LINK" in bodyText)
        # click logout
        self.selenium.find_element(By.ID, "oidc-anon-logout-link").click()

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
        Test a complete working OIDC login/logout.
        """
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_success")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)
        self._selenium_sso_login(
            start_url, middle_url, "user1", "passwd1", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)

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

        # Check the logout view message is shown
        self.assertTrue("message: post logout view." in bodyText)
        # check we have the login link
        self.assertTrue("OIDC-LOGIN-LINK" in bodyText)
        self.assertFalse("OIDC-LOGOUT-LINK" in bodyText)

    def test_02_selenium_sso_login__relogin_and_logout(self, *args):
        """
        Test a login/logout session, adding a re-login on existing session in the middle
        """
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_success")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)

        # LOGIN 1
        self._selenium_sso_login(
            start_url, middle_url, "user1", "passwd1", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)

        # LOGIN 2: reusing existing session
        self._selenium_sso_login(start_url, middle_url, "", "", active_sso_session=True)

        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

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

        # Check the logout view message is shown
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
                "OIDC_CALLBACK_PATH": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGIN_URI_SUCCESS": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
                "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            },
        },
    )
    def test_03_selenium_sso_session_with_callbacks(self, *args):
        timeout = 5
        login_url = reverse("test_login")
        success_url = reverse("test_success")
        post_logout_url = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        end_url = f"{self.live_server_url}{post_logout_url}"
        self.wait = WebDriverWait(self.selenium, timeout)
        # previous test destroyed the SSO session, we need to reconnect
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
                "OIDC_CALLBACK_PATH": "/callback",
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGIN_URI_SUCCESS": "/test-success",
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

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "app1",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "OIDC_CALLBACK_PATH": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "POST_LOGIN_URI_SUCCESS": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "HOOK_GET_USER": "tests.e2e.test_app.callback:get_user_with_resource_access_check",
            },
        },
    )
    def test_05_selenium_ressource_access_checks(self, *args):
        """
        Check that a resource access check can be performed to prevent access for some users.

        @see tests.e2e.test_app.callback:get_user_with_resource_access_check
        """
        timeout = 5
        login_location = reverse("test_login")
        success_location = reverse("test_success")
        failure_location = reverse("test_failure")
        post_logout_location = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_location}"
        ok_url = f"{self.live_server_url}{success_location}"
        failure_url = f"{self.live_server_url}{failure_location}"
        end_url = f"{self.live_server_url}{post_logout_location}"
        self.wait = WebDriverWait(self.selenium, timeout)

        # user1 login is OK, resource access success
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user1",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)
        self._selenium_logout(end_url)

        # user_limit_app1 has access to app1 and app1-api, resource access should match
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user_limit_app1",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        self.assertTrue(
            "message: user_limit_app1@example.com is logged in." in bodyText
        )

        self._selenium_logout(end_url)

        # user_limit_app2 login Will FAIL, as user has access to group2 apps only, and we are not in
        self._selenium_sso_login(
            start_url,
            failure_url,
            "user_limit_app2",
            "passwd2",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        print(bodyText)
        # Check we have the Permission Denied message
        self.assertTrue("Permission Denied." in bodyText)
        # we are not allowed in this app but we still have a valid SSO session
        # so having a logout action can be useful
        self._selenium_anon_logout()

        # to ensure this destroy cookies worked redo a user1 login/logout
        # user1 login is OK, resource access success
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user1",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)
        self._selenium_logout(end_url)

    @override_settings(
        DJANGO_PYOIDC={
            "sso1": {
                "OIDC_CLIENT_ID": "app1",
                "CACHE_DJANGO_BACKEND": "default",
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/realm1",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "OIDC_CALLBACK_PATH": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "REDIRECT_REQUIRES_HTTPS": False,
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "POST_LOGIN_URI_SUCCESS": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "HOOK_GET_USER": "tests.e2e.test_app.callback:get_user_with_minimal_audiences_check",
            },
        },
    )
    def test_06_selenium_minimal_audience_checks(self, *args):
        """
        Check that a minimal audience check can be performed to prevent access for some users.

        @see tests.e2e.test_app.callback:get_user_with_minimal_audiences_check
        """
        timeout = 5
        login_location = reverse("test_login")
        success_location = reverse("test_success")
        post_logout_location = reverse("test_logout_done")
        start_url = f"{self.live_server_url}{login_location}"
        ok_url = f"{self.live_server_url}{success_location}"
        end_url = f"{self.live_server_url}{post_logout_location}"
        self.wait = WebDriverWait(self.selenium, timeout)

        # user1 login is OK, resource access success
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user1",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)
        self._selenium_logout(end_url)

        # user_limit_app1 has access to app1 and app1-api, aud will be app1-api
        # should be OK here
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user_limit_app1",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        self.assertTrue(
            "message: user_limit_app1@example.com is logged in." in bodyText
        )

        self._selenium_logout(end_url)

        # WARRN: FAILURE to detect bad user here, but that's because the HOOK_USER used
        # is not good enough for Keycloak, a ressource_access check would be better.
        # user_limit_app2 login Will NOT FAIL
        # as our 'aud' check is not sufficient to detect that, sad...
        # since keycloak decided to remove the current client_di in 'aud' in access_tokens
        # that's hard to detect this type of users from access_tokens without test resource_access
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user_limit_app2",
            "passwd2",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # Check the session message is shown
        self.assertTrue(
            "message: user_limit_app2@example.com is logged in." in bodyText
        )
        self._selenium_logout(end_url)

        # And then test the user with only one app access
        # to ensure that the 'aud' token is still present for him even if the audience is just
        # the present app.
        self._selenium_sso_login(
            start_url,
            ok_url,
            "user_app1_only",
            "passwd1",
            active_sso_session=False,
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # Check the session message is shown
        self.assertTrue("message: user_app1_only@example.com is logged in." in bodyText)
        self._selenium_logout(end_url)
