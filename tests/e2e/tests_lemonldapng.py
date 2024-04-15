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

from tests.e2e.utils import OIDCE2ELemonLdapNgTestCase

# HTTP debug for requests
http_client.HTTPConnection.debuglevel = 1


class LemonLDAPTestCase(OIDCE2ELemonLdapNgTestCase):
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

    def test_00_login_page_redirects_to_lemonldap_sso(self, *args):
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
        # we should get something like http://localhost:8070/oauth2/authorize
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
        self.assertEqual(parsed.netloc, "localhost:8070")
        self.assertEqual(parsed.path, "/oauth2/authorize")
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

            username_input = self.selenium.find_element(By.NAME, "user")
            username_input.send_keys(user)
            password_input = self.selenium.find_element(By.NAME, "password")
            password_input.send_keys(password)
            self.selenium.find_element(
                By.XPATH, '//form[@id="lform"]//button[contains(@class, "btn-success")]'
            ).click()
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
        self._selenium_sso_login(start_url, end_url, "rtyler", "rtyler")

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are logged in
        self.assertTrue("You are logged in as rtyler@badwolf.org" in bodyText)
        self.assertFalse("You are logged out" in bodyText)
        # Check the session message is shown
        self.assertTrue("message: rtyler@badwolf.org is logged in." in bodyText)

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
            start_url, middle_url, "rtyler", "rtyler", active_sso_session=True
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
        print(bodyText)
        self.assertFalse("You are logged in as rtyler@badwolf.org" in bodyText)
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
                "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8070/",
                "OIDC_CLIENT_SECRET": "secret_app1",
                "OIDC_CALLBACK_PATH": "/callback",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
                "LOGIN_REDIRECTION_REQUIRES_HTTPS": False,
                "POST_LOGIN_URI_SUCCESS": "/test-success",
                "POST_LOGIN_URI_FAILURE": "/test-failure",
                "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
                "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
                "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
                "LOGOUT_QUERY_STRING_EXTRA_PARAMETERS_DICT": {"confirm": 1},
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
        # previous test destroyed the SSO session, we need to reconnect
        self._selenium_sso_login(
            start_url, middle_url, "rtyler", "rtyler", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # print(bodyText)

        # Check the session message is shown
        self.assertTrue("message: rtyler@badwolf.org is logged in." in bodyText)
        # Check the CALLBACK session message is also shown
        self.assertTrue("login_callback for : rtyler" in bodyText)

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
        self.assertTrue("Logout Callback for rtyler@badwolf.org." in bodyText)

    # @override_settings(
    #    DJANGO_PYOIDC={
    #        "sso1": {
    #            "OIDC_CLIENT_ID": "bad_client_id",
    #            "CACHE_DJANGO_BACKEND": "default",
    #            "OIDC_PROVIDER_DISCOVERY_URI": "http://localhost:8070/",
    #            "OIDC_CLIENT_SECRET": "secret_app1",
    #            "OIDC_CALLBACK_PATH": "/callback",
    #            "POST_LOGOUT_REDIRECT_URI": "/test-logout-done",
    #            "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["testserver"],
    #            "LOGIN_REDIRECTION_REQUIRES_HTTPS": False,
    #            "POST_LOGIN_URI_SUCCESS": "/test-success",
    #            "POST_LOGIN_URI_FAILURE": "/test-failure",
    #        },
    #    },
    # )
    # def test_04_selenium_sso_failed_login(self, *args):
    #    """
    #    Test a failed SSO login (bad client)
    #    """
    #    timeout = 30
    #    login_url = reverse("test_login")
    #    start_url = f"{self.live_server_url}{login_url}"
    #    wait = WebDriverWait(self.selenium, timeout)
    #    # wait ->
    #    #   EC.url_changes('a') // anything but a
    #    #   EC.url_contains('')
    #    #   EC.url_matches(pattern)
    #    #   EC.title_contains('')
    #    #   EC.title_is('')
    #    #   EC.url_to_be('') // exact


#
#    self.selenium.get(start_url)
#    # wait for the SSO redirection
#    wait.until(EC.url_changes(start_url))
#
#    bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
#    # check the SSO rejected our client id
#    self.assertTrue("We are sorry..." in bodyText)
#    self.assertTrue("Invalid parameter: redirect_uri" in bodyText)
#
#
