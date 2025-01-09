import http.client as http_client
import logging
import time
from urllib.parse import parse_qs, urlparse

import requests
from django.urls import reverse
from selenium.webdriver import FirefoxProfile
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from tests.e2e.utils import OIDCE2EKeycloakTestCase

logger = logging.getLogger(__name__)


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
        options.profile = profile
        cls.selenium = WebDriver(options=options)
        # cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()

    def test_001_m2m_client_credential_success(self, *args):
        """
        Check that we can request the API using a 'service account'.

        We use a 'service account', so we are an external M2M client
        in this situation, we do not use the Django OIDC credentials
        but the creds of a service account, as would be done by an external
        application in a B2B call.
        """

        sso_url = (
            "http://localhost:8080/auth/realms/realm1/protocol/openid-connect/token"
        )
        params = {
            "client_id": "app_m2m1",
            "client_secret": "secret_app-m2m1",
            "grant_type": "client_credentials",
        }
        print("sending M2M Login Request")
        response = requests.post(sso_url, data=params)
        # failing the test in case of bad HTTP status
        response.raise_for_status()

        print("Auth success")
        data = response.json()
        access_token = data["access_token"]

        api_url = f"{self.live_server_url}/api/users"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        print("sending API Request with access token")
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        content = response.text
        self.assertIn('"username":"service-account-app_m2m1"', content)

    def test_002_m2m_client_credential_forbidden(self, *args):
        """
        Check that we can request the API using a 'service account' and be rejected.

        The client used here does not have access to the same scope as the client
        used in the API. THe group and roles are OK, but not the scope. So Keycloak
        will not add the right audience in the token and we should be rejected.
        """

        sso_url = (
            "http://localhost:8080/auth/realms/realm1/protocol/openid-connect/token"
        )
        params = {
            "client_id": "app2_m2m2",
            "client_secret": "secret_app2-m2m2",
            "grant_type": "client_credentials",
        }
        print("sending M2M Login Request")
        response = requests.post(sso_url, data=params)
        # failing the test in case of bad HTTP status
        response.raise_for_status()

        print("Auth success")
        data = response.json()
        access_token = data["access_token"]

        api_url = f"{self.live_server_url}/api/users"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        print("sending API Request with access token, should get a 403 Forbidden.")
        response = requests.get(api_url, headers=headers)
        self.assertEqual(403, response.status_code)

    def test_003_m2m_anonymous_api_access(self, *args):

        # auth part is forbidden
        api_url = f"{self.live_server_url}/api/users"
        response = requests.get(api_url)
        self.assertEqual(403, response.status_code)

        # public part is OK
        api_url = f"{self.live_server_url}/api/publics"
        print("sending anonymous API Request.")
        response = requests.get(api_url)
        response.raise_for_status()
        content = response.text
        self.assertIn("[]", content)

    def test_100_login_page_redirects_to_keycloak_sso(self, *args):
        """
        Test that accessing login callback redirects to the SSO server.
        """
        self.selenium.delete_all_cookies()
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        client = requests

        print(f"Running Django on {self.live_server_url}")

        login_url = reverse("e2e_test_login_1")
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
        self.assertEqual(qs["redirect_uri"][0], f"{self.live_server_url}/callback-1/")
        self.assertEqual(qs["response_type"][0], "code")
        self.assertEqual(qs["scope"][0], "openid")
        self.assertTrue(qs["state"][0])
        self.assertTrue(qs["nonce"][0])

    def _selenium_front_sso_login(self, user, password):
        front_url = "http://localhost:9999"
        self.selenium.get(front_url)
        WebDriverWait(self.selenium, 30).until(
            EC.element_to_be_clickable((By.ID, "loginBtn"))
        ).click()
        # self.selenium.find_element(By.ID, "loginBtn").click()
        self.wait.until(EC.url_changes(front_url))
        username_input = self.selenium.find_element(By.NAME, "username")
        username_input.send_keys(user)
        password_input = self.selenium.find_element(By.NAME, "password")
        password_input.send_keys(password)
        self.selenium.find_element(By.ID, "kc-login").click()
        self.wait.until(EC.url_matches(front_url))

    def _selenium_front_logout(self):
        front_url = "http://localhost:9999"
        WebDriverWait(self.selenium, 30).until(
            EC.element_to_be_clickable((By.ID, "logoutBtn"))
        ).click()
        self.wait.until(EC.url_matches(front_url))
        bodyText = self.selenium.find_element(By.ID, "message").text
        # check we are NOT logged in
        self.assertEqual("", bodyText)

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

            # Uncomment if you want time to detect why it's not working
            WebDriverWait(self.selenium, 30).until(
                EC.presence_of_element_located((By.NAME, "username"))
            )

            username_input = self.selenium.find_element(
                By.NAME,
                "username",
            )
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
        # FIXME: ensure the anon logout worked for real
        # WebDriverWait(self.selenium, 30).until(
        #     EC.presence_of_element_located((By.NAME, "username"))
        # )
        # self.wait.until(EC.url_matches(logout_end_url))

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

    def test_101_selenium_sso_login(self, *args):
        """
        Test a complete working OIDC login/logout.
        """
        self.selenium.delete_all_cookies()
        timeout = 5
        login_url = reverse("e2e_test_login_1")
        success_url = reverse("e2e_test_success_1")
        post_logout_url = reverse("e2e_test_logout_done_1")
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

    def _test_102_selenium_sso_login_relogin_and_logout_with_mixed_clients_id(
        self, *args
    ):
        """
        Test using sso1 and sso2 with different client_id on same sso server.
        """
        self.selenium.delete_all_cookies()
        timeout = 5
        login_url = reverse("e2e_test_login_2")
        success_url = reverse("e2e_test_success_2")
        start_url = f"{self.live_server_url}{login_url}"
        middle_url = f"{self.live_server_url}{success_url}"
        self.wait = WebDriverWait(self.selenium, timeout)

        # LOGIN 1 on sso2
        self._selenium_sso_login(
            start_url, middle_url, "user1", "passwd1", active_sso_session=False
        )

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text
        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

        # Check the session message is shown
        self.assertTrue("message: user1@example.com is logged in." in bodyText)

        # LOGIN 2: reusing existing session on sso2
        self._selenium_sso_login(start_url, middle_url, "", "", active_sso_session=True)

        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

        # LOGIN 3: using sso1, different client_id on same sso
        # we should get automatcally connected without a form submission
        login_url1 = reverse("e2e_test_login_1")
        success_url1 = reverse("e2e_test_success_1")
        post_logout_url1 = reverse("e2e_test_logout_done_1")
        start_url1 = f"{self.live_server_url}{login_url1}"
        middle_url1 = f"{self.live_server_url}{success_url1}"
        end_url1 = f"{self.live_server_url}{post_logout_url1}"
        self._selenium_sso_login(
            start_url1, middle_url1, "", "", active_sso_session=True
        )

        # check we are logged in
        self.assertTrue("You are logged in as user1@example.com" in bodyText)
        self.assertFalse("You are logged out" in bodyText)

        # check we have the logout link
        self.assertFalse("OIDC-LOGIN-LINK" in bodyText)
        self.assertTrue("OIDC-LOGOUT-LINK" in bodyText)

        # click logout
        self.selenium.find_element(By.ID, "oidc-logout-link").click()

        self.wait.until(EC.url_matches(end_url1))

        bodyText = self.selenium.find_element(By.TAG_NAME, "body").text

        # check we are NOT logged in
        self.assertFalse("You are logged in as user1@example.com" in bodyText)
        self.assertTrue("You are logged out" in bodyText)

        # Check the logout view message is shown
        self.assertTrue("message: post logout view." in bodyText)
        # check we have the login link
        self.assertTrue("OIDC-LOGIN-LINK" in bodyText)
        self.assertFalse("OIDC-LOGOUT-LINK" in bodyText)

    def _test_103_selenium_sso_login__relogin_and_logout(self, *args):
        """
        Test a login/logout session, adding a re-login on existing session in the middle
        """
        self.selenium.delete_all_cookies()
        timeout = 5
        login_url = reverse("e2e_test_login_1")
        success_url = reverse("e2e_test_success_1")
        post_logout_url = reverse("e2e_test_logout_done_1")
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

    def _test_104_selenium_sso_session_with_callbacks(self, *args):
        self.selenium.delete_all_cookies()
        timeout = 5
        login_url = reverse("e2e_test_login_1")
        success_url = reverse("e2e_test_success_1")
        post_logout_url = reverse("e2e_test_logout_done_1")
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

    def _test_105_selenium_sso_failed_login(self, *args):
        """
        Test a failed SSO login (bad client_id: bad_client_id)
        """
        self.selenium.delete_all_cookies()
        timeout = 30
        login_url = reverse("e2e_test_login_3")
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
        logger.error("*****************************")
        logger.error(bodyText)
        self.assertTrue("We are sorry..." in bodyText)

    def test_106_selenium_ressource_access_checks(self, *args):
        """
        Check that a resource access check can be performed to prevent access for some users.

        @see tests.e2e.test_app.callback:get_user_with_resource_access_check
        """
        self.selenium.delete_all_cookies()
        timeout = 5
        login_location = reverse("e2e_test_login_4")
        success_location = reverse("e2e_test_success_4")
        failure_location = reverse("e2e_test_failure_4")
        post_logout_location = reverse("e2e_test_logout_done_4")
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

    def test_107_selenium_minimal_audience_checks(self, *args):
        """
        Check that a minimal audience check can be performed to prevent access for some users.
        @see tests.e2e.test_app.callback:get_user_with_minimal_audiences_check
        """
        self.selenium.delete_all_cookies()
        timeout = 5
        login_location = reverse("e2e_test_login_5")
        success_location = reverse("e2e_test_success_5")
        post_logout_location = reverse("e2e_test_logout_done_5")
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

    def test_201_selenium_front_app_api_call(self, *args):
        """
        Check that a test front app can make an OIDC API call.
        """
        timeout = 60
        self.wait = WebDriverWait(self.selenium, timeout)

        # user1 login is OK, resource access success
        self._selenium_front_sso_login("user1", "passwd1")
        # let the page reloads after login fill the user session stuff
        time.sleep(3)
        bodyText = self.selenium.find_element(By.ID, "message").get_attribute(
            "innerHTML"
        )
        self.assertTrue("User: user1" in bodyText)

        WebDriverWait(self.selenium, 30).until(
            EC.element_to_be_clickable((By.ID, "securedBtn"))
        ).click()

        # let the ajax stuff behave
        time.sleep(3)
        bodyText = self.selenium.find_element(By.ID, "message").get_attribute(
            "innerHTML"
        )
        logger.error(bodyText)
        self.assertTrue("user1@example.com" in bodyText)

        # FIXME: there a selenium issue in the logout btn selection...
        self._selenium_front_logout()

        # After logout, launch unauthorized ajax call
        WebDriverWait(self.selenium, 30).until(
            EC.element_to_be_clickable((By.ID, "securedBtn"))
        ).click()
        # let the ajax stuff behave
        time.sleep(3)
        bodyText = self.selenium.find_element(By.ID, "message").get_attribute(
            "innerHTML"
        )
        self.assertTrue("Request Forbidden" in bodyText)
