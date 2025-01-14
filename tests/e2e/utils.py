import contextlib
import logging
import os
import subprocess
import time
from typing import Generator
from unittest.mock import MagicMock, patch

from django.core.servers.basehttp import ThreadedWSGIServer, WSGIRequestHandler
from django.test import override_settings
from django.test.testcases import LiveServerTestCase, LiveServerThread

logger = logging.getLogger(__name__)


class NotReadyException(Exception):
    pass


class OIDCE2ETestCase(LiveServerTestCase):

    docker_id = None
    workdir = None
    docker_workdir = None

    class VerboseLiveServerThread(LiveServerThread):
        def _create_server(self, connections_override=None):
            return ThreadedWSGIServer(
                (self.host, self.port),
                WSGIRequestHandler,
                allow_reuse_address=False,
                connections_override=connections_override,
            )

    server_thread_class = VerboseLiveServerThread


@override_settings(
    ALLOWED_HOSTS=["testserver"],
    STATIC_URL="/static",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    DJANGO_PYOIDC={
        "lemon1": {
            "provider_class": "LemonLDAPng2Provider",
            "client_id": "app1",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://localhost:8070/",
            "client_secret": "secret_app1",
            "oidc_callback_path": "/callback-ll-1",
            "post_logout_redirect_uri": "/test-ll-logout-done-1",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
            "post_login_uri_success": "/test-ll-success-1",
            "post_login_uri_failure": "/test-ll-failure-1",
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            # "oidc_logout_query_string_extra_parameters_dict": {"confirm": 1},
        },
    },
)
class OIDCE2ELemonLdapNgTestCase(OIDCE2ETestCase):
    @classmethod
    def setUpClass(cls):
        print(" *** Live Server Test Case Setup (LemonLdap::Ng) ***")
        super().setUpClass()

        cls.workdir = os.getcwd()
        print(f"Current workdir: {cls.workdir} ...")
        cls.docker_workdir = f"{cls.workdir}/tests/e2e/docker"
        os.chdir(cls.docker_workdir)
        cls.docker_id = None
        try:
            print("Building LemonLdap docker image...")
            subprocess.run(
                [
                    "docker",
                    "buildx",
                    "build",
                    "-f",
                    "Dockerfile-lemonldap",
                    "-t",
                    "oidc-test-lemonldap-image",
                    ".",
                ]
            )
            print("Running LemonLdap docker image...")
            command = (
                "docker run"
                " --detach --rm -it"
                " -p 8070:8070"
                " -p 8071:8071"
                " -p 8072:8072"
                " -p 8073:8073"
                " -p 8999:9000"
                " -e SSODOMAIN=localhost"
                " -e LOGLEVEL=debug"
                " -e PORTAL_HOSTNAME=localhost:8070"
                " -e MANAGER_HOSTNAME=localhost:8071"
                " -e HANDLER_HOSTNAME=localhost:8072"
                " -e TEST1_HOSTNAME=localhost:8073"
                " -e TEST2_HOSTNAME=localhost.localdomain:8073"
                " oidc-test-lemonldap-image"
            )
            res = subprocess.run(
                command, shell=True, text=True, check=True, capture_output=True
            )
            cls.docker_id = res.stdout.partition("\n")[0]
            print(cls.docker_id)
        except subprocess.CalledProcessError as e:
            print(
                f"Error while launching LemonLdap docker container. errcode: {e.returncode}."
            )
            print(e.stderr)
            if e.returncode == 125:
                print(" +----------|  |--------------------------+ ")
                print(" +---------_|  |_-------------------------+ ")
                print(" +---------\    /-------------------------+ ")  # noqa
                print(" +----------\  /--------------------------+ ")  # noqa
                print(" +-----------\/---------------------------+ ")  # noqa
                print(
                    "   + Try removing any previous LemonLdap image running using this command:"
                )
                print(
                    '   docker stop $(docker ps -a -q --filter ancestor=oidc-test-lemonldap-image --format="{{.ID}}")'
                )
                print(
                    "   + Check also you have no service running on localhost port 8070, 8071, 8072 and 8073."
                )
                print(" +---------------------------------------+ ")
                print(" +---------------------------------------+ ")
                print(" +---------------------------------------+ ")
        finally:
            os.chdir(cls.workdir)
        if cls.docker_id:
            cls.loadLemonLDAPFixtures()
        else:
            raise RuntimeError("Cannot build the context environnement with docker.")

    @classmethod
    def loadLemonLDAPFixtures(cls):
        print(f"Running Django on {cls.live_server_url}")

        print(" + get LemonLDAP info (testing it's up)")
        retry = 0
        ok = False
        while retry < 15 and not ok:
            try:
                cls.docker_lemonldap_command(
                    "/usr/share/lemonldap-ng/bin/lemonldap-ng-cli info"
                )
                ok = True
            except NotReadyException:
                print("   ->  waiting for lemonldap startup...")
                time.sleep(2)
            finally:
                retry += 1

        if retry == 15:
            print(" Aborting, seems LemonLdap-ng is not starting fast enough.")
            raise RuntimeError("Cannot reach lemonldap via cli in time.")

        print(" + Set Global Configuration.")
        cls.docker_lemonldap_command(
            """/usr/share/lemonldap-ng/bin/lemonldap-ng-cli\
    -yes 1 \
    -safe 1\
      set \
        portal http://localhost:8070/ \
        mailUrl http://localhost:8070/resetpwd \
        registerUrl http://localhost:8070/register \
        https 0 \
        securedCookie 0 """
        )

        print(" + Enable OIDC.")
        cls.docker_lemonldap_command(
            """/usr/share/lemonldap-ng/bin/lemonldap-ng-cli \
    -yes 1 \
    -safe 1\
    set \
        issuerDBOpenIDConnectActivation 1 \
        issuerDBOpenIDConnectPath '^/oauth2/' """
        )

        print(" + Create RSA key")
        cls.docker_lemonldap_command(
            """rm -f /tmp/oidc*.key \
    && openssl genrsa -out /tmp/oidc.key 4096 \
    && openssl rsa -pubout \
        -in /tmp/oidc.key \
        -out /tmp/oidc_pub.key \
    && ls -alh /tmp/ \
    && PRIVATE=$(cat /tmp/oidc.key) \
    && PUBLIC=$(cat /tmp/oidc_pub.key) \
    && /usr/share/lemonldap-ng/bin/lemonldap-ng-cli -yes 1 \
      set \
        oidcServicePrivateKeySig "${PRIVATE}" \
    && /usr/share/lemonldap-ng/bin/lemonldap-ng-cli -yes 1 \
      set \
        oidcServicePublicKeySig "${PUBLIC}" \
    && /usr/share/lemonldap-ng/bin/lemonldap-ng-cli -yes 1 \
      set \
        oidcServiceKeyIdSig "somethingsomething" """
        )

        print(" + Create client applications.")
        cls.registerClient(
            "app1",
            "secret_app1",
            cls.live_server_url,
            callback_url=f"{cls.live_server_url}/callback-ll-1",
            post_login_url=f"{cls.live_server_url}/test-ll-logout-done-1",
        )
        cls.registerClient(
            "app1-api",
            "secret_app1-api",
            cls.live_server_url,
            bearerOnly=True,
        )
        cls.registerClient(
            "app2-full",
            "secret_app2-full",
            cls.live_server_url,
            callback_url=f"{cls.live_server_url}/callback-ll-2",
            post_login_url=f"{cls.live_server_url}/test-ll-logout-done-2",
        )
        cls.registerClient(
            "app2-api", "secret_app2-api", cls.live_server_url, bearerOnly=True
        )
        # Default demo users:
        # rtyler :: rtyler
        # msmith :: msmith
        # dwho :: dwho (administrator)

    @classmethod
    def tearDownClass(cls):
        print(" *** Live Server Test Case : Teardown ***")

        # print(" + Debug LemonLdap conf.")
        # conf = cls.docker_lemonldap_command("/usr/share/lemonldap-ng/bin/lemonldap-ng-cli save > /tmp/conf && cat /tmp/conf")
        # print(conf.stdout)

        print("Removing lemonldap docker image...")

        os.chdir(cls.docker_workdir)
        try:
            cmd = (
                "docker stop $("
                'docker ps -a -q --filter ancestor=oidc-test-lemonldap-image --format="{{.ID}}"'
                ")"
            )
            subprocess.run(cmd, shell=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error stopping lemonldap container: {e.returncode}.")
            print(e.stderr)
        finally:
            os.chdir(cls.workdir)

    @classmethod
    def docker_lemonldap_command(cls, command: str):
        logger.debug(f"Docker LemonLDAP command: {command}")
        # TEMP
        print(f"Docker LemonLDAP command: {command}")
        cmd_prefix = f"docker exec -i {cls.docker_id}"
        # command = command.replace('"', '"')
        final_command = f"{cmd_prefix} /bin/bash <<'EOF'\n{command}\nEOF"
        # print(final_command)
        os.chdir(cls.docker_workdir)
        output = ""
        try:
            output = subprocess.run(
                final_command,
                shell=True,
                text=True,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            errors = e.stderr.split("\n")
            last_error = errors[-1:][0]
            if last_error == "" and len(errors) > 1:
                last_error = errors[-2:-1][0]
            # print(f"Last Error: >{last_error}<")
            print(
                f"Error while launching command on the keycloak container. errcode: {e.returncode}."
            )
            print(e.stderr)
        finally:
            os.chdir(cls.workdir)
        return output

    @classmethod
    def registerClient(
        cls, name, secret, url, callback_url="", post_login_url="", bearerOnly=False
    ):
        redirectUris = "''" if bearerOnly else f"'{callback_url}'"
        logoutRedirectUris = "''" if bearerOnly else f"'{post_login_url}'"

        cls.docker_lemonldap_command(
            f"""usr/share/lemonldap-ng/bin/lemonldap-ng-cli -yes 1 \
    addKey \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsClientID {name} \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsClientSecret {secret} \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsPublic 0 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsRedirectUris {redirectUris} \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsPostLogoutRedirectUris '{logoutRedirectUris}' \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsIDTokenSignAlg RS512 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsIDTokenExpiration 3600 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsAccessTokenExpiration 3600 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsAllowClientCredentialsGrant 0 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsAllowPasswordGrant 0 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsoidcRPMetaDataOptionsRefreshToken 1 \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsLogoutType front \
        oidcRPMetaDataOptions/{name} oidcRPMetaDataOptionsBypassConsent 1 \
           """
        )
        cls.docker_lemonldap_command(
            f""" /usr/share/lemonldap-ng/bin/lemonldap-ng-cli -yes 1 \
    addKey \
        oidcRPMetaDataExportedVars/{name} email mail \
        oidcRPMetaDataExportedVars/{name} family_name sn \
        oidcRPMetaDataExportedVars/{name} name cn \
           """
        )


@override_settings(
    ALLOWED_HOSTS=["testserver"],
    STATIC_URL="/static",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "corsheaders.middleware.CorsMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    DJANGO_PYOIDC={
        "sso1": {
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
            "client_id": "app1",
            "client_secret": "secret_app1",
            "cache_django_backend": "default",
            "callback_uri_name": "e2e_test_callback_1",
            "post_login_uri_success": "/test-success-1",
            "post_login_uri_failure": "/test-failure-1",
            "post_logout_redirect_uri": "/test-logout-done-1",
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
        },
        # sso2 use a different client_id
        "sso2": {
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
            "client_id": "app2-full",
            "client_secret": "secret_app2-full",
            "cache_django_backend": "default",
            "callback_uri_name": "e2e_test_callback_2",
            "post_login_uri_success": "/test-success-2",
            "post_login_uri_failure": "/test-failure-2",
            "post_logout_redirect_uri": "/test-logout-done-2",
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
            "hook_get_user": "tests.e2e.test_app.callback:get_user_with_resource_access_check",
        },
        # broken client_id
        "sso3": {
            "client_id": "bad_client_id",
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
            "client_secret": "secret_app1",
            "cache_django_backend": "default",
            "callback_uri_name": "e2e_test_callback_3",
            "post_login_uri_success": "/test-success-3",
            "post_login_uri_failure": "/test-failure-3",
            "post_logout_redirect_uri": "/test-logout-done-3",
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
        },
        # hook_get_user
        "sso4": {
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
            "client_id": "app1",
            "client_secret": "secret_app1",
            "cache_django_backend": "default",
            "callback_uri_name": "e2e_test_callback_4",
            "post_login_uri_success": "/test-success-4",
            "post_login_uri_failure": "/test-failure-4",
            "post_logout_redirect_uri": "/test-logout-done-4",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            "hook_get_user": "tests.e2e.test_app.callback:get_user_with_resource_access_check",
            "use_introspection_on_access_tokens": True,
        },
        # hook_get_user
        "sso5": {
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
            "client_id": "app1",
            "client_secret": "secret_app1",
            "cache_django_backend": "default",
            "callback_uri_name": "e2e_test_callback_5",
            "post_login_uri_success": "/test-success-5",
            "post_login_uri_failure": "/test-failure-5",
            "post_logout_redirect_uri": "/test-logout-done-5",
            "login_uris_redirect_allowed_hosts": ["testserver"],
            "login_redirection_requires_https": False,
            "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
            "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            "use_introspection_on_access_tokens": True,
            "hook_get_user": "tests.e2e.test_app.callback:get_user_with_minimal_audiences_check",
        },
        # API
        "drf": {
            "client_id": "app1-api",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://localhost:8080/auth/realms/realm1",
            "client_secret": "secret_app1-api",
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://localhost:8080/auth/",
            "keycloak_realm": "realm1",
        },
    },
)
class OIDCE2EKeycloakTestCase(OIDCE2ETestCase):
    @classmethod
    def setUpClass(cls):
        print(" *** Live Server Test Case Setup (Keycloak) ***")
        super().setUpClass()

        cls.workdir = os.getcwd()
        print(f"Current workdir: {cls.workdir} ...")
        cls.docker_workdir = f"{cls.workdir}/tests/e2e/docker"
        os.chdir(cls.docker_workdir)
        cls.docker_id = None
        try:
            print("Building keycloak docker image...")
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-f",
                    "Dockerfile-keycloak",
                    "-t",
                    "oidc-test-keycloak-image",
                    ".",
                ]
            )
            print("Running keycloak docker image...")
            command = (
                "docker run"
                " --detach --rm -it"
                " -p 8080:8080"
                " -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin"
                " oidc-test-keycloak-image"
            )
            res = subprocess.run(
                command, shell=True, text=True, check=True, capture_output=True
            )
            cls.docker_id = res.stdout.partition("\n")[0]
            print(cls.docker_id)

            cls.docker_front_workdir = f"{cls.workdir}/tests/e2e/front_test_app"
            os.chdir(cls.docker_front_workdir)
            print("Building front docker image...")
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-f",
                    "Dockerfile",
                    "-t",
                    "oidc-test-front-image",
                    ".",
                ]
            )
            command = (
                "docker run"
                " --detach --rm -it"
                " -p 9999:9999"
                f" -e KEYCLOAK_URL=http://localhost:8080/auth -e BACKEND_URL={cls.live_server_url}"
                " oidc-test-front-image"
            )
            subprocess.run(
                command, shell=True, text=True, check=True, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            print(
                f"Error while launching keycloak docker container. errcode: {e.returncode}."
            )
            print(e.stderr)
            if e.returncode == 125:
                print(" +----------|  |--------------------------+ ")
                print(" +---------_|  |_-------------------------+ ")
                print(" +---------\    /-------------------------+ ")  # noqa
                print(" +----------\  /--------------------------+ ")  # noqa
                print(" +-----------\/---------------------------+ ")  # noqa
                print(
                    "   + Try removing any previous Keycloak and front images running using these commands:"
                )
                print(
                    '   docker stop $(docker ps -a -q --filter ancestor=oidc-test-keycloak-image --format="{{.ID}}")'
                )
                print(
                    '   docker stop $(docker ps -a -q --filter ancestor=oidc-test-front-image --format="{{.ID}}")'
                )
                print("   + Check also you have no service running on localhost:8080.")
                print(" +---------------------------------------+ ")
                print(" +---------------------------------------+ ")
                print(" +---------------------------------------+ ")
        finally:
            os.chdir(cls.workdir)
        if cls.docker_id:
            cls.loadKeycloakFixtures()
        else:
            raise RuntimeError("Cannot build the context environnement with docker.")

    @classmethod
    def loadKeycloakFixtures(cls):
        print(f"Running Django on {cls.live_server_url}")

        print(" + connect as Keycloak admin")
        retry = 0
        ok = False
        while retry < 15 and not ok:
            try:
                cls.docker_keycloak_command(
                    "bin/kcadm.sh config credentials --server http://127.0.0.1:8080/auth/ --realm master --user admin --password admin"
                )
                ok = True
            except NotReadyException:
                print("   ->  waiting for keycloak startup...")
                time.sleep(2)
            finally:
                retry += 1

        if retry == 15:
            print(" Aborting, seems Keycloak is not starting fast enough.")
            raise RuntimeError("Cannot reach Keycloak admin in time.")

        print(" + Create test realm")
        cls.docker_keycloak_command(
            "bin/kcadm.sh create realms -s realm=realm1 -s enabled=true"
        )

        print(" + Remove offline authorization default role affectation.")
        cls.docker_keycloak_command(
            "bin/kcadm.sh remove-roles --rname default-roles-realm1 --rolename offline_access -r realm1"
        )

        print(" + Create client applications.")
        app1_id = cls.registerClient(
            "app1",
            "secret_app1",
            cls.live_server_url,
            serviceAccount=False,
            channelLogoutUrl=f"{cls.live_server_url}/back_channel_logout-1/",
        )
        app1_api_id = cls.registerClient(
            "app1-api",
            "secret_app1-api",
            cls.live_server_url,
            bearerOnly=True,
            serviceAccount=False,
        )
        app1_front_id = cls.registerClient(
            "app1-front",
            None,
            "http://localhost:9999",
            bearerOnly=False,
            serviceAccount=False,
            channelLogoutUrl="http://localhost:9999",
        )
        app_m2m1_id = cls.registerClient(
            "app_m2m1",
            "secret_app-m2m1",
            cls.live_server_url,
            bearerOnly=False,
            serviceAccount=True,
        )
        app2_m2m2_id = cls.registerClient(
            "app2_m2m2",
            "secret_app2-m2m2",
            cls.live_server_url,
            bearerOnly=False,
            serviceAccount=True,
        )
        app2_full_id = cls.registerClient(
            "app2-full",
            "secret_app2-full",
            cls.live_server_url,
            bearerOnly=False,
            channelLogoutUrl=f"{cls.live_server_url}/back_channel_logout-2/",
        )
        app2_api_id = cls.registerClient(
            "app2-api", "secret_app2-api", cls.live_server_url, bearerOnly=True
        )

        print(" + Create client applications access roles.")
        app1_role = cls.registerClientRole(app1_id, "AccessApp1")
        app1_bis_role = cls.registerClientRole(app1_api_id, "AccessApp1API")
        app1_front_role = cls.registerClientRole(app1_front_id, "AccessApp1Front")
        app2_full_role = cls.registerClientRole(app2_full_id, "AccessApp2Full")
        app2_api_role = cls.registerClientRole(app2_api_id, "AccessApp2API")

        print(" + Create Client Scopes.")
        id_zone_app1 = cls.registerClientScope(
            "zone-app1",
            [
                {app1_id: app1_role},
                {app1_api_id: app1_bis_role},
                {app1_front_id: app1_front_role},
            ],
        )
        id_zone_app2 = cls.registerClientScope(
            "zone-app2",
            [
                {app2_full_id: app2_full_role},
                {app2_api_id: app2_api_role},
            ],
        )

        print(" + Update applications client scopes")
        cls.addClientScopeForClient(app1_id, id_zone_app1)
        cls.addClientScopeForClient(app1_api_id, id_zone_app1)
        cls.addClientScopeForClient(app1_front_id, id_zone_app1)
        cls.addClientScopeForClient(app_m2m1_id, id_zone_app1)
        cls.addClientScopeForClient(app2_full_id, id_zone_app2)
        cls.addClientScopeForClient(app2_api_id, id_zone_app2)
        cls.addClientScopeForClient(app2_m2m2_id, id_zone_app2)

        print(" + Create Groups.")
        gApp1 = cls.registerGroup(
            "App1",
            [
                {"app1": "AccessApp1"},
                {"app1-api": "AccessApp1API"},
                {"app1-front": "AccessApp1Front"},
            ],
        )
        gApp2 = cls.registerGroup(
            "App2",
            [
                {"app2-full": "AccessApp2Full"},
                {"app2-api": "AccessApp2API"},
            ],
        )
        gApp1Restricted = cls.registerGroup(
            "App1Restricted",
            [
                {"app1": "AccessApp1"},
            ],
        )
        gm2m = cls.registerGroup(
            "GroupM2M",
            [
                {"app1": "AccessApp1"},
                {"app1-api": "AccessApp1API"},
                {"app2-full": "AccessApp2Full"},
                {"app2-api": "AccessApp2API"},
            ],
        )
        gAppAll = cls.registerGroup(
            "AllApps",
            [
                {"app1": "AccessApp1"},
                {"app1-api": "AccessApp1API"},
                {"app1-front": "AccessApp1Front"},
                {"app2-full": "AccessApp2Full"},
                {"app2-api": "AccessApp2API"},
            ],
        )
        print(" + Link service account users to groups")
        m2m_user1 = cls.searchUser("service-account-app_m2m1")
        m2m_user2 = cls.searchUser("service-account-app2_m2m2")
        cls.add_user_to_group(m2m_user1, gm2m)
        cls.add_user_to_group(m2m_user2, gm2m)

        print(" + Create users.")
        cls.registerUser(
            "user1",
            "passwd1",
            groups=[
                gAppAll,
            ],
        )
        cls.registerUser(
            "user_limit_app2",
            "passwd2",
            groups=[
                gApp2,
            ],
        )
        cls.registerUser(
            "user_limit_app1",
            "passwd1",
            groups=[
                gApp1,
            ],
        )
        cls.registerUser(
            "user_app1_only",
            "passwd1",
            groups=[gApp1Restricted],
        )

    @classmethod
    def tearDownClass(cls):
        print(" *** Live Server Test Case : Teardown ***")

        print("Extracting keycloak logs before stopping...")
        os.chdir(cls.docker_workdir)
        try:
            subprocess.run(
                f"docker logs {cls.docker_id}", shell=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Error while retrieving keycloak docker logs: {e.returncode}.")
            print(e.stderr)
        finally:
            os.chdir(cls.workdir)

        print("Removing keycloak docker image...")

        os.chdir(cls.docker_workdir)
        try:
            cmd = (
                "docker stop $("
                'docker ps -a -q --filter ancestor=oidc-test-keycloak-image --format="{{.ID}}"'
                ")"
            )
            subprocess.run(cmd, shell=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error stopping keycloak container: {e.returncode}.")
            print(e.stderr)
        finally:
            os.chdir(cls.docker_front_workdir)
            print("Removing front docker image...")
            try:
                cmd = (
                    "docker stop $("
                    'docker ps -a -q --filter ancestor=oidc-test-front-image --format="{{.ID}}"'
                    ")"
                )
                subprocess.run(cmd, shell=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error stopping front container: {e.returncode}.")
                print(e.stderr)
            finally:
                os.chdir(cls.workdir)

    @classmethod
    def docker_keycloak_command(cls, command: str):
        logger.debug(f"Docker Keycloak command: {command}")
        # print(f"Docker Keycloak command: {command}")
        cmd_prefix = f"docker exec {cls.docker_id}"
        command = command.replace('"', '"')
        final_command = f"{cmd_prefix} /bin/bash -c '{command}'"
        # print(final_command)
        os.chdir(cls.docker_workdir)
        output = ""
        try:
            output = subprocess.run(
                final_command,
                shell=True,
                text=True,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            errors = e.stderr.split("\n")
            last_error = errors[-1:][0]
            if last_error == "" and len(errors) > 1:
                last_error = errors[-2:-1][0]
            # print(f"Last Error: >{last_error}<")
            if e.returncode == 1 and last_error in [
                "Failed to send request - Connect to 127.0.0.1:8080 [/127.0.0.1] failed: Connection refused",
                "Failed to send request - Connect to 127.0.0.1:8080 [/127.0.0.1] failed: Connection refused (Connection refused)",
                "Invalid user credentials [invalid_grant]",
            ]:
                raise NotReadyException()
            else:
                print(
                    f"Error while launching command on the keycloak container. errcode: {e.returncode}."
                )
                print(e.stderr)
        finally:
            os.chdir(cls.workdir)
        return output

    @classmethod
    def add_user_to_group(cls, user_id, group):
        cls.docker_keycloak_command(
            f"bin/kcadm.sh update users/{user_id}/groups/{group} -r realm1"
        )

    @classmethod
    def searchUser(cls, user_name):
        output = cls.docker_keycloak_command(
            "bin/kcadm.sh get users -r realm1"
            f" -q username={user_name} --fields 'id,username'"
        )
        id = None
        cpt = 0
        prevline = ""
        for line in output.stdout.splitlines():
            if line == f'  "username" : "{user_name}"':
                cpt = cpt - 1
                id_line = prevline
                # line looks like '    "id": "42562-..-45646",'
                # we split on " and get 3rd value
                id = id_line.split('"')[3]
                break
            cpt += 1
            prevline = line
        return id

    @classmethod
    def registerClient(
        cls,
        name,
        secret,
        url,
        bearerOnly=False,
        serviceAccount=False,
        channelLogoutUrl="",
    ):
        if serviceAccount:
            bServiceAccountEnabled = "true"
            redirectUris = "[ ]"
            extraAttributes = (
                '"use.refresh.tokens": "true",'
                '"client_credentials.use_refresh_token": "false",'
                '"tls.client.certificate.bound.access.tokens": "false",'
                '"require.pushed.authorization.requests": "false",'
                '"acr.loa.map": "{}",'
                '"token.response.type.bearer.lower-case": "false",'
            )
            backchannelLogoutUrl = ""
            frontchannelLogoutUrl = ""
        else:

            bServiceAccountEnabled = "false"
            redirectUris = "[ ]" if bearerOnly else f'[ "{url}/*" ]'
            extraAttributes = ""
        bBearerOnly = "true" if bearerOnly else "false"
        bStandardFlowEnabled = "false" if bearerOnly else "true"
        if secret is None:
            public_line = '"publicClient" : true,'
            secret_line = ""
            frontch_line = '"frontchannelLogout" : true,'
            backchannelLogoutUrl = ""
            frontchannelLogoutUrl = channelLogoutUrl
        else:
            public_line = '"publicClient" : false,'
            frontch_line = '"frontchannelLogout" : false,'
            frontchannelLogoutUrl = ""
            backchannelLogoutUrl = channelLogoutUrl
            secret_line = (
                f'"clientAuthenticatorType" : "client-secret", "secret" : "{secret}",'
            )
        output = cls.docker_keycloak_command(
            f"""bin/kcadm.sh create clients -r realm1 -f - << EOF
{{
    "clientId": "{name}",
    "name": "{name}",
    "description": "{name}",
    "rootUrl": "{url}",
    "adminUrl" : "",
    "baseUrl" : "",
    "surrogateAuthRequired" : false,
    "enabled" : true,
    "alwaysDisplayInConsole" : false,
    {secret_line}
    "redirectUris" : {redirectUris},
    "webOrigins" : [ "+" ],
    "notBefore" : 0,
    "bearerOnly" : {bBearerOnly},
    "consentRequired" : false,
    "standardFlowEnabled" : {bStandardFlowEnabled},
    "implicitFlowEnabled" : false,
    "directAccessGrantsEnabled" : false,
    "serviceAccountsEnabled" : {bServiceAccountEnabled},
    {public_line}
    {frontch_line}
    "protocol" : "openid-connect",
    "attributes" : {{
      {extraAttributes}
      "oidc.ciba.grant.enabled" : "false",
      "post.logout.redirect.uris" : "+",
      "display.on.consent.screen" : "false",
      "oauth2.device.authorization.grant.enabled" : "false",
      "backchannel.logout.revoke.offline.tokens" : "false",
      "backchannel.logout.session.required" : "false",
      "backchannel.logout.url": "{backchannelLogoutUrl}",
      "frontchannel.logout.url": "{frontchannelLogoutUrl}"
    }},
    "authenticationFlowBindingOverrides" : {{ }},
    "fullScopeAllowed" : false,
    "defaultClientScopes" : [ "web-origins", "acr", "roles", "profile", "email" ],
    "optionalClientScopes" : [ "address", "phone" ]
}}
EOF"""
        )
        # output was in the form
        # "Created new client with id '0f5d0645-a7a7-4e88-adf8-b9e568025f5c'""
        # we need to extract the id from this message
        id = None
        if output.stderr[:18] == "Created new client":
            id = output.stderr.split(" ")[5].strip("'\r\n")
        return id

    @classmethod
    def addClientScopeForClient(cls, client_id, clientscope_id):
        cls.docker_keycloak_command(
            "bin/kcadm.sh update"
            f" clients/{client_id}/default-client-scopes/{clientscope_id}"
            " -r realm1"
        )

    @classmethod
    def registerClientRole(cls, client_id, role):
        output = cls.docker_keycloak_command(
            "bin/kcadm.sh create "
            f"clients/{client_id}/roles"
            " -r realm1"
            f" -s name={role}"
            " -o --fields id,name,composite,clientRole,containerId"
        )
        return output.stdout

    @classmethod
    def registerClientScope(cls, client_scope, role_mappings=[]):
        output = cls.docker_keycloak_command(
            f"""bin/kcadm.sh create client-scopes -r realm1 -f - << EOF
{{
    "name": "{client_scope}",
    "protocol" : "openid-connect",
    "description" : "{client_scope}",
    "attributes" : {{
      "include.in.token.scope" : "false",
      "display.on.consent.screen" : "false"
    }}
}}
EOF"""
        )
        # output was in the form
        # "Created new client-scope with id '0f5d0645-a7a7-4e88-adf8-b9e568025f5c'""
        # we need to extract the id from this message
        id = None
        if output.stderr[:18] == "Created new client":
            id = output.stderr.split(" ")[5].strip("'\r\n")
        if id:
            for role_mapping in role_mappings:
                for client_id, role_definition in role_mapping.items():
                    cls.docker_keycloak_command(
                        f"""bin/kcadm.sh create client-scopes/{id}/scope-mappings/clients/{client_id} -r realm1 -f - << EOF
[{role_definition}]
EOF"""
                    )
        return id

    @classmethod
    def registerGroup(cls, name, role_mappings=[]):
        output = cls.docker_keycloak_command(
            "bin/kcadm.sh create groups -r realm1" f" -s name={name}"
        )
        # output was in the form
        # "Created new group with id '0f5d0645-a7a7-4e88-adf8-b9e568025f5c'""
        # we need to extract the id from this message
        id = None
        if output.stderr[:17] == "Created new group":
            id = output.stderr.split(" ")[5].strip("'\r\n")
        if id:
            for role_mapping in role_mappings:
                for client_name, role_name in role_mapping.items():
                    cls.docker_keycloak_command(
                        "bin/kcadm.sh add-roles"
                        " -r realm1"
                        f" --gid {id}"
                        f" --cclientid {client_name}"
                        f" --rolename {role_name}"
                    )
        return id

    @classmethod
    def registerUser(cls, user, password, groups=[]):
        output = cls.docker_keycloak_command(
            "bin/kcadm.sh create users"
            " -r realm1"
            f" -s username={user}"
            f" -s email={user}@example.com"
            " -s enabled=true -s emailVerified=true"
        )
        # output was in the form
        # "Created new user with id '0f5d0645-a7a7-4e88-adf8-b9e568025f5c'""
        # we need to extract the id from this message
        user_id = None
        if output.stderr[:16] == "Created new user":
            user_id = output.stderr.split(" ")[5].strip("'\r\n")
        if user_id:
            cls.docker_keycloak_command(
                "bin/kcadm.sh set-password"
                " -r realm1"
                f" --username {user}"
                f" --new-password={password}"
            )
            for group in groups:
                cls.docker_keycloak_command(
                    f"bin/kcadm.sh update users/{user_id}/groups/{group}" " -r realm1"
                )


@contextlib.contextmanager
def wrap_class(obj: object, method: str) -> Generator[MagicMock, None, None]:
    mock = MagicMock()
    real_method = getattr(obj, method)

    def wrap_method(self, *args, **kwargs):
        mock.__call__(*args, **kwargs)
        return real_method(self, *args, **kwargs)

    with patch.object(obj, method, wrap_method):
        yield mock
