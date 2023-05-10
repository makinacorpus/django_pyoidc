import os
import subprocess
import time

from django.core.servers.basehttp import ThreadedWSGIServer, WSGIRequestHandler
from django.test import TestCase, override_settings
from django.test.testcases import LiveServerTestCase, LiveServerThread


@override_settings(
    DJANGO_PYOIDC={
        "sso1": {
            "OIDC_CLIENT_ID": "1",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
            "OIDC_CALLBACK_PATH": "/callback",
            "POST_LOGIN_URI_SUCCESS_DEFAULT": "/default/success",
            "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["test.django-pyoidc.notatld"],
            "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": True,
            "POST_LOGOUT_REDIRECT_URI": "/logoutdone",
            "POST_LOGIN_URI_FAILURE": "/logout_failure",
        },
        "sso2": {
            "OIDC_CLIENT_ID": "2",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass


@override_settings(
    ALLOWED_HOSTS=["testserver"],
    STATIC_URL="/static",
    MAKINA_DJANGO_OIDC={
        "sso1": {
            "CLIENT_ID": "app1",
            "CACHE_BACKEND": "default",
            "URI_PROVIDER": "http://localhost:8080/auth",
            "URI_CONFIG": "realms/realm1",
            "CLIENT_SECRET": "secret_app1",
            "CALLBACK_PATH": "/callback",
            "URI_DEFAULT_SUCCESS": "/test-success",
            "REDIRECT_ALLOWED_HOSTS": ["testserver"],
            "REDIRECT_REQUIRES_HTTPS": False,
            "URI_LOGOUT": "/test-logout-done",
            "URI_FAILURE": "/test-failure",
        },
    },
)
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

    @classmethod
    def setUpClass(cls):
        print(" *** Live Server Test Case Setup ***")
        super().setUpClass()

        cls.workdir = os.getcwd()
        print(f"Current workdir: {cls.workdir} ...")
        cls.docker_workdir = f"{cls.workdir}/tests/e2e"
        os.chdir(cls.docker_workdir)
        cls.docker_id = None
        try:
            print("Building keycloak docker image...")
            subprocess.run(["docker", "build", "-t", "oidc-test-keycloak-image", "."])
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
        except subprocess.CalledProcessError as e:
            print(
                f"Error while launching keycloak docker container. errcode: {e.returncode}."
            )
            print(e.stderr)
            if e.returncode == 125:
                print(
                    "   + Try removing any previous Keycloak image running using this command:"
                )
                print(
                    '   docker stop $(docker ps -a -q --filter ancestor=oidc-test-keycloak-image --format="{{.ID}}")'
                )
                print("   + Check also you have no service running on localhost:8080.")
        finally:
            os.chdir(cls.workdir)
        if cls.docker_id:
            print("wait 15s for keycloak startup...")
            time.sleep(15)
            cls.docker_keycloak_command(
                "bin/kcadm.sh config credentials --server http://127.0.0.1:8080/auth/ --realm master --user admin --password admin"
            )
            cls.docker_keycloak_command(
                "bin/kcadm.sh create realms -s realm=realm1 -s enabled=true"
            )
        else:
            raise RuntimeError("Cannot build the context environnement with docker.")

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
            os.chdir(cls.workdir)

    @classmethod
    def docker_keycloak_command(cls, command: str):
        # print(f"Docker Keycloak command: {command}")
        cmd_prefix = f"docker exec {cls.docker_id}"
        command = command.replace('"', '"')
        final_command = f"{cmd_prefix} /bin/bash -c '{command}'"
        # print(final_command)
        os.chdir(cls.docker_workdir)
        try:
            subprocess.run(final_command, shell=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(
                f"Error while launching command on the keycloak container. errcode: {e.returncode}."
            )
            print(e.stderr)
        finally:
            os.chdir(cls.workdir)

    @classmethod
    def registerClient(cls, name, secret, url):
        cls.docker_keycloak_command(
            f"""bin/kcadm.sh create clients -r realm1 -f - << EOF
{{
    "clientId": "{name}",
    "name": "{name}",
    "rootUrl": "{url}",
    "adminUrl" : "",
    "baseUrl" : "",
    "surrogateAuthRequired" : false,
    "enabled" : true,
    "alwaysDisplayInConsole" : false,
    "clientAuthenticatorType" : "client-secret",
    "secret" : "{secret}",
    "redirectUris" : [ "{url}/*" ],
    "webOrigins" : [ "+" ],
    "notBefore" : 0,
    "bearerOnly" : false,
    "consentRequired" : false,
    "standardFlowEnabled" : true,
    "implicitFlowEnabled" : false,
    "directAccessGrantsEnabled" : false,
    "serviceAccountsEnabled" : false,
    "publicClient" : false,
    "frontchannelLogout" : false,
    "protocol" : "openid-connect",
    "attributes" : {{
      "oidc.ciba.grant.enabled" : "false",
      "backchannel.logout.session.required" : "true",
      "backchannel.logout.url" : "{url}/back_channel_logout",
      "post.logout.redirect.uris" : "{url}/*",
      "display.on.consent.screen" : "false",
      "oauth2.device.authorization.grant.enabled" : "false",
      "backchannel.logout.revoke.offline.tokens" : "false"
    }},
    "authenticationFlowBindingOverrides" : {{ }},
    "fullScopeAllowed" : false,
    "defaultClientScopes" : [ "web-origins", "acr", "roles", "profile", "email" ],
    "optionalClientScopes" : [ "address", "phone" ]
}}
EOF"""
        )
        os.chdir(cls.docker_workdir)

    @classmethod
    def registerUser(cls, user, password):
        cls.docker_keycloak_command(
            f"bin/kcadm.sh create users -r realm1"
            f" -s username={user}"
            f" -s email={user}@example.com"
            " -s enabled=true -s emailVerified=true"
            " -o --fields id,username"
        )
        cls.docker_keycloak_command(
            f"bin/kcadm.sh set-password -r realm1"
            f" --username {user}"
            f" --new-password={password}"
        )
        os.chdir(cls.docker_workdir)
