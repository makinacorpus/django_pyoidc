import logging
import os
import subprocess
import time

from django.core.servers.basehttp import ThreadedWSGIServer, WSGIRequestHandler
from django.test import TestCase, override_settings
from django.test.testcases import LiveServerTestCase, LiveServerThread

logger = logging.getLogger(__name__)


@override_settings(
    MAKINA_DJANGO_OIDC={
        "sso1": {
            "CLIENT_ID": "1",
            "CACHE_BACKEND": "default",
            "URI_PROVIDER": "",
            "URI_CONFIG": "",
            "CLIENT_SECRET": "",
            "CALLBACK_PATH": "/callback",
            "URI_DEFAULT_SUCCESS": "/default/success",
            "REDIRECT_ALLOWED_HOSTS": ["test.django-pyoidc.notatld"],
            "REDIRECT_REQUIRES_HTTPS": True,
            "URI_LOGOUT": "/logoutdone",
            "URI_FAILURE": "/logout_failure",
        },
        "sso2": {
            "CLIENT_ID": "2",
            "CACHE_BACKEND": "default",
            "URI_PROVIDER": "",
            "URI_CONFIG": "",
            "CLIENT_SECRET": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass


class NotReadyException(Exception):
    pass


@override_settings(
    ALLOWED_HOSTS=["testserver"],
    STATIC_URL="/static",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
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
        cls.app1_id = cls.registerClient("app1", "secret_app1", cls.live_server_url)
        cls.app1_bis_id = cls.registerClient(
            "app1-bis", "secret_app1-bis", cls.live_server_url
        )
        cls.app2_foo_id = cls.registerClient(
            "app2-foo", "secret_app2-foo", cls.live_server_url
        )
        cls.app2_bar_id = cls.registerClient(
            "app2-bar", "secret_app2-bar", cls.live_server_url
        )

        print(" + Create client applications access roles.")
        cls.app1_role = cls.registerClientRole(cls.app1_id, "AccessApp1")
        cls.app1_bis_role = cls.registerClientRole(cls.app1_bis_id, "AccessApp1Bis")
        cls.app2_foo_role = cls.registerClientRole(cls.app2_foo_id, "AccessApp2Foo")
        cls.app2_bar_role = cls.registerClientRole(cls.app2_bar_id, "AccessApp2Bar")

        print(" + Create Client Scopes.")
        id_zone_app1 = cls.registerClientScope(
            "zone-app1",
            [{cls.app1_id: cls.app1_role}, {cls.app1_bis_id: cls.app1_bis_role}],
        )
        id_zone_app2 = cls.registerClientScope(
            "zone-app2",
            [
                {cls.app2_foo_id: cls.app2_foo_role},
                {cls.app2_bar_id: cls.app2_bar_role},
            ],
        )

        print(" + Update applications client scopes")
        cls.addClientScopeForClient(cls.app1_id, id_zone_app1)
        cls.addClientScopeForClient(cls.app1_bis_id, id_zone_app1)
        cls.addClientScopeForClient(cls.app2_foo_id, id_zone_app2)
        cls.addClientScopeForClient(cls.app2_bar_id, id_zone_app2)

        print(" + Create Groups.")
        gApp1 = cls.registerGroup(
            "App1",
            [
                {"app1": "AccessApp1"},
                {"app1-bis": "AccessApp1Bis"},
            ],
        )
        gApp2 = cls.registerGroup(
            "App2",
            [
                {"app2-foo": "AccessApp2Foo"},
                {"app2-bar": "AccessApp2Bar"},
            ],
        )
        gAppAll = cls.registerGroup(
            "AllApps",
            [
                {"app1": "AccessApp1"},
                {"app1-bis": "AccessApp1Bis"},
                {"app2-foo": "AccessApp2Foo"},
                {"app2-bar": "AccessApp2Bar"},
            ],
        )

        print(" + Create users.")
        cls.registerUser(
            "user1",
            "passwd1",
            groups=[
                gAppAll,
            ],
        )
        cls.registerUser(
            "user_app2",
            "passwd2",
            groups=[
                gApp2,
            ],
        )
        cls.registerUser(
            "user_app1",
            "passwd3",
            groups=[
                gApp1,
            ],
        )
        # time.sleep(60)

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
            if (
                e.returncode == 1
                and last_error
                == "Failed to send request - Connect to 127.0.0.1:8080 [/127.0.0.1] failed: Connection refused (Connection refused)"
            ):
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
    def registerClient(cls, name, secret, url):
        output = cls.docker_keycloak_command(
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
      "backchannel.logout.session.required" : "false",
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
            "bin/kcadm.sh create groups" " -r realm1" f" -s name={name}"
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
