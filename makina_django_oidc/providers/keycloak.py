"""
toto
"""
from typing import Any, Dict

from makina_django_oidc.providers.keycloak_10 import Keycloak10Provider


class KeycloakProvider(Keycloak10Provider):
    """
    Provide django settings/urlconf based on keycloak behaviour (v17 and more).

    For Keycloak before version 17 please check Keycloak_10 provider
    """

    def get_config(self, allowed_hosts) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts)
        # Starting with v17 the /auth/ prefix is not activated by default
        # if you altered Keycloak configuration to keep the auth/ path prefix please add
        # this prefix in the keycloak_base_uri setting
        result[self.op_name]["URI_CONFIG"] = f"/realms/{self.keycloak_realm}"
        return result
