"""
toto
"""
from typing import Any, Dict

from django_pyoidc.providers.base import Provider


class Keycloak10Provider(Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v10 to v18)
    """

    def __init__(self, keycloak_base_uri: str, keycloak_realm: str, *args, **kwargs):
        self.keycloak_base_uri = keycloak_base_uri
        self.keycloak_realm = keycloak_realm
        provider_discovery_uri = f"{keycloak_base_uri}/{keycloak_realm}"
        super().__init__(*args, **kwargs, provider_discovery_uri=provider_discovery_uri)

    def get_config(self, allowed_hosts, **kwargs) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts, **kwargs)
        # result[self.op_name]["SCOPE"] = "full-dedicated"
        result[self.op_name][
            "OIDC_LOGOUT_QUERY_STRING_REDIRECT_PARAMETER"
        ] = "redirect_uri"
        return result
