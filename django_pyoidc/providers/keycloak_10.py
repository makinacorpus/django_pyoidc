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
        super().__init__(*args, **kwargs)
        self.keycloak_base_uri = keycloak_base_uri
        self.keycloak_realm = keycloak_realm

    def get_config(self, allowed_hosts) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts)
        # result[self.op_name]["SCOPE"] = "full-dedicated"
        result[self.op_name]["OIDC_LOGOUT_QUERY_STRING_REDIRECT_PARAMETER"] = "redirect_uri"
        return result
