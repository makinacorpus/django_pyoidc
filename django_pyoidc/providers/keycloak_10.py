"""
toto
"""
from typing import Any, Dict

from django_pyoidc.providers.provider import Provider


class Keycloak10Provider(Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v10 to v18)
    """

    def __init__(
        self, op_name: str, keycloak_base_uri: str, keycloak_realm: str, *args, **kwargs
    ):
        self.keycloak_base_uri = keycloak_base_uri
        if self.keycloak_base_uri[-1] == "/":
            self.keycloak_base_uri = self.keycloak_base_uri[:-1]
        self.keycloak_realm = keycloak_realm
        provider_discovery_uri = (
            f"{self.keycloak_base_uri}/realms/{self.keycloak_realm}"
        )
        kwargs["provider_discovery_uri"] = provider_discovery_uri
        super().__init__(op_name=op_name, *args, **kwargs)

    def get_default_config(self) -> Dict[str, Dict[str, Any]]:
        result = super().get_default_config()

        result["oidc_logout_query_string_redirect_parameter"] = "redirect_uri"
        return result
