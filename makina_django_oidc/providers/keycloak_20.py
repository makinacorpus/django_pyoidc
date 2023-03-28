from typing import Any, Dict

from makina_django_oidc.providers import Provider


class Keycloak20Provider(Provider):
    def __init__(self, keycloak_realm_uri: str, keycloak_realm: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keycloak_realm_uri = keycloak_realm_uri
        self.keycloak_realm = keycloak_realm

    def get_config(self, allowed_hosts) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts)
        # result[self.op_name]["SCOPE"] = "full-dedicated"
        result[self.op_name]["URI_PROVIDER"] = self.keycloak_realm_uri
        result[self.op_name]["URI_CONFIG"] = f"/auth/realms/{self.keycloak_realm}"
        return result
