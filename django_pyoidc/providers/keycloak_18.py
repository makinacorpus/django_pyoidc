from typing import Any, Dict

from django_pyoidc.providers.keycloak_17 import Keycloak17Provider


class Keycloak18Provider(Keycloak17Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v18)
    """

    def get_default_config(self) -> Dict[str, Dict[str, Any]]:
        result = super().get_default_config()
        # logout redirection query string parameter name altered, from redirect_uri to post_logout_redirect_uri
        result[
            "oidc_logout_query_string_redirect_parameter"
        ] = "post_logout_redirect_uri"
        return result
