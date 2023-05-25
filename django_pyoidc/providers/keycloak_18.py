from typing import Any, Dict

from django_pyoidc.providers.keycloak_17 import Keycloak17Provider


class Keycloak18Provider(Keycloak17Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v18)
    """

    def get_config(self, allowed_hosts) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts)
        # logout redirection query string parameter name altered, fromredirect_uri to post_logout_redirect_uri
        result[self.op_name][
            "OIDC_LOGOUT_QUERY_STRING_REDIRECT_PARAMETER"
        ] = "post_logout_redirect_uri"
        return result
