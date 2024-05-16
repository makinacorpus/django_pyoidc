from typing import Any, Dict

from django_pyoidc.providers.base import Provider


class LemonLDAPng2Provider(Provider):
    """
    Provide Django settings/urlconf based on LemonLDAP-ng behaviour (v2)
    """

    def get_config(self, allowed_hosts) -> Dict[str, Dict[str, Any]]:
        result = super().get_config(allowed_hosts)
        # logout is by default asking for confirmation unless you pass confirm=1
        result[self.op_name]["LOGOUT_QUERY_STRING_EXTRA_PARAMETERS_DICT"] = {
            "confirm": 1
        }
        return result
