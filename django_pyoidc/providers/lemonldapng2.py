from typing import Any, Dict

from django_pyoidc.providers.provider import Provider


class LemonLDAPng2Provider(Provider):
    """
    Provide Django settings/urlconf based on LemonLDAP-ng behaviour (v2)
    """

    def get_default_config(self) -> Dict[str, Dict[str, Any]]:
        result = super().get_default_config()
        result["oidc_logout_query_string_extra_parameters_dict"] = {"confirm": 1}
        return result
