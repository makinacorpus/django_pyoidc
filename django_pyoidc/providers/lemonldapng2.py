from django_pyoidc.providers.provider import Provider, ProviderConfig


class LemonLDAPng2Provider(Provider):
    """
    Provide Django settings/urlconf based on LemonLDAP-ng behaviour (v2)
    """

    def get_default_config(self) -> ProviderConfig:
        result = super().get_default_config()
        result["oidc_logout_query_string_extra_parameters_dict"] = {"confirm": 1}
        return result
