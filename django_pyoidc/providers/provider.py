from typing import Any, Dict, Optional, TypedDict

ProviderConfig = TypedDict(
    "ProviderConfig",
    {
        # most important ----
        "client_id": Optional[str],
        "client_secret": Optional[str],
        "oidc_cache_provider_metadata": Optional[str],
        "oidc_paths_prefix": str,
        "oidc_callback_path": str,
        # less important ---
        "provider_discovery_uri": str,
        "oidc_logout_redirect_parameter_name": str,
        # Use introspection in API-Bearer mode?
        "use_introspection_on_access_tokens": bool,
        # Rare usages ---
        "client_authn_method": Optional[bool],
        "oidc_logout_query_string_redirect_parameter": Optional[str],
        "oidc_logout_query_string_extra_parameters_dict": Optional[Dict[str, Any]],
        # "client_consumer_config_dict": None,
        # some providers may return even more stuff (...) ---
    },
)


class Provider:
    """
    This is the base `Provider` class that is used to implement common provider configuration patterns. You should not
    use this class directly. Instead, you should but subclass it to implement the configuration logic.
    """

    def __init__(self, *args: Any, op_name: str, **kwargs: Any):
        """
        Parameters:
            op_name (str): the name of the sso provider that you are using
        """

        self.op_name = op_name

        if "provider_discovery_uri" in kwargs:
            self.provider_discovery_uri = kwargs["provider_discovery_uri"]
        else:
            self.provider_discovery_uri = None

        if "oidc_logout_redirect_parameter_name" in kwargs:
            self.oidc_logout_redirect_parameter_name = kwargs[
                "oidc_logout_redirect_parameter_name"
            ]
        else:
            self.oidc_logout_redirect_parameter_name = "post_logout_redirect"

        if "oidc_paths_prefix" in kwargs:
            self.oidc_paths_prefix = kwargs["oidc_paths_prefix"]
        else:
            self.oidc_paths_prefix = self.op_name
        if "oidc_callback_path" in kwargs:
            self.oidc_callback_path = kwargs["oidc_callback_path"]
        else:
            self.oidc_callback_path = f"{self.oidc_paths_prefix}-callback"

    def get_default_config(self) -> ProviderConfig:
        """Get the default configuration settings for this provider.

        This configuration defaults are used to provide default values for OIDCSettings.
        User can override these defaults by playing with OIDCSettings arguments.
        """
        return ProviderConfig(
            # most important ----
            client_id=None,
            client_secret=None,
            oidc_cache_provider_metadata=None,
            oidc_paths_prefix=self.oidc_paths_prefix,
            oidc_callback_path=self.oidc_callback_path,
            # less important ---
            provider_discovery_uri=self.provider_discovery_uri,
            oidc_logout_redirect_parameter_name=self.oidc_logout_redirect_parameter_name,
            # Use introspection in API-Bearer mode?
            use_introspection_on_access_tokens=self.op_name == "drf",
            # Rare usages ---
            client_authn_method=None,
            oidc_logout_query_string_redirect_parameter=None,
            oidc_logout_query_string_extra_parameters_dict=None,
        )
