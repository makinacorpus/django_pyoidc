from typing import Any, Dict, List, Optional, TypedDict

from django.urls import path

ProviderConfig = TypedDict(
    "ProviderConfig",
    {
        # most important ----
        "client_id": Optional[str],
        "client_secret": Optional[str],
        "oidc_cache_provider_metadata": Optional[str],
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

        if "oidc_callback_path" in kwargs:
            self.oidc_callback_path = kwargs["oidc_callback_path"]
        else:
            self.oidc_callback_path = "/oidc-callback/"

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

    @property
    def login_uri_name(self) -> str:
        """
        The login viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-login"

    @property
    def logout_uri_name(self) -> str:
        """
        The logout viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-logout"

    @property
    def callback_uri_name(self) -> str:
        """
        The callback viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-callback"

    def get_urlpatterns(self) -> List[Any]:
        """
        Returns:
            A list of urllpatterns to be included using :func:`django:django.urls.include` in your url configuration
        """
        from django_pyoidc.views import OIDCCallbackView, OIDCLoginView, OIDCLogoutView

        result = [
            path(
                f"{self.oidc_callback_path}",
                OIDCCallbackView.as_view(op_name=self.op_name),
                name=self.callback_uri_name,
            ),
            path(
                f"{self.oidc_callback_path}-login",
                OIDCLoginView.as_view(op_name=self.op_name),
                name=self.login_uri_name,
            ),
            path(
                f"{self.oidc_callback_path}-logout",
                OIDCLogoutView.as_view(op_name=self.op_name),
                name=self.logout_uri_name,
            ),
        ]
        return result
