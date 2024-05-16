from typing import Any, Dict, List

from django.urls import path, reverse_lazy


class Provider:
    """
    This is the base `Provider` class that is used to implement common provider configuration patterns. You should not
    use this class directly. Instead, you should but subclass it to implement the configuration logic.
    """

    def __init__(
        self,
        op_name: str,
        provider_discovery_uri: str,
        logout_redirect: str,
        failure_redirect: str,
        success_redirect: str,
        redirect_requires_https: bool,
        client_secret: str,
        client_id: str,
    ):
        """
        Parameters:
            op_name (str): the name of the sso provider that you are using
            logout_redirect (str): the URI where a user should be redirected to on logout success
            failure_redirect (str): the URI where a user should be redirected to on login failure
            success_redirect (str): the URI a user should be redirected to on login success if no redirection url where provided
            redirect_requires_https (bool): set to True to disallow redirecting user to non-https uri on login success
            client_secret (str): the OIDC client secret
            client_id (str): the OIDC client ID
        """
        self.op_name = op_name
        self.provider_discovery_uri = provider_discovery_uri
        self.logout_redirect = logout_redirect
        self.failure_redirect = failure_redirect
        self.success_redirect = success_redirect
        self.redirect_requires_https = redirect_requires_https
        self.client_secret = client_secret
        self.client_id = client_id

    def get_config(
        self, allowed_hosts, cache_backend: str = "default"
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parameters:
            allowed_hosts(:obj:`list`) : A list of allowed domains that can be redirected to. A good idea is to this to
             :setting:`ALLOWED_HOSTS <django:ALLOWED_HOSTS>`. See :ref:`Redirect the user after login` for more details.
            cache_backend(:obj:`str`, optional): Defaults to 'default'. The cache backend that should be used to store
                this provider sessions. Take a look at :ref:`Cache Management`

        Returns:
            dict: A dictionary with all the settings that `django-pyoidc` expects to work properly
        """
        return {
            self.op_name: {
                "POST_LOGIN_URI_FAILURE": self.failure_redirect,
                "POST_LOGIN_URI_SUCCESS": self.success_redirect,
                "POST_LOGOUT_REDIRECT_URI": self.logout_redirect,
                "OIDC_CALLBACK_PATH": reverse_lazy(self.callback_uri_name),
                "REDIRECT_REQUIRES_HTTPS": self.redirect_requires_https,
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": allowed_hosts,
                "OIDC_CLIENT_SECRET": self.client_secret,
                "OIDC_CLIENT_ID": self.client_id,
                "OIDC_PROVIDER_DISCOVERY_URI": self.provider_discovery_uri,
                "OIDC_LOGOUT_REDIRECT_PARAMETER_NAME": None,
                "CACHE_DJANGO_BACKEND": cache_backend,
            }
        }

    @property
    def login_uri_name(self):
        """
        The login viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-login"

    @property
    def logout_uri_name(self):
        """
        The logout viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-logout"

    @property
    def callback_uri_name(self):
        """
        The callback viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-callback"

    def get_urlpatterns(self) -> List[Any]:
        """
        Returns:
            A list of urllpatterns to be included using :func:`django:django.urls.include` in your urllconfiguration
        """
        from django_pyoidc.views import OIDCCallbackView, OIDCLoginView, OIDCLogoutView

        result = [
            path(
                "callback",
                OIDCCallbackView.as_view(op_name=self.op_name),
                name=self.callback_uri_name,
            ),
            path(
                "login",
                OIDCLoginView.as_view(op_name=self.op_name),
                name=self.login_uri_name,
            ),
            path(
                "logout",
                OIDCLogoutView.as_view(op_name=self.op_name),
                name=self.logout_uri_name,
            ),
        ]
        return result
