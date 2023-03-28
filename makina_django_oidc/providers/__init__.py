from typing import Any, Dict, List

from django.urls import path, reverse_lazy


class Provider:
    def __init__(
        self,
        op_name: str,
        logout_redirect: str,
        failure_redirect: str,
        success_redirect: str,
        redirect_requires_https: bool,
        client_secret: str,
        client_id: str,
    ):
        self.op_name = op_name
        self.logout_redirect = logout_redirect
        self.failure_redirect = failure_redirect
        self.success_redirect = success_redirect
        self.redirect_requires_https = redirect_requires_https
        self.client_secret = client_secret
        self.client_id = client_id

    def get_config(
        self, allowed_hosts, cache_backend: str = "default"
    ) -> Dict[str, Dict[str, Any]]:
        return {
            self.op_name: {
                "URI_FAILURE": self.failure_redirect,
                "URI_LOGOUT": self.logout_redirect,
                "URI_DEFAULT_SUCCESS": self.success_redirect,
                "CALLBACK_PATH": reverse_lazy(self.callback_uri_name),
                "REDIRECT_REQUIRES_HTTPS": self.redirect_requires_https,
                "REDIRECT_ALLOWED_HOSTS": allowed_hosts,
                "CLIENT_SECRET": self.client_secret,
                "CLIENT_ID": self.client_id,
                "CACHE_BACKEND": cache_backend,
            }
        }

    @property
    def login_uri_name(self):
        return f"{self.op_name}-login"

    @property
    def logout_uri_name(self):
        return f"{self.op_name}-logout"

    @property
    def callback_uri_name(self):
        return f"{self.op_name}-callback"

    def get_urlpatterns(self) -> List[Any]:
        from makina_django_oidc.views import (
            OIDCCallbackView,
            OIDCLoginView,
            OIDCLogoutView,
        )

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
