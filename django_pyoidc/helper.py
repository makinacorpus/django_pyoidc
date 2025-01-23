from typing import Any, List

from django.urls import URLPattern, path

from django_pyoidc.settings import OIDCSettings, OIDCSettingsFactory


class OIDCHelper:
    """
    This is a utility class providing a wrapper around the provider, the settings and the views.
    """

    def __init__(self, *args: Any, op_name: str, **kwargs: Any):
        """
        Parameters:
            op_name (str): the name of the sso provider that you are using.
              This should exists as a key in the DJANGO_PYOIDC settings section.
        """
        self.op_name = op_name
        self.opsettings: OIDCSettings = OIDCSettingsFactory.get(self.op_name)
        self.provider = self.opsettings.provider

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

    @property
    def backchannel_logout_uri_name(self) -> str:
        """
        The backchannel logout viewname (use in :func:`django:django.urls.reverse` django directive for example) of this configuration
        """
        return f"{self.op_name}-backchannel-logout"

    def get_urlpatterns(self) -> List[URLPattern]:
        """
        Returns:
            A list of urllpatterns to be included using :func:`django:django.urls.include` in your url configuration
        """
        from django_pyoidc.views import (
            OIDCBackChannelLogoutView,
            OIDCCallbackView,
            OIDCLoginView,
            OIDCLogoutView,
        )

        oidc_paths_prefix = self.opsettings.get("oidc_paths_prefix")
        result = [
            path(
                f"{oidc_paths_prefix}-callback",
                OIDCCallbackView.as_view(op_name=self.op_name),
                name=self.callback_uri_name,
            ),
            path(
                f"{oidc_paths_prefix}-login",
                OIDCLoginView.as_view(op_name=self.op_name),
                name=self.login_uri_name,
            ),
            path(
                f"{oidc_paths_prefix}-logout",
                OIDCLogoutView.as_view(op_name=self.op_name),
                name=self.logout_uri_name,
            ),
            path(
                f"{oidc_paths_prefix}-backchannel-logout",
                OIDCBackChannelLogoutView.as_view(op_name=self.op_name),
                name=self.backchannel_logout_uri_name,
            ),
        ]
        return result
