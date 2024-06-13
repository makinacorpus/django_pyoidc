from functools import lru_cache
from typing import Any, Dict

from django.conf import settings
from django.urls import reverse_lazy

from django_pyoidc.exceptions import InvalidOIDCConfigurationException


class OIDCSettingsFactory:
    @lru_cache
    def get(op_name, *args, **kwargs):
        """
        lru_cache will return a singleton for each argument value.
        So this is a memoized function
        """

        # FIXME: Not good, too much args, needs to memoize only on op_name

        return OIDCSettings(op_name, *args, **kwargs)


class OIDCSettings:

    GLOBAL_SETTINGS = {
        "CACHE_PROVIDER_TTL": 60,
        "DRF_CLIENT_ID": None,
        "DRF_USE_INTROSPECTION": True,
    }
    OP_SETTINGS = {
        "POST_LOGIN_URI_FAILURE": "/",
        "POST_LOGIN_URI_SUCCESS": "/",
        "POST_LOGOUT_REDIRECT_URI": "/",
        "OIDC_CALLBACK_PATH": "/oidc",
        "REDIRECT_REQUIRES_HTTPS": True,
        "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": [],
        "OIDC_CLIENT_SECRET": None,
        "OIDC_CLIENT_ID": None,
        "OIDC_PROVIDER_DISCOVERY_URI": None,
        "OIDC_LOGOUT_REDIRECT_PARAMETER_NAME": "post_logut_redirect",
        "CACHE_DJANGO_BACKEND": None,
    }

    def init(self, op_name: str, *args, **kwargs):
        #    provider_discovery_uri: str,
        #    logout_redirect: str,
        #    failure_redirect: str,
        #    success_redirect: str,
        #    redirect_requires_https: bool,
        #    client_secret: str,
        #    client_id: str,
        # ):

        # provider_discovery_uri = kwargs["provider_discovery_uri"]
        logout_redirect = kwargs["logout_redirect"]
        failure_redirect = kwargs["failure_redirect"]
        success_redirect = kwargs["success_redirect"]
        redirect_requires_https = kwargs["redirect_requires_https"]
        client_secret = kwargs["client_secret"]
        client_id = kwargs["client_id"]
        if op_name == "__default":
            raise InvalidOIDCConfigurationException(
                "'__default' is a reserved word that you cannot use for the provide name"
            )
        self.op_name = op_name
        # self.attrs =
        # NEW !!
        # if 'provider_name' in kwargs:
        # FIXME: load provider by name, to get all defaults from that
        if "provider_discovery_uri" in kwargs:
            self.provider_discovery_uri = kwargs["provider_discovery_uri"]
        else:
            self.provider_discovery_uri = kwargs["provider_discovery_uri"]
        self.init("POST_LOGOUT_REDIRECT_URI", logout_redirect)
        # if settings.DJANGO_PYOIDC[op_name]
        self.OP_SETTINGS["POST_LOGOUT_REDIRECT_URI"] = logout_redirect
        self.OP_SETTINGS["POST_LOGIN_URI_FAILURE"] = failure_redirect
        self.success_redirect = success_redirect
        self.redirect_requires_https = redirect_requires_https
        self.client_secret = client_secret
        self.client_id = client_id

    def get(self, name, default=None):
        return self.get_op_setting(self.op_name, name, default)

    def set(self, key: str, value=None):
        self.OP_SETTINGS[key] = value

    def _get_attr(self, key):
        if key in self.OP_SETTINGS and self.OP_SETTINGS[key] is not None:
            return self.OP_SETTINGS[key]
        else:
            if key in self.GLOBAL_SETTINGS:
                return self.GLOBAL_SETTINGS[key]
            else:
                raise InvalidOIDCConfigurationException(
                    f"{key} is not a valid setting."
                )

    def get_op_setting(self, key: str, default=None):
        res = self._get_attr(key)
        if res is None:
            return default

    def get_op_settings(op_name: str):
        # FALSE
        return settings.DJANGO_PYOIDC[op_name]

    def get_op_config(self) -> Dict[str, Dict[str, Any]]:
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
                "OIDC_CLIENT_SECRET": self.attrs["client_secret"],
                "OIDC_CLIENT_ID": self.attrs["client_id"],
                "OIDC_PROVIDER_DISCOVERY_URI": self.provider_discovery_uri,
                "OIDC_LOGOUT_REDIRECT_PARAMETER_NAME": None,
                "CACHE_PROVIDER_TTL": self.GLOBAL_SETTINGS["CACHE_PROVIDER_TTL"],
            }
        }
