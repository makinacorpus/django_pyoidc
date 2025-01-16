import logging
from functools import lru_cache
from importlib import import_module
from typing import Any, Dict, List, Optional, TypedDict, TypeVar, Union

from django.conf import settings as django_settings
from django.urls import reverse_lazy

from django_pyoidc.exceptions import InvalidOIDCConfigurationException

logger = logging.getLogger(__name__)

T = TypeVar("T")

TypedOidcSettings = TypedDict(
    "TypedOidcSettings",
    {
        "cache_django_backend": str,
        "oidc_cache_provider_metadata": bool,
        "oidc_cache_provider_metadata_ttl": int,
        "use_introspection_on_access_tokens": bool,
    },
)

OidcSettingValue = Union[bool, int, str, List[str]]


class OIDCSettings:

    GLOBAL_SETTINGS: TypedOidcSettings = {
        "cache_django_backend": "default",
        "oidc_cache_provider_metadata": False,
        "oidc_cache_provider_metadata_ttl": 120,
        "use_introspection_on_access_tokens": True,
    }

    def __repr__(self) -> str:
        repr_str = f"Oidc Settings for {self.op_name}"
        for key, val in self.OP_SETTINGS.items():
            if val is None:
                repr_str += f"\n + {key}: None"
            else:
                repr_str += f"\n + {key}: {val}"
        return repr_str

    def __init__(self, op_name: str):
        """
           Parameters:
               op_name (str): the name of the sso provider that you are using
        Other settings are loaded from Django setting DJANGO_PYOIDC, prefixed by the op_name
        It may for example contain:
               client_secret (str): the OIDC client secret
               client_id (str): the OIDC client ID
               provider_discovery_uri (str): URL of the SSO server (the .well-known/openid-configuration part is added to this path).
                Some providers like the keycloak provider can instead generate this settings by combining 'keycloak_base_uri' (str) and
                'keycloak_realm' (str) settings.
               oidc_callback_path (str): the path used to call this library during the login round-trips, the default is "/oidc-callback/".
               callback_uri_name (str): the route giving the path for oidc_callback_path that you can use instead of oidc_callback_path
               post_logout_redirect_uri (str): the URI where a user should be redirected to on logout success
               post_login_uri_failure (str): the URI where a user should be redirected to on login failure
               post_login_uri_success (str): the URI a user should be redirected to on login success if no redirection url where provided
               login_redirection_requires_https (bool): set to True to disallow redirecting user to non-https uri on login success
               login_uris_redirect_allowed_hosts(:obj:`list`) : A list of allowed domains that can be redirected to.
                 A good idea is to this to use :setting:`ALLOWED_HOSTS <django:ALLOWED_HOSTS>`.
                 See :ref:`Redirect the user after login` for more details.
               oidc_cache_provider_metadata (bool): default to False; if True calls to the provider_discovery_uri will be cached,
                removing a lot of HTTP traffic. The provider metadata is the same for all your users, so when you havce a lot of
                concurrent OIDC related operations this cache can be useful even with a short duration.
               oidc_cache_provider_metadata_ttl (int): validity of the metadata cache in seconds, default is 120 (2 minutes).
                you can use a long TTL (you know the SSO metadata does not move a lot) or a shorter one (microcache).
               cache_django_backend(:obj:`str`, optional): Defaults to 'default'. The cache backend that should be used to store
                 this provider sessions. Take a look at :ref:`Cache Management`
               hook_user_login (str): path to a function hook to be run after successful login.
               hook_user_logout (str):  path to a function hook to be run during logout(before local session removal and redirection to SSO
                remote logout).
               hook_validate_access_token (str):  path to a function hook to extract access tokens claims from the raw jwt.
                this is not used if 'use_introspection_on_access_tokens' is True
               use_introspection_on_access_tokens (bool): extract access tokens claims by sending the access token to the sso server on
                the introspection route. This delegates validation of the token to the SSO server. If you do not use hook_validate_access_token
                or use_introspection_on_access_tokens you will just have the raw jwt for the access token, that you can use to send HTTP queries
                on behalf of the user.
        """

        self.op_name = op_name
        if self.op_name not in django_settings.DJANGO_PYOIDC:
            raise InvalidOIDCConfigurationException(
                f"{self.op_name} provider name must be configured in DJANGO_PYOIDC settings."
            )

        op_definition = {
            k.lower(): v for k, v in django_settings.DJANGO_PYOIDC[self.op_name].items()
        }

        # fix potential bad settings declaration (or aliases)
        op_definition = self._fix_settings(op_definition)
        if "provider_class" in op_definition:
            provider_class = op_definition["provider_class"]
            # allow usage of simple names like "keycloak" instead of "django_pyoidc.providers.keycloak"
            if "." not in provider_class:
                provider_class = f"django_pyoidc.providers.{provider_class}"
        else:
            provider_class = "django_pyoidc.providers.Provider"

        provider_module_path, provider_class = provider_class.rsplit(".", 1)
        provider_real_class = getattr(
            import_module(provider_module_path), provider_class
        )

        # This call can fail if required attributes are not set
        provider = provider_real_class(op_name=self.op_name, **op_definition)

        # Init a local final operator settings with user given values
        self.OP_SETTINGS = op_definition
        # get some defaults and variation set by the provider
        # For example it could be a newly computed value (provider_discovery_uri from uri and realm for keycloak)
        # or some defaults altered
        provider_default_settings = provider.get_default_config()
        # Then merge the two, so for all settings we have, with priority
        #  * user defined specific values (if not empty)
        #  * provider computed or default value (if not empty)
        #  * then later if a get() is made on this value we'll have the globals applied
        for key, val in provider_default_settings.items():
            key = key.lower()
            if key not in self.OP_SETTINGS or self.OP_SETTINGS[key] is None:
                self.OP_SETTINGS[key] = val

        self.OP_SETTINGS["op_name"] = self.op_name
        self._validate_settings()

    def _fix_settings(self, op_definition: Dict[str, Any]) -> Dict[str, Any]:
        """Workarounds over specific settings and aliases."""

        # pyoidc wants the discovery uri WITHOUT the well-known part '.well-known/openid-configuration'
        if (
            "provider_discovery_uri" in op_definition
            and op_definition["provider_discovery_uri"]
        ):
            discovery = op_definition["provider_discovery_uri"]
            extra_string = ".well-known/openid-configuration"
            if discovery.endswith(extra_string):
                discovery = discovery[: -len(extra_string)]
                op_definition["provider_discovery_uri"] = discovery
            extra_string = ".well-known/openid-configuration/"
            if discovery.endswith(extra_string):
                discovery = discovery[: -len(extra_string)]
                op_definition["provider_discovery_uri"] = discovery
            extra_string = "/"
            if discovery.endswith(extra_string):
                discovery = discovery[: -len(extra_string)]
                op_definition["provider_discovery_uri"] = discovery

        # Special path manipulations
        if "oidc_callback_path" in op_definition:
            op_definition["oidc_callback_path"] = op_definition["oidc_callback_path"]
        if "callback_uri_name" in op_definition:
            op_definition["oidc_callback_path"] = reverse_lazy(
                op_definition["callback_uri_name"]
            )
            del op_definition["callback_uri_name"]
        # else: do not set defaults.
        # The Provider objet will define a defaut callback path if not set.

        # allow simpler names
        # * "logout_redirect" for "post_logout_redirect_uri"
        # * "failure_redirect" for "post_login_uri_failure"
        # * "success_redirect" for "post_login_uri_success"
        # * "redirect_requires_https" for "login_redirection_requires_https"
        if "post_logout_redirect_uri" not in op_definition:
            if "logout_redirect" in op_definition:
                op_definition["post_logout_redirect_uri"] = op_definition[
                    "logout_redirect"
                ]
                del op_definition["logout_redirect"]
            else:
                op_definition["post_logout_redirect_uri"] = "/"

        if "post_login_uri_failure" not in op_definition:
            if "failure_redirect" in op_definition:
                op_definition["post_login_uri_failure"] = op_definition[
                    "failure_redirect"
                ]
                del op_definition["failure_redirect"]
            else:
                op_definition["post_login_uri_failure"] = "/"

        if "post_login_uri_success" not in op_definition:
            if "success_redirect" in op_definition:
                op_definition["post_login_uri_success"] = op_definition[
                    "success_redirect"
                ]
                del op_definition["success_redirect"]
            else:
                op_definition["post_login_uri_success"] = "/"

        if "login_redirection_requires_https" not in op_definition:
            if "redirect_requires_https" in op_definition:
                op_definition["login_redirection_requires_https"] = op_definition[
                    "redirect_requires_https"
                ]
                del op_definition["redirect_requires_https"]
            else:
                op_definition["login_redirection_requires_https"] = True

        return op_definition

    def _validate_settings(self) -> None:
        if (
            "hook_validate_access_token" in self.OP_SETTINGS
            and "use_introspection_on_access_tokens" in self.OP_SETTINGS
            and self.OP_SETTINGS["use_introspection_on_access_tokens"]
        ):
            raise InvalidOIDCConfigurationException(
                "You cannot define hook_validate_access_token if you use use_introspection_on_access_tokens."
            )

        # client_id is required
        if "client_id" not in self.OP_SETTINGS or self.OP_SETTINGS["client_id"] is None:
            raise InvalidOIDCConfigurationException(
                f"Provider definition does not contain any 'client_id' entry. Check your DJANGO_PYOIDC['{self.op_name}'] settings."
            )
        # we do not enforce client_secret (in case someone wrongly use a public client)
        if (
            "client_secret" not in self.OP_SETTINGS
            or self.OP_SETTINGS["client_secret"] is None
        ):
            logger.warning(
                f"OIDC settings for {self.op_name} has no client_secret. You are maybe using a public OIDC client, you should not."
            )

    def set(self, key: str, value: Optional[OidcSettingValue] = None) -> None:
        self.OP_SETTINGS[key] = value

    def get(
        self, name: str, default: Optional[Union[OidcSettingValue, T]] = None
    ) -> Optional[Union[OidcSettingValue, T]]:
        "Get attr value for op or global, given last arg is the default value if None."
        res = self._get_attr(name)
        if res is None:
            return default
        return res

    def _get_attr(self, key: str) -> Optional[OidcSettingValue]:
        """Retrieve attr, if op value is None a check on globals is made.

        Note that op value is already a computation of provider defaults and user defined settings.
        """
        key = key.lower()
        if key in self.OP_SETTINGS and self.OP_SETTINGS[key] is not None:
            return self.OP_SETTINGS[key]
        else:
            if key in self.GLOBAL_SETTINGS.keys():
                return self.GLOBAL_SETTINGS[key]  # type: ignore[literal-required] #  we check that the key is available the line before
        return None


class OIDCSettingsFactory:
    @classmethod
    @lru_cache(maxsize=10)
    def get(cls, op_name: str) -> OIDCSettings:
        """
        lru_cache will return a singleton for each argument value.
        So this is a memoized function.
        """
        settings = OIDCSettings(op_name=op_name)
        return settings
