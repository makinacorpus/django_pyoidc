"""
Base Keycloak Provider class.
"""

from typing import Any, Optional
from urllib.parse import urlparse

from typing_extensions import override

from django_pyoidc.providers.provider import Provider, ProviderConfig


class Keycloak10Provider(Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v10 to v18)
    """

    def __init__(
        self,
        keycloak_base_uri: Optional[str] = None,
        keycloak_realm: Optional[str] = None,
        *args: Any,
        op_name: str,
        **kwargs: Any,
    ):
        if keycloak_base_uri is None or keycloak_realm is None:
            # Usage of this provider SHOULD be providing keycloak_base_uri and keycloak_realm so we generate provider_discovery_uri
            # but the contrary works (you provide provider_discovery_uri and we extract base_uri and realm).
            if (
                "provider_discovery_uri" not in kwargs
                or not kwargs["provider_discovery_uri"]
            ):
                raise TypeError(
                    "Keycloak10Provider requires keycloak_base_uri and keycloak_realm or provider_discovery_uri."
                )
            url = urlparse(kwargs["provider_discovery_uri"])
            base_path = url.path
            if "/realms/" in base_path:
                parts = base_path.split("/realms/")
                base_path = parts[0]
                keycloak_realm = parts[1]
                extra_string = ".well-known/openid-configuration"
                if keycloak_realm is not None and keycloak_realm.endswith(extra_string):
                    keycloak_realm = keycloak_realm[: -len(extra_string)]
                extra_string = ".well-known/openid-configuration/"
                if keycloak_realm is not None and keycloak_realm.endswith(extra_string):
                    keycloak_realm = keycloak_realm[: -len(extra_string)]
                extra_string = "/"
                if keycloak_realm is not None and keycloak_realm.endswith(extra_string):
                    keycloak_realm = keycloak_realm[: -len(extra_string)]
                if (
                    keycloak_realm is not None
                    and "/" in keycloak_realm
                    or keycloak_realm is None
                ):
                    raise RuntimeError(
                        "Cannot extract the keycloak realm from the provided url."
                    )
            else:
                raise RuntimeError(
                    "Provided 'provider_discovery_uri' url is not a valid Keycloak metadata url, it does not contains /realms/."
                )
            keycloak_base_uri = f"{url.scheme}{url.netloc}{base_path}"

        if keycloak_base_uri is not None:
            self.keycloak_base_uri = keycloak_base_uri
        if self.keycloak_base_uri[-1] == "/":
            self.keycloak_base_uri = self.keycloak_base_uri[:-1]
        self.keycloak_realm = keycloak_realm
        provider_discovery_uri = (
            f"{self.keycloak_base_uri}/realms/{self.keycloak_realm}"
        )
        kwargs["provider_discovery_uri"] = provider_discovery_uri
        super().__init__(op_name=op_name, *args, **kwargs)

    @override
    def get_default_config(self) -> ProviderConfig:
        result = super().get_default_config()

        result["oidc_logout_query_string_redirect_parameter"] = "redirect_uri"
        return result
