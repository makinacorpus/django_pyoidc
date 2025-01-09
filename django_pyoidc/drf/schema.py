import logging

logger = logging.getLogger(__name__)

try:
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    from django_pyoidc.settings import OIDCSettingsFactory

    class OIDCScheme(OpenApiAuthenticationExtension):
        target_class = "django_pyoidc.drf.authentication.OIDCBearerAuthentication"
        name = "openIdConnect"
        match_subclasses = True
        priority = -1

        def get_security_definition(self, auto_schema):
            # from django_pyoidc.drf.authentication import OIDCBearerAuthentication

            opsettings = OIDCSettingsFactory.get("drf")
            well_known_url = opsettings.get("provider_discovery_uri")

            header_name = opsettings.get("oidc_api_bearer_name", "Bearer")
            if header_name != "Bearer":
                logger.warning(
                    "The configuration for 'oidc_api_bearer_name' will cause issue with swagger UI :"
                    "it is not yet possible to change the header name for swagger UI, you should stick to"
                    "'Bearer'."
                )
            return {
                "type": "openIdConnect",
                "openIdConnectUrl": well_known_url,
            }

except ImportError:
    logger.debug(
        "The package 'drf-spectacular' is not installed, skipping schema generation."
    )
