try:
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    from django_pyoidc.utils import get_setting_for_sso_op

    class OIDCScheme(OpenApiAuthenticationExtension):
        target_class = "django_pyoidc.drf.authentication.OIDCBearerAuthentication"
        name = "openIdConnect"
        match_subclasses = True
        priority = -1

        def get_security_definition(self, auto_schema):
            from django_pyoidc.drf.authentication import OIDCBearerAuthentication

            op = OIDCBearerAuthentication.extract_drf_opname()
            well_known_url = get_setting_for_sso_op(op, "OIDC_PROVIDER_DISCOVERY_URI")
            return {"type": "openIdConnect", "openIdConnectUrl": well_known_url}

except ImportError:
    pass
