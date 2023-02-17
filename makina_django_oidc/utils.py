from django.conf import settings


def get_settings_for_sso_op(op_name: str):
    return settings.MAKINA_DJANGO_OIDC[op_name]
