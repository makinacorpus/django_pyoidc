from django.conf import settings


def get_setting_for_sso_op(op_name: str, key: str, default=None):
    if default and key not in settings.MAKINA_DJANGO_OIDC[op_name]:
        return default
    return settings.MAKINA_DJANGO_OIDC[op_name][key]


def get_settings_for_sso_op(op_name: str):
    return settings.MAKINA_DJANGO_OIDC[op_name]
