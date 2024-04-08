from django.conf import settings


def get_setting_for_sso_op(op_name: str, key: str, default=None):
    if key in settings.DJANGO_PYOIDC[op_name]:
        return settings.DJANGO_PYOIDC[op_name][key]
    else:
        return default


def get_settings_for_sso_op(op_name: str):
    return settings.DJANGO_PYOIDC[op_name]
