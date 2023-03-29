from typing import Dict

from django.contrib.auth import get_user_model


def get_user_by_email(token: Dict[str, str]):
    User = get_user_model()
    user, created = User.objects.get_or_create(email=token["email"])
    user.backend = "django.contrib.auth.backends.ModelBackend"
    return user
