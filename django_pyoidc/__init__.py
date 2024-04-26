from typing import Dict

from django.contrib.auth import get_user_model


def get_user_by_email(tokens: Dict):
    User = get_user_model()

    username = ""
    email = ""

    if "info_token_claims" in tokens and "email" in tokens["info_token_claims"]:
        email = tokens["info_token_claims"]["email"]
    elif "id_token_claims" in tokens and "email" in tokens["id_token_claims"]:
        email = tokens["id_token_claims"]["email"]
    elif "access_token_claims" and "email" in tokens["access_token_claims"]:
        email = tokens["info_token_claims"]["email"]
    else:
        email = tokens["info_token_claims"]["email"]

    if (
        "id_token_claims" in tokens
        and "preferred_username" in tokens["id_token_claims"]
    ):
        username = tokens["id_token_claims"]["preferred_username"]
    elif (
        "info_token_claims" in tokens
        and "preferred_username" in tokens["info_token_claims"]
    ):
        username = tokens["info_token_claims"]["preferred_username"]
    elif (
        "access_token_claims" in tokens
        and "preferred_username" in tokens["access_token_claims"]
    ):
        username = tokens["info_token_claims"]["preferred_username"]
    else:
        username = email

    user, created = User.objects.get_or_create(
        email=email,
        username=username,
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    return user
