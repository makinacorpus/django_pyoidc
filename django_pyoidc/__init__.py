from typing import Dict

from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation

from django_pyoidc.exceptions import ClaimNotFoundError
from django_pyoidc.utils import extract_claim_from_tokens


def get_user_by_email(tokens: Dict):
    User = get_user_model()

    username = None
    email = None

    try:
        email = extract_claim_from_tokens("email", tokens)
    except ClaimNotFoundError:
        pass

    try:
        username = extract_claim_from_tokens("preferred_username", tokens)
    except ClaimNotFoundError:
        if email:
            username = email
        else:
            raise SuspiciousOperation(
                "Cannot extract username or email from available OIDC tokens."
            )

    user, created = User.objects.get_or_create(
        email=email,
        username=username,
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    return user
