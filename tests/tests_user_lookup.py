from unittest.mock import MagicMock, patch

from django.core.exceptions import PermissionDenied

from django_pyoidc import get_user_by_email
from tests.utils import OIDCTestCase


class GetUserByEmailTestCase(OIDCTestCase):
    def setUp(self):
        self.user = MagicMock()
        self.user_model = MagicMock()
        self.user_model.objects.get_or_create.return_value = (self.user, True)
        self.get_user_model_patcher = patch("django_pyoidc.get_user_model", return_value=self.user_model)
        self.get_user_model_patcher.start()
        self.addCleanup(self.get_user_model_patcher.stop)

    def test_one_argument_call_keeps_legacy_behavior(self):
        tokens = {"info_token_claims": {"email": "alice@example.com", "preferred_username": "alice"}}

        user = get_user_by_email(tokens)

        self.assertIs(user, self.user)
        self.user_model.objects.get_or_create.assert_called_once_with(
            email="alice@example.com",
            username="alice",
        )

    def test_explicitly_disabled_check_accepts_unverified_email(self):
        tokens = {
            "info_token_claims": {
                "email": "alice@example.com",
                "preferred_username": "alice",
                "email_verified": False,
            }
        }

        get_user_by_email(tokens, require_email_verified=False)

        self.user_model.objects.get_or_create.assert_called_once()

    def test_enabled_check_accepts_literal_true(self):
        tokens = {
            "info_token_claims": {
                "email": "alice@example.com",
                "preferred_username": "alice",
                "email_verified": True,
            }
        }

        user = get_user_by_email(tokens, require_email_verified=True)

        self.assertIs(user, self.user)
        self.user_model.objects.get_or_create.assert_called_once()

    def test_enabled_check_rejects_false_missing_and_non_boolean_claims_before_lookup(self):
        invalid_claim_values = [False, None, 0, 1, "true", "True"]
        for claim_value in invalid_claim_values:
            with self.subTest(email_verified=claim_value):
                self.user_model.objects.get_or_create.reset_mock()
                tokens = {
                    "info_token_claims": {
                        "email": "alice@example.com",
                        "preferred_username": "alice",
                        "email_verified": claim_value,
                    }
                }

                with self.assertRaises(PermissionDenied):
                    get_user_by_email(tokens, require_email_verified=True)

                self.user_model.objects.get_or_create.assert_not_called()

        with self.subTest(email_verified="missing"):
            self.user_model.objects.get_or_create.reset_mock()
            tokens = {"info_token_claims": {"email": "alice@example.com", "preferred_username": "alice"}}

            with self.assertRaises(PermissionDenied):
                get_user_by_email(tokens, require_email_verified=True)

            self.user_model.objects.get_or_create.assert_not_called()

    def test_email_verified_claim_uses_userinfo_id_token_access_token_precedence(self):
        cases = [
            (
                "userinfo wins over ID token and access token",
                {
                    "info_token_claims": {"email": "alice@example.com", "email_verified": False},
                    "id_token_claims": {"email_verified": True},
                    "access_token_claims": {"email_verified": True},
                },
                False,
            ),
            (
                "ID token wins over access token",
                {
                    "info_token_claims": {"email": "alice@example.com"},
                    "id_token_claims": {"email_verified": False},
                    "access_token_claims": {"email_verified": True},
                },
                False,
            ),
            (
                "access token is used when higher-priority tokens omit the claim",
                {
                    "info_token_claims": {"email": "alice@example.com"},
                    "id_token_claims": {},
                    "access_token_claims": {"email_verified": True},
                },
                True,
            ),
        ]

        for description, tokens, accepted in cases:
            with self.subTest(description=description):
                self.user_model.objects.get_or_create.reset_mock()
                if accepted:
                    get_user_by_email(tokens, require_email_verified=True)
                    self.user_model.objects.get_or_create.assert_called_once()
                else:
                    with self.assertRaises(PermissionDenied):
                        get_user_by_email(tokens, require_email_verified=True)
                    self.user_model.objects.get_or_create.assert_not_called()

    def test_username_only_login_does_not_require_email_verification(self):
        tokens = {"info_token_claims": {"preferred_username": "service-user"}}

        user = get_user_by_email(tokens, require_email_verified=True)

        self.assertIs(user, self.user)
        self.user_model.objects.get_or_create.assert_called_once_with(
            email=None,
            username="service-user",
        )
