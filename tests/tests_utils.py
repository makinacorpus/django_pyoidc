from django.urls import reverse

from django_pyoidc.exceptions import ClaimNotFoundError
from django_pyoidc.utils import extract_claim_from_tokens
from tests.utils import OIDCTestCase


class UtilsTestCase(OIDCTestCase):
    def test_extract_claim_from_tokens_priority(self, *args):
        """
        Test that extract_claim_from_tokens does the right things.
        """
        tokens = {
            "info_token_claims": {"A": "A1", "B": "B1"},  # U
            "access_token_claims": {"A": "A2", "C": "C2", "D": "D2"},  # A
            "id_token_claims": {"A": "A3", "B": "B2", "C": "C3"},  # I
        }

        # default priority is UIA
        self.assertEqual(
            extract_claim_from_tokens("A", tokens),
            "A1",
        )
        self.assertEqual(
            extract_claim_from_tokens("B", tokens),
            "B1",
        )
        self.assertEqual(
            extract_claim_from_tokens("C", tokens),
            "C3",
        )
        self.assertEqual(
            extract_claim_from_tokens("D", tokens),
            "D2",
        )
        self.assertEqual(
            extract_claim_from_tokens("E", tokens, False),
            None,
        )
        with self.assertRaises(ClaimNotFoundError) as context:
            (extract_claim_from_tokens("E", tokens),)

        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="IUA"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="AIU"),
            "A2",
        )
        self.assertEqual(
            extract_claim_from_tokens("B", tokens, priority="IUA"),
            "B2",
        )
        self.assertEqual(
            extract_claim_from_tokens("B", tokens, priority="AIU"),
            "B2",
        )
        with self.assertRaises(RuntimeError) as context:
            (extract_claim_from_tokens("A", tokens, priority="iau"),)
        with self.assertRaises(RuntimeError) as context:
            (extract_claim_from_tokens("A", tokens, raise_exception=False, priority="iau"),)

    def test_extract_claim_from_tokens_with_none(self, *args):
        """
        Test that extract_claim_from_tokens support missing dict and values.
        """
        tokens = {
            "info_token_claims": None,  # U
            "id_token_claims": {"A": "A3", "B": "B2", "C": "C3"},  # I
        }

        # default priority is UIA
        self.assertEqual(
            extract_claim_from_tokens("A", tokens),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="IUA"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="IAU"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="UIA"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="UAI"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="AIU"),
            "A3",
        )
        self.assertEqual(
            extract_claim_from_tokens("A", tokens, priority="AUI"),
            "A3",
        )
