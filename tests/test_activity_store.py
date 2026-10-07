import unittest
from unittest.mock import Mock, patch

from activity_store import (
    get_user_activity,
    record_activity,
    register_account,
    sign_in,
)


class ActivityStoreTests(unittest.TestCase):
    @patch("activity_store.requests.request")
    def test_registration_uses_supabase_auth(self, request):
        response = Mock(ok=True, content=b'{"user":{"id":"user-1"}}')
        response.json.return_value = {"user": {"id": "user-1"}}
        request.return_value = response

        result = register_account(
            "https://example.supabase.co", "public-key", "person@example.com", "long-password"
        )

        self.assertEqual(result["user"]["id"], "user-1")
        args, kwargs = request.call_args
        self.assertEqual(args[:2], ("POST", "https://example.supabase.co/auth/v1/signup"))
        self.assertEqual(kwargs["headers"]["apikey"], "public-key")
        self.assertEqual(
            kwargs["json"],
            {"email": "person@example.com", "password": "long-password"},
        )

    @patch("activity_store.requests.request")
    def test_sign_in_uses_password_grant(self, request):
        response = Mock(ok=True, content=b'{"user":{"id":"user-1"}}')
        response.json.return_value = {"user": {"id": "user-1"}}
        request.return_value = response

        result = sign_in(
            "https://example.supabase.co", "public-key", "person@example.com", "long-password"
        )

        self.assertEqual(result["user"]["id"], "user-1")
        args, kwargs = request.call_args
        self.assertEqual(
            args[:2],
            (
                "POST",
                "https://example.supabase.co/auth/v1/token?grant_type=password",
            ),
        )
        self.assertEqual(kwargs["headers"]["apikey"], "public-key")

    @patch("activity_store.requests.request")
    def test_activity_insert_uses_server_key_and_only_metadata(self, request):
        response = Mock(ok=True, content=b"")
        request.return_value = response

        record_activity(
            "https://example.supabase.co",
            "server-only-key",
            user_id="user-1",
            user_email="person@example.com",
            activity="Steganography operation",
            operation="Conceal",
            payload_bits=128,
        )

        args, kwargs = request.call_args
        self.assertEqual(args[:2], ("POST", "https://example.supabase.co/rest/v1/user_activity"))
        self.assertEqual(kwargs["headers"]["apikey"], "server-only-key")
        self.assertEqual(
            kwargs["headers"]["Authorization"], "Bearer server-only-key"
        )
        self.assertEqual(kwargs["json"]["user_id"], "user-1")
        self.assertEqual(kwargs["json"]["operation"], "Conceal")
        self.assertNotIn("message", kwargs["json"])
        self.assertNotIn("password", kwargs["json"])

    @patch("activity_store.requests.request")
    def test_user_activity_query_is_scoped_to_user(self, request):
        rows = [{"activity": "Signed in"}]
        response = Mock(ok=True, content=b'[{"activity":"Signed in"}]')
        response.json.return_value = rows
        request.return_value = response

        result = get_user_activity(
            "https://example.supabase.co", "server-only-key", "user-1"
        )

        self.assertEqual(result, rows)
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(kwargs["params"]["user_id"], "eq.user-1")
        self.assertEqual(kwargs["params"]["order"], "created_at.desc")
        self.assertEqual(kwargs["params"]["limit"], "101")
        self.assertEqual(kwargs["params"]["offset"], "0")


if __name__ == "__main__":
    unittest.main()
