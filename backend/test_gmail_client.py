import base64
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException

import gmail_client


class GmailClientTests(unittest.TestCase):
    def setUp(self):
        gmail_client._oauth_states.clear()
        gmail_client._oauth_tokens.clear()
        self.environment = patch.dict(
            "os.environ",
            {
                "GOOGLE_CLIENT_ID": "test-client-id",
                "GOOGLE_CLIENT_SECRET": "test-client-secret",
                "GOOGLE_REDIRECT_URI": (
                    "http://localhost:8080/api/auth/google/callback"
                ),
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def tearDown(self):
        gmail_client._oauth_states.clear()
        gmail_client._oauth_tokens.clear()

    def test_oauth_start_uses_readonly_scope_and_registered_redirect(self):
        response = gmail_client.start_google_oauth()
        query = parse_qs(urlparse(response.headers["location"]).query)

        self.assertEqual(query["client_id"], ["test-client-id"])
        self.assertEqual(
            query["redirect_uri"],
            ["http://localhost:8080/api/auth/google/callback"],
        )
        self.assertEqual(query["scope"], [gmail_client.GMAIL_SCOPE])
        self.assertIn(query["state"][0], gmail_client._oauth_states)

    def test_callback_rejects_unrecognized_state(self):
        with self.assertRaises(HTTPException) as context:
            gmail_client.complete_google_oauth("code", "invalid-state", None)

        self.assertEqual(context.exception.status_code, 400)

    @patch("gmail_client.requests.post")
    def test_callback_exchanges_code_and_stores_refresh_token(self, post):
        oauth_response = gmail_client.start_google_oauth()
        state = parse_qs(urlparse(oauth_response.headers["location"]).query)["state"][0]
        response = Mock()
        response.json.return_value = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
        }
        post.return_value = response

        result = gmail_client.complete_google_oauth("authorization-code", state, None)

        self.assertEqual(result.status_code, 200)
        self.assertTrue(gmail_client.is_gmail_connected())
        self.assertEqual(gmail_client._oauth_tokens["refresh_token"], "refresh-token")
        self.assertEqual(
            post.call_args.kwargs["data"]["redirect_uri"],
            "http://localhost:8080/api/auth/google/callback",
        )

    @patch("gmail_client.requests.get")
    def test_fetch_returns_inbox_message_headers_and_text(self, get):
        gmail_client._oauth_tokens.update(
            {
                "refresh_token": "refresh-token",
                "access_token": "access-token",
                "expires_at": 4_000_000_000,
            }
        )
        body = base64.urlsafe_b64encode(b"Please review this test message.").decode()
        list_response = Mock()
        list_response.json.return_value = {"messages": [{"id": "message-id"}]}
        message_response = Mock()
        message_response.json.return_value = {
            "id": "message-id",
            "snippet": "snippet",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Synthetic test"},
                    {"name": "From", "value": "Test Sender <sender@example.com>"},
                ],
                "mimeType": "text/plain",
                "body": {"data": body},
            },
        }
        get.side_effect = [list_response, message_response]

        emails = gmail_client.fetch_recent_emails()

        self.assertEqual(
            emails,
            [
                {
                    "id": "message-id",
                    "subject": "Synthetic test",
                    "from": "sender@example.com",
                    "body": "Please review this test message.",
                    "body_preview": "Please review this test message.",
                }
            ],
        )
        self.assertEqual(get.call_args_list[0].kwargs["params"]["labelIds"], "INBOX")

    @patch("gmail_client.requests.get")
    def test_fetch_does_not_truncate_plain_text_body(self, get):
        gmail_client._oauth_tokens.update(
            {
                "refresh_token": "refresh-token",
                "access_token": "access-token",
                "expires_at": 4_000_000_000,
            }
        )
        body_text = "test " * 1200
        body = base64.urlsafe_b64encode(body_text.encode()).decode()
        list_response = Mock()
        list_response.json.return_value = {"messages": [{"id": "message-id"}]}
        message_response = Mock()
        message_response.json.return_value = {
            "id": "message-id",
            "payload": {
                "headers": [],
                "mimeType": "text/plain",
                "body": {"data": body},
            },
        }
        get.side_effect = [list_response, message_response]

        emails = gmail_client.fetch_recent_emails()

        self.assertEqual(emails[0]["body"], body_text)
        self.assertEqual(emails[0]["body_preview"], body_text[:4000])


if __name__ == "__main__":
    unittest.main()
