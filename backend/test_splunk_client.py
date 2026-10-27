import unittest
from unittest.mock import Mock, patch

import requests
from fastapi import HTTPException

from splunk_client import send_phishing_email_to_splunk


class SplunkClientTests(unittest.TestCase):
    def setUp(self):
        self.email = {
            "id": "message-id",
            "subject": "Synthetic test",
            "from": "sender@example.com",
            "body": "Synthetic email body",
        }
        self.environment = patch.dict(
            "os.environ",
            {
                "SPLUNK_HEC_URL": "https://splunk.example/services/collector",
                "SPLUNK_HEC_TOKEN": "test-hec-token",
                "SPLUNK_HEC_INDEX": "test-index",
                "SPLUNK_HEC_VERIFY_TLS": "true",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @patch("splunk_client.requests.post")
    def test_posts_email_as_a_hec_event(self, post):
        response = Mock()
        response.json.return_value = {"text": "Success", "code": 0}
        post.return_value = response

        send_phishing_email_to_splunk(
            self.email,
            "PHISHING_HIGH",
            "Synthetic reason",
        )

        post.assert_called_once()
        self.assertTrue(post.call_args.kwargs["verify"])
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"],
            "Splunk test-hec-token",
        )
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["index"], "test-index")
        self.assertEqual(payload["source"], "phishing-email")
        self.assertEqual(
            payload["event"],
            {
                "email_id": "message-id",
                "sender": "sender@example.com",
                "subject": "Synthetic test",
                "body": "Synthetic email body",
                "classification": "PHISHING_HIGH",
                "reason": "Synthetic reason",
            },
        )

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_hec_settings_fails_explicitly(self):
        with self.assertRaises(HTTPException) as context:
            send_phishing_email_to_splunk(
                self.email,
                "PHISHING_HIGH",
                "Synthetic reason",
            )

        self.assertEqual(context.exception.status_code, 503)

    @patch("splunk_client.requests.post")
    def test_hec_rejection_fails_explicitly(self, post):
        response = Mock()
        response.json.return_value = {"text": "Invalid token", "code": 4}
        post.return_value = response

        with self.assertRaises(HTTPException) as context:
            send_phishing_email_to_splunk(
                self.email,
                "PHISHING_HIGH",
                "Synthetic reason",
            )

        self.assertEqual(context.exception.status_code, 502)

    @patch.dict("os.environ", {"SPLUNK_HEC_VERIFY_TLS": "false"})
    @patch("splunk_client.requests.post")
    def test_tls_verification_can_be_disabled_for_explicit_demo_override(self, post):
        response = Mock()
        response.json.return_value = {"text": "Success", "code": 0}
        post.return_value = response

        with self.assertLogs("splunk_client", level="WARNING") as captured:
            send_phishing_email_to_splunk(
                self.email,
                "PHISHING_HIGH",
                "Synthetic reason",
            )

        self.assertFalse(post.call_args.kwargs["verify"])
        self.assertTrue(any("may be exposed" in line for line in captured.output))

    @patch("splunk_client.requests.post", side_effect=requests.ConnectionError)
    def test_connection_error_gives_endpoint_diagnostic(self, _post):
        with self.assertRaises(HTTPException) as context:
            send_phishing_email_to_splunk(
                self.email,
                "PHISHING_HIGH",
                "Synthetic reason",
            )

        self.assertEqual(context.exception.status_code, 502)
        self.assertIn("endpoint hostname", context.exception.detail)


if __name__ == "__main__":
    unittest.main()
