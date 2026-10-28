import os
import tempfile
import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

import main


class EmailTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.state_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_directory.cleanup)
        self.state_path = os.path.join(self.state_directory.name, "export-state.sqlite3")
        self.state_environment = patch.dict(
            os.environ,
            {"PHISHING_EXPORT_STATE_DB": self.state_path},
        )
        self.state_environment.start()
        self.addCleanup(self.state_environment.stop)
        self.email = {
            "id": "message-id",
            "subject": "Synthetic test",
            "from": "sender@example.com",
            "body": "Synthetic message body",
        }
        self.result = {
            "classification": "PHISHING_HIGH",
            "reason": "Synthetic test reason",
        }

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "false"})
    @patch("main.send_phishing_email_to_splunk")
    def test_email_content_is_not_exported_by_default(self, export):

        main._export_phishing_email(self.email, self.result)

        export.assert_not_called()

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "true"})
    @patch("main.send_phishing_email_to_splunk")
    def test_phishing_email_is_sent_to_splunk_when_opted_in(self, export):

        main._export_phishing_email(self.email, self.result)

        export.assert_called_once_with(
            self.email,
            "PHISHING_HIGH",
            "Synthetic test reason",
        )

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "true"})
    @patch("main.send_phishing_email_to_splunk")
    def test_benign_email_is_not_sent_to_splunk(self, export):
        result = {
            "classification": "BENIGN",
            "reason": "Routine message",
        }

        main._export_phishing_email(self.email, result)

        export.assert_not_called()

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "true"})
    @patch("main.send_phishing_email_to_splunk")
    def test_phishing_email_is_exported_only_once_across_repeated_scans(self, export):
        main._export_phishing_email(self.email, self.result)
        main._export_phishing_email(self.email, self.result)

        export.assert_called_once_with(
            self.email,
            "PHISHING_HIGH",
            "Synthetic test reason",
        )

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "true"})
    @patch("main.send_phishing_email_to_splunk", side_effect=RuntimeError("HEC failed"))
    def test_failed_export_can_be_retried(self, export):
        with self.assertRaises(RuntimeError):
            main._export_phishing_email(self.email, self.result)

        with patch("main.send_phishing_email_to_splunk") as retry:
            main._export_phishing_email(self.email, self.result)

        retry.assert_called_once()

    @patch.dict(os.environ, {"SPLUNK_INCLUDE_EMAIL_CONTENT": "true"})
    @patch("main.simulate_actions")
    @patch("main.classify_email")
    @patch("main.fetch_recent_emails")
    def test_scans_reuse_cached_classification(self, fetch, classify, _actions):
        email = {
            "id": "message-id",
            "subject": "Synthetic test",
            "from": "sender@example.com",
            "body": "Synthetic message body",
            "body_preview": "Synthetic message preview",
        }
        fetch.return_value = [email]
        classify.return_value = self.result

        with patch("main.send_phishing_email_to_splunk") as export:
            first = main._scan_inbox()
            second = main._scan_inbox()

        self.assertEqual(first["incidents"][0]["reason"], "Synthetic test reason")
        self.assertEqual(second["incidents"][0]["reason"], "Synthetic test reason")
        classify.assert_called_once_with("Synthetic test", "Synthetic message preview")
        export.assert_called_once()


class GmailPollingTests(IsolatedAsyncioTestCase):
    @patch("main._scan_inbox")
    @patch("main.is_gmail_connected", return_value=False)
    async def test_poll_skips_when_gmail_is_not_connected(self, _connected, scan):
        await main._poll_gmail_once()

        scan.assert_not_called()

    @patch("main._scan_inbox")
    @patch("main.is_gmail_connected", return_value=True)
    async def test_poll_scans_when_gmail_is_connected(self, _connected, scan):
        await main._poll_gmail_once()

        scan.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
