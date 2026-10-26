import os
import unittest
from unittest.mock import Mock, patch

import main


class EmailTelemetryTests(unittest.TestCase):
    def setUp(self):
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


if __name__ == "__main__":
    unittest.main()
