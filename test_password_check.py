"""Unit tests for HIBP Pwned Passwords k-anonymity helpers (no live network)."""
import hashlib
import unittest
from unittest.mock import MagicMock, patch

import hibp_passwords


class TestPasswordPwned(unittest.TestCase):
    def test_found_in_range_response(self):
        password = "Password123"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        suffix = sha1[5:]
        body = f"AAAAA:1\n{suffix}:42\nBBBBB:3\n"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = body
        with patch("hibp_passwords.requests.get", return_value=mock_resp) as get:
            count = hibp_passwords.check_password_pwned(password)
        self.assertEqual(count, 42)
        args, kwargs = get.call_args
        self.assertTrue(args[0].endswith(sha1[:5]))
        self.assertEqual(kwargs["headers"].get("Add-Padding"), "true")

    def test_not_found(self):
        password = "unique-not-in-list-xyz"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "DEADB:9\nC0FFEE:2\n"
        with patch("hibp_passwords.requests.get", return_value=mock_resp):
            count = hibp_passwords.check_password_pwned(password)
        self.assertEqual(count, 0)

    def test_only_prefix_sent(self):
        password = "secret"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        with patch("hibp_passwords.requests.get", return_value=mock_resp) as get:
            hibp_passwords.check_password_pwned(password)
        url = get.call_args[0][0]
        self.assertEqual(url, f"https://api.pwnedpasswords.com/range/{sha1[:5]}")
        self.assertNotIn(sha1[5:], url)


if __name__ == "__main__":
    unittest.main()
