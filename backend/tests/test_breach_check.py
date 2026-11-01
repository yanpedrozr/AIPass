import hashlib
import os
import unittest
from unittest import mock

import requests

from app import create_app
from app.breach_check import hibp
from app.breach_check.hibp import (
    HIBPUnavailableError,
    parse_range,
    pwned_count,
    sha1_hex,
    split_hash,
)
from app.config import Config

# SHA-1 de "password": 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PASSWORD_PREFIX = "5BAA6"
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

API = {"api_url": "https://hibp.test", "timeout": 3, "user_agent": "teste"}


def fake_response(text="", status=200):
    response = mock.Mock(spec=requests.Response)
    response.status_code = status
    response.text = text
    return response


def range_body(*lines):
    return "\r\n".join(lines)


class HashTest(unittest.TestCase):
    def test_sha1_is_uppercase_hex(self):
        self.assertEqual(sha1_hex("password"), PASSWORD_PREFIX + PASSWORD_SUFFIX)

    def test_split(self):
        self.assertEqual(split_hash("password"), (PASSWORD_PREFIX, PASSWORD_SUFFIX))

    def test_utf8_encoding(self):
        expected = hashlib.sha1("senhaçã€".encode("utf-8")).hexdigest().upper()
        self.assertEqual(sha1_hex("senhaçã€"), expected)


class ParseRangeTest(unittest.TestCase):
    def test_parses_counts_and_drops_padding(self):
        body = range_body(
            "0018A45C4D1DEF81644B54AB7F969B88D65:10",
            f"{PASSWORD_SUFFIX}:10434004",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0",   # preenchimento falso
        )
        self.assertEqual(parse_range(body), {
            "0018A45C4D1DEF81644B54AB7F969B88D65": 10,
            PASSWORD_SUFFIX: 10434004,
        })

    def test_ignores_malformed_lines_and_normalizes_case(self):
        body = range_body("", "lixo", "ABC:x", "abcdef:3")
        self.assertEqual(parse_range(body), {"ABCDEF": 3})


class PwnedCountTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(hibp.requests, "get")
        self.get = patcher.start()
        self.addCleanup(patcher.stop)

    def test_leaked_password(self):
        self.get.return_value = fake_response(range_body(
            "0018A45C4D1DEF81644B54AB7F969B88D65:10",
            f"{PASSWORD_SUFFIX}:10434004",
        ))
        self.assertEqual(pwned_count("password", **API), 10434004)

    def test_password_not_leaked(self):
        self.get.return_value = fake_response(range_body(
            "0018A45C4D1DEF81644B54AB7F969B88D65:10",
        ))
        self.assertEqual(pwned_count("password", **API), 0)

    def test_padding_entry_does_not_count_as_leak(self):
        self.get.return_value = fake_response(f"{PASSWORD_SUFFIX}:0")
        self.assertEqual(pwned_count("password", **API), 0)

    def test_only_the_prefix_is_sent(self):
        self.get.return_value = fake_response("")
        pwned_count("password", **API)

        args, kwargs = self.get.call_args
        self.assertEqual(args[0], f"https://hibp.test/range/{PASSWORD_PREFIX}")
        sent = repr((args, kwargs))
        self.assertNotIn("password", sent.replace("'password'", ""))
        self.assertNotIn(PASSWORD_SUFFIX, sent)
        self.assertNotIn("data", kwargs)
        self.assertNotIn("params", kwargs)

    def test_headers_and_timeout(self):
        self.get.return_value = fake_response("")
        pwned_count("password", **API)
        kwargs = self.get.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Add-Padding"], "true")
        self.assertEqual(kwargs["headers"]["User-Agent"], "teste")
        self.assertEqual(kwargs["timeout"], 3)

    def test_network_errors(self):
        for error in (requests.Timeout(), requests.ConnectionError()):
            with self.subTest(error=type(error).__name__):
                self.get.side_effect = error
                with self.assertRaises(HIBPUnavailableError):
                    pwned_count("password", **API)

    def test_http_errors(self):
        for status in (400, 429, 500, 503):
            with self.subTest(status=status):
                self.get.return_value = fake_response("erro", status)
                with self.assertRaises(HIBPUnavailableError):
                    pwned_count("password", **API)

    def test_invalid_password_is_not_sent(self):
        for value in ("", None, 123, "a" * (hibp.MAX_PASSWORD_LENGTH + 1)):
            with self.subTest(value=repr(value)[:20]):
                with self.assertRaises(ValueError):
                    pwned_count(value, **API)
        self.get.assert_not_called()


class BreachRouteTest(unittest.TestCase):
    URL = "/api/breach"

    @classmethod
    def setUpClass(cls):
        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            HIBP_API_URL = "https://hibp.test/"
            HIBP_TIMEOUT_SECONDS = 2
            HIBP_USER_AGENT = "agente-de-teste"

        cls.client = create_app(TestConfig).test_client()

    def setUp(self):
        patcher = mock.patch.object(hibp.requests, "get")
        self.get = patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, password):
        return self.client.post(self.URL, json={"password": password})

    def test_leaked(self):
        self.get.return_value = fake_response(f"{PASSWORD_SUFFIX}:10434004")
        response = self.check("password")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"pwned": True, "count": 10434004})
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_not_leaked(self):
        self.get.return_value = fake_response("")
        response = self.check("k7GqT2mZr9XbWc4N!")
        self.assertEqual(response.get_json(), {"pwned": False, "count": 0})

    def test_uses_app_config(self):
        self.get.return_value = fake_response("")
        self.check("password")
        args, kwargs = self.get.call_args
        self.assertEqual(args[0], f"https://hibp.test/range/{PASSWORD_PREFIX}")
        self.assertEqual(kwargs["timeout"], 2)
        self.assertEqual(kwargs["headers"]["User-Agent"], "agente-de-teste")

    def test_trailing_slash(self):
        self.get.return_value = fake_response("")
        response = self.client.post(self.URL + "/", json={"password": "abc"})
        self.assertEqual(response.status_code, 200)

    def test_response_does_not_echo_password(self):
        self.get.return_value = fake_response("")
        response = self.check("minha-senha-secreta-42")
        self.assertNotIn(b"minha-senha-secreta-42", response.data)

    def test_hibp_unavailable(self):
        self.get.side_effect = requests.Timeout()
        response = self.check("password")
        self.assertEqual(response.status_code, 503)
        self.assertIn("error", response.get_json())

    def test_invalid_bodies(self):
        for kwargs in ({"json": {}}, {"json": {"password": ""}},
                       {"json": {"password": 123}}, {"json": ["abc"]},
                       {"data": "abc"}, {}):
            with self.subTest(kwargs=kwargs):
                response = self.client.post(self.URL, **kwargs)
                self.assertEqual(response.status_code, 400)
        self.get.assert_not_called()

    def test_password_is_not_accepted_in_url(self):
        response = self.client.get(self.URL + "?password=123456")
        self.assertEqual(response.status_code, 405)
        self.get.assert_not_called()

    def test_status(self):
        response = self.client.get(self.URL + "/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")


@unittest.skipUnless(os.getenv("HIBP_LIVE_TESTS") == "1",
                     "defina HIBP_LIVE_TESTS=1 para consultar a API real")
class LiveHIBPTest(unittest.TestCase):
    """Consulta a API real do HIBP (precisa de internet)."""

    LIVE = {"api_url": Config.HIBP_API_URL, "timeout": 10,
            "user_agent": Config.HIBP_USER_AGENT}

    def test_known_leaked_password(self):
        self.assertGreater(pwned_count("password", **self.LIVE), 1_000_000)

    def test_random_password_not_leaked(self):
        import secrets
        self.assertEqual(pwned_count(secrets.token_urlsafe(32), **self.LIVE), 0)


if __name__ == "__main__":
    unittest.main()
