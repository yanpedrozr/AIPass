import unittest
from pathlib import Path
from unittest import mock

from app import create_app
from app.config import Config
from app.ml_analysis import predictor
from app.ml_analysis.features import FEATURE_NAMES
from app.ml_analysis.labels import LABELS
from app.ml_analysis.train import MODEL_FILE


class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class AnalysisRouteBase(unittest.TestCase):
    URL = "/api/analysis"

    @classmethod
    def setUpClass(cls):
        cls.client = create_app(TestConfig).test_client()

    def analyze(self, password, url=None):
        return self.client.post(url or self.URL, json={"password": password})


@unittest.skipUnless(MODEL_FILE.exists(), "modelo ainda não treinado")
class AnalysisRouteTest(AnalysisRouteBase):
    def setUp(self):
        predictor.get_model.cache_clear()

    def test_response_format(self):
        response = self.analyze("Dragon2024!")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

        data = response.get_json()
        self.assertEqual(set(data), {"strength", "probabilities", "features"})
        self.assertIn(data["strength"], LABELS)
        self.assertEqual(set(data["probabilities"]), set(LABELS))
        self.assertAlmostEqual(sum(data["probabilities"].values()), 1.0, places=3)
        self.assertEqual(data["strength"],
                         max(data["probabilities"], key=data["probabilities"].get))
        self.assertEqual(set(data["features"]), set(FEATURE_NAMES))
        self.assertEqual(data["features"]["common_substring_length"], 6)
        self.assertEqual(data["features"]["contains_year"], 1)

    def test_obvious_cases(self):
        for password, expected in (("123456", "fraca"), ("password", "fraca"),
                                   ("k7GqT2mZr9XbWc4N!", "forte")):
            with self.subTest(password=password):
                data = self.analyze(password).get_json()
                self.assertEqual(data["strength"], expected)

    def test_response_does_not_echo_password(self):
        response = self.analyze("minha-senha-secreta-42")
        self.assertNotIn(b"minha-senha-secreta-42", response.data)

    def test_url_with_trailing_slash(self):
        self.assertEqual(self.analyze("abc", url=self.URL + "/").status_code, 200)

    def test_unicode_password(self):
        self.assertEqual(self.analyze("ção_İstanbul_ü").status_code, 200)

    def test_model_is_loaded_once(self):
        with mock.patch.object(predictor, "load_model",
                               wraps=predictor.load_model) as loader:
            self.analyze("abc")
            self.analyze("def")
        self.assertEqual(loader.call_count, 1)

    def test_status(self):
        response = self.client.get(self.URL + "/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["features"], list(FEATURE_NAMES))


class AnalysisValidationTest(AnalysisRouteBase):
    """Validação da entrada, antes de usar o modelo."""

    def test_invalid_bodies(self):
        cases = (
            {},
            {"password": ""},
            {"password": None},
            {"password": 123456},
            {"password": ["abc"]},
            {"senha": "abc"},
        )
        for body in cases:
            with self.subTest(body=body):
                response = self.client.post(self.URL, json=body)
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())

    def test_body_must_be_json_object(self):
        for kwargs in ({"json": ["abc"]}, {"data": "abc"}, {}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.client.post(self.URL, **kwargs).status_code, 400)

    def test_password_too_long(self):
        limit = predictor.MAX_PASSWORD_LENGTH
        self.assertEqual(self.analyze("a" * (limit + 1)).status_code, 400)

    def test_password_is_not_accepted_in_url(self):
        response = self.client.get(self.URL + "?password=123456")
        self.assertEqual(response.status_code, 405)


class ModelUnavailableTest(AnalysisRouteBase):
    def setUp(self):
        predictor.get_model.cache_clear()
        patcher = mock.patch.object(predictor, "MODEL_FILE",
                                    Path("nao-existe") / "modelo.joblib")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(predictor.get_model.cache_clear)

    def test_returns_503_without_model(self):
        response = self.analyze("abc")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Treine", response.get_json()["error"])

    def test_status_reports_missing_model(self):
        response = self.client.get(self.URL + "/status")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "model unavailable")


if __name__ == "__main__":
    unittest.main()
