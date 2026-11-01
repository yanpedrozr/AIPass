import secrets
import string
import unittest
from unittest import mock

from app import create_app
from app.breach_check import similarity
from app.breach_check.similarity import (
    HIGH_SIMILARITY,
    MAX_AFFIX_LENGTH,
    MEDIUM_SIMILARITY,
    LeakIndex,
    analyze_similarity,
    get_index,
    normalize,
)
from app.config import Config

LEAKED = ["dragon", "Dragon1", "senha123", "senha", "flamengo", "password",
          "iloveyou", "brasil", "monkey", "abc"]


class NormalizeTest(unittest.TestCase):
    def test_lowercase_and_leet(self):
        self.assertEqual(normalize("P@ssW0rd"), "password")
        self.assertEqual(normalize("S3NH@"), "senha")


class LeakIndexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = LeakIndex(LEAKED)

    def test_empty_base_is_rejected(self):
        with self.assertRaises(ValueError):
            LeakIndex([])

    def test_nearest_is_sorted_and_finds_variant(self):
        similar = self.index.nearest("Dr@gon2024!", k=3)
        self.assertLessEqual(len(similar), 3)
        self.assertIn(similar[0][0], ("dragon", "Dragon1"))
        scores = [score for _, score in similar]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_identical_after_normalization_has_similarity_one(self):
        leaked, score = self.index.nearest("FL@MENG0", k=1)[0]
        self.assertEqual(leaked, "flamengo")
        self.assertAlmostEqual(score, 1.0, places=6)

    def test_unrelated_password_has_low_similarity(self):
        similar = self.index.nearest("zzqxv", k=5)
        self.assertTrue(all(score < MEDIUM_SIMILARITY for _, score in similar))

    def test_leaked_base_with_affixes(self):
        cases = {
            "Dragon2024!": ("dragon", 0, 6),
            "S3nh@123!": ("senha123", 0, 8),   # a maior base, não só "senha"
            "123flamengo": ("flamengo", 3, 11),
            "!brasil@26": ("brasil", 1, 7),
            "P@ssw0rd": ("password", 0, 8),
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                self.assertEqual(self.index.leaked_base(password), expected)

    def test_no_leaked_base(self):
        for password in (
            "k7GqT2mZr9XbWc4N!",
            "dragonfly",                 # letras depois da base não são acréscimo
            "xdragon",                   # nem antes
            "abc123",                    # base menor que 4 caracteres
            "dragon" + "!" * (MAX_AFFIX_LENGTH + 1),
        ):
            with self.subTest(password=password):
                self.assertIsNone(self.index.leaked_base(password))

    def test_affix_limit_is_inclusive(self):
        password = "12" + "monkey" + "!" * (MAX_AFFIX_LENGTH - 2)
        self.assertEqual(self.index.leaked_base(password)[0], "monkey")


class AnalyzeSimilarityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = LeakIndex(LEAKED)

    def analyze(self, password):
        return analyze_similarity(password, self.index)

    def test_derived_password_is_high_risk(self):
        result = self.analyze("Dragon2024!")
        self.assertEqual(result["risk"], "alto")
        self.assertEqual(result["leaked_base"]["password"], "dragon")
        self.assertFalse(result["leaked_base"]["exact"])
        self.assertEqual(result["leaked_base"]["transformations"],
                         ["letras maiúsculas", "sufixo de 5 dígito(s)/símbolo(s)"])

    def test_exact_leak_with_leet(self):
        result = self.analyze("p@ssw0rd")
        self.assertTrue(result["leaked_base"]["exact"])
        self.assertEqual(result["leaked_base"]["transformations"],
                         ["substituições leet (ex.: @ → a, 0 → o)"])
        self.assertEqual(result["similarity"], 1.0)

    def test_prefix_is_reported(self):
        result = self.analyze("99monkey")
        self.assertEqual(result["leaked_base"]["transformations"],
                         ["prefixo de 2 dígito(s)/símbolo(s)"])

    def test_random_password_is_low_risk(self):
        result = self.analyze("k7GqT2mZr9XbWc4N!")
        self.assertEqual(result["risk"], "baixo")
        self.assertIsNone(result["leaked_base"])

    def test_risk_by_similarity_alone(self):
        self.assertEqual(similarity.risk_level(HIGH_SIMILARITY, None), "alto")
        self.assertEqual(similarity.risk_level(MEDIUM_SIMILARITY, None), "médio")
        self.assertEqual(similarity.risk_level(MEDIUM_SIMILARITY - 0.01, None), "baixo")
        self.assertEqual(similarity.risk_level(0.0, ("x", 0, 4)), "alto")

    def test_response_does_not_echo_password(self):
        result = self.analyze("Dragon2024!")
        self.assertNotIn("Dragon2024!", repr(result))
        self.assertNotIn("2024", repr(result))

    def test_unknown_characters(self):
        result = self.analyze("€€€€")
        self.assertEqual(result["risk"], "baixo")
        self.assertEqual(result["similar_passwords"], [])

    def test_invalid_passwords(self):
        for value in ("", None, 123, "a" * (similarity.MAX_PASSWORD_LENGTH + 1)):
            with self.subTest(value=repr(value)[:20]):
                with self.assertRaises(ValueError):
                    self.analyze(value)


class ProjectIndexTest(unittest.TestCase):
    """Usa a base real (amostra da RockYou + listas do SecLists)."""

    @classmethod
    def setUpClass(cls):
        cls.index = get_index()

    def test_index_is_built_once(self):
        self.assertIs(get_index(), self.index)
        self.assertGreater(len(self.index.passwords), 100_000)

    def test_known_variations_are_high_risk(self):
        for password in ("Dragon2024!", "S3nh@123!", "flamengo2023", "P@ssw0rd2024"):
            with self.subTest(password=password):
                self.assertEqual(analyze_similarity(password)["risk"], "alto")

    def test_generated_passwords_are_mostly_low_risk(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        passwords = ["".join(secrets.choice(alphabet) for _ in range(16))
                     for _ in range(50)]
        risks = [analyze_similarity(password)["risk"] for password in passwords]
        self.assertNotIn("alto", risks)
        self.assertGreaterEqual(risks.count("baixo"), 45)


class SimilarityRouteTest(unittest.TestCase):
    URL = "/api/breach/similarity"

    @classmethod
    def setUpClass(cls):
        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

        cls.client = create_app(TestConfig).test_client()

    def setUp(self):
        patcher = mock.patch.object(similarity, "get_index",
                                    return_value=LeakIndex(LEAKED))
        self.get_index = patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, password):
        return self.client.post(self.URL, json={"password": password})

    def test_response_format(self):
        response = self.check("Dragon2024!")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        body = response.get_json()
        self.assertEqual(set(body), {"risk", "similarity", "similar_passwords",
                                     "leaked_base"})
        self.assertEqual(body["risk"], "alto")
        self.assertEqual(body["leaked_base"]["password"], "dragon")
        self.assertLessEqual(len(body["similar_passwords"]), similarity.TOP_K)
        self.assertNotIn(b"Dragon2024!", response.data)

    def test_invalid_bodies(self):
        for kwargs in ({"json": {}}, {"json": {"password": ""}},
                       {"json": {"password": 123}}, {"json": ["abc"]},
                       {"data": "abc"}, {}):
            with self.subTest(kwargs=kwargs):
                response = self.client.post(self.URL, **kwargs)
                self.assertEqual(response.status_code, 400)

    def test_too_long(self):
        response = self.check("a" * (similarity.MAX_PASSWORD_LENGTH + 1))
        self.assertEqual(response.status_code, 400)

    def test_password_is_not_accepted_in_url(self):
        response = self.client.get(self.URL + "?password=123456")
        self.assertEqual(response.status_code, 405)

    def test_missing_base(self):
        self.get_index.side_effect = FileNotFoundError("rockyou-sample.txt")
        response = self.check("Dragon2024!")
        self.assertEqual(response.status_code, 503)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()
