import unittest

from app.ml_analysis.features import (
    FEATURE_NAMES,
    common_passwords,
    common_substring_length,
    contains_year,
    extract_features,
    is_common_password,
    keyboard_sequence_length,
    repeated_char_length,
    sequence_length,
    to_vector,
)


class CommonPasswordListTest(unittest.TestCase):
    """A lista pública é carregada corretamente."""

    def test_list_is_loaded(self):
        common = common_passwords()
        self.assertGreaterEqual(len(common), 9000)
        for password in ("password", "123456", "qwerty", "dragon"):
            self.assertIn(password, common)

    def test_portuguese_list_is_loaded(self):
        common = common_passwords()
        for password in ("senha123", "brasil", "flamengo", "123mudar", "deusefiel"):
            self.assertIn(password, common)

    def test_list_has_no_blank_entries(self):
        self.assertNotIn("", common_passwords())


class CommonPasswordTest(unittest.TestCase):
    def test_exact_match_ignores_case(self):
        for password in ("password", "PASSWORD", "Qwerty", "123456"):
            with self.subTest(password=password):
                self.assertTrue(is_common_password(password))

    def test_leet_variants_are_detected(self):
        for password in ("p@ssw0rd", "P@$$W0RD", "dr4g0n", "p@ssw0rd1"):
            with self.subTest(password=password):
                self.assertTrue(is_common_password(password))

    def test_portuguese_passwords_are_detected(self):
        for password in ("Brasil", "FLAMENGO", "s3nh@123", "palmeiras"):
            with self.subTest(password=password):
                self.assertTrue(is_common_password(password))
        # Trecho em português dentro de uma senha maior.
        self.assertEqual(common_substring_length("#Palmeiras!"), 9)

    def test_random_password_is_not_common(self):
        self.assertFalse(is_common_password("k7GqT2mZr9XbWc4N"))

    def test_common_substring(self):
        cases = {
            "Dragon2024!": 6,        # dragon
            "xX_m0nk3y_Xx": 6,       # monkey (leet)
            "meuPASSWORD#9": 8,      # password
            "k7GqT2mZr9XbWc4N": 0,
            "": 0,
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                self.assertEqual(common_substring_length(password), expected)

    def test_common_substring_ignores_short_matches(self):
        # "abc" está abaixo do mínimo de 4 caracteres.
        self.assertEqual(common_substring_length("#abc#"), 0)


class SequencePatternTest(unittest.TestCase):
    def test_alphabetic_and_numeric_sequences(self):
        cases = {
            "abc": 3,
            "xyzABCD!": 4,           # ABCD, sem diferenciar maiúsculas
            "senha4321": 4,
            "a1b2c3": 0,             # sem vizinhos consecutivos
            "ab": 0,                 # curta demais
            "az9": 0,                # letra e dígito não formam sequência
            "abcba": 3,              # muda de direção: dois trechos de 3
            "İİabc": 3,              # "İ".lower() tem 2 caracteres
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                self.assertEqual(sequence_length(password), expected)

    def test_keyboard_sequences(self):
        cases = {
            "qwerty": 6,
            "ASDF123": 4,            # asdf (123 também conta, mas é menor)
            "!@#$%": 5,              # linha dos números com Shift
            "poiu": 4,               # direção inversa
            "qaz": 0,                # vizinhos na vertical não contam
            "k7GqT2mZ": 0,
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                self.assertEqual(keyboard_sequence_length(password), expected)

    def test_repeated_characters(self):
        cases = {
            "aaa": 3,
            "senha11111": 5,
            "aabb": 0,
            "": 0,
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                self.assertEqual(repeated_char_length(password), expected)

    def test_year(self):
        self.assertTrue(contains_year("maria1998"))
        self.assertTrue(contains_year("2024@senha"))
        self.assertFalse(contains_year("senha1800"))
        self.assertFalse(contains_year("abc"))


class FeatureVectorTest(unittest.TestCase):
    def test_vector_follows_feature_names(self):
        features = extract_features("P@ssw0rd#2024")
        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertEqual(to_vector("P@ssw0rd#2024"),
                         [features[name] for name in FEATURE_NAMES])

    def test_pattern_features_for_weak_password(self):
        features = extract_features("P@ssw0rd#2024")
        self.assertEqual(features["is_common_password"], 0)
        self.assertEqual(features["common_substring_length"], 8)
        self.assertEqual(features["contains_year"], 1)

    def test_all_values_are_numeric(self):
        for value in extract_features("Qwerty123!!!").values():
            self.assertIsInstance(value, (int, float))
            self.assertNotIsInstance(value, bool)

    def test_rejects_non_string(self):
        with self.assertRaises(ValueError):
            extract_features(None)


if __name__ == "__main__":
    unittest.main()
