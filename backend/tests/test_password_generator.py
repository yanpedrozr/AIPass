import math
import string
import unittest
from collections import Counter
from itertools import product
from unittest import mock

from app import create_app
from app.config import Config
from app.password_generator import generator
from app.password_generator.generator import (
    CHARSETS,
    MAX_LENGTH,
    MIN_LENGTH,
    entropy_bits,
    generate_password,
)

CATEGORY_NAMES = list(CHARSETS)


def all_option_combinations():
    """As 15 combinações possíveis com pelo menos uma categoria ativa."""
    for flags in product([True, False], repeat=len(CATEGORY_NAMES)):
        if any(flags):
            yield dict(zip(CATEGORY_NAMES, flags))


class GeneratorCriteriaTest(unittest.TestCase):
    """A senha gerada respeita os critérios escolhidos."""

    def assert_meets_criteria(self, password, length, options):
        self.assertEqual(len(password), length)
        allowed = set()
        for name, enabled in options.items():
            charset = set(CHARSETS[name])
            if enabled:
                allowed |= charset
                self.assertTrue(
                    set(password) & charset,
                    f"sem caractere de '{name}' em {password!r}",
                )
            else:
                self.assertFalse(
                    set(password) & charset,
                    f"'{name}' desativado mas presente em {password!r}",
                )
        self.assertLessEqual(set(password), allowed)

    def test_default_uses_length_16_and_all_categories(self):
        password = generate_password()
        self.assert_meets_criteria(password, 16, dict.fromkeys(CATEGORY_NAMES, True))

    def test_every_combination_and_length_meets_criteria(self):
        for options in all_option_combinations():
            for length in (MIN_LENGTH, 5, 8, 16, 64, MAX_LENGTH):
                for _ in range(30):
                    with self.subTest(options=options, length=length):
                        password = generate_password(length, **options)
                        self.assert_meets_criteria(password, length, options)

    def test_minimum_length_with_all_categories_has_one_of_each(self):
        for _ in range(200):
            password = generate_password(4)
            for charset in CHARSETS.values():
                self.assertEqual(sum(ch in charset for ch in password), 1)

    def test_rejects_no_category_selected(self):
        with self.assertRaises(ValueError):
            generate_password(
                16, uppercase=False, lowercase=False, digits=False, symbols=False
            )

    def test_rejects_invalid_lengths(self):
        for length in (MIN_LENGTH - 1, 0, -5, MAX_LENGTH + 1, "16", 16.0, None, True):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    generate_password(length)


class GeneratorRandomnessTest(unittest.TestCase):
    """A senha é imprevisível e a distribuição dos caracteres é uniforme."""

    def test_uses_secrets_and_not_random(self):
        self.assertFalse(hasattr(generator, "random"), "o módulo não deve usar random")
        with mock.patch.object(
            generator.secrets, "choice", wraps=generator.secrets.choice
        ) as spy:
            generate_password(32, uppercase=False, digits=False, symbols=False)
        self.assertEqual(spy.call_count, 32)

    def test_passwords_do_not_repeat(self):
        passwords = [generate_password(12) for _ in range(5000)]
        self.assertEqual(len(set(passwords)), len(passwords))

    def test_consecutive_passwords_are_not_correlated(self):
        # Em média, duas senhas independentes coincidem em 1/94 das posições
        matches = 0
        previous = generate_password(64)
        for _ in range(500):
            current = generate_password(64)
            matches += sum(a == b for a, b in zip(previous, current))
            previous = current
        rate = matches / (500 * 64)
        self.assertAlmostEqual(rate, 1 / 94, delta=0.005)

    def test_every_character_of_pool_is_used(self):
        seen = set("".join(generate_password(32) for _ in range(2000)))
        expected = set(string.ascii_letters + string.digits + string.punctuation)
        self.assertEqual(seen, expected)

    def test_character_frequencies_are_uniform_chi_square(self):
        # Só minúsculas: sem restrição de categoria, cada letra tem chance 1/26
        text = "".join(
            generate_password(50, uppercase=False, digits=False, symbols=False)
            for _ in range(2000)
        )
        counts = Counter(text)
        expected = len(text) / 26
        chi_square = sum((counts[ch] - expected) ** 2 / expected
                         for ch in string.ascii_lowercase)
        # Valor crítico para 25 graus de liberdade com p = 1e-6
        # (falso alarme em ~1 a cada 1 milhão de execuções)
        self.assertLess(chi_square, 73.89)

    def test_categories_are_not_tied_to_positions(self):
        # Garantir uma categoria de cada não pode deixá-las em posições fixas
        # (ex.: primeira letra sempre maiúscula). A proporção de cada categoria
        # deve ser a mesma em todas as posições.
        length, samples = 16, 3000
        category_of = {ch: name for name, cs in CHARSETS.items() for ch in cs}
        per_position = [Counter() for _ in range(length)]
        for _ in range(samples):
            for i, ch in enumerate(generate_password(length)):
                per_position[i][category_of[ch]] += 1

        for name in CATEGORY_NAMES:
            overall = sum(pos[name] for pos in per_position) / (samples * length)
            for i, pos in enumerate(per_position):
                with self.subTest(category=name, position=i):
                    self.assertAlmostEqual(pos[name] / samples, overall, delta=0.04)


class EntropyTest(unittest.TestCase):
    def test_single_category_entropy(self):
        bits = entropy_bits(10, uppercase=False, digits=False, symbols=False)
        self.assertAlmostEqual(bits, 10 * math.log2(26))

    def test_minimum_length_entropy_is_exact(self):
        # 4 caracteres, um de cada categoria: 4! ordens x 26 x 26 x 10 x 32
        expected = math.log2(math.factorial(4) * 26 * 26 * 10 * 32)
        self.assertAlmostEqual(entropy_bits(4), expected)

    def test_entropy_slightly_below_unrestricted_pool(self):
        unrestricted = 16 * math.log2(94)
        bits = entropy_bits(16)
        self.assertLess(bits, unrestricted)
        self.assertGreater(bits, unrestricted - 1)


class GeneratePasswordEndpointTest(unittest.TestCase):
    URL = "/api/generator/generate-password"

    @classmethod
    def setUpClass(cls):
        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

        cls.client = create_app(TestConfig).test_client()

    def test_get_with_defaults(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["password"]), 16)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertGreater(response.json["entropy_bits"], 100)

    def test_get_with_query_params(self):
        response = self.client.get(
            self.URL + "?length=24&symbols=false&uppercase=0"
        )
        password = response.json["password"]
        self.assertEqual(len(password), 24)
        self.assertTrue(set(password) <= set(string.ascii_lowercase + string.digits))
        self.assertEqual(response.json["options"]["symbols"], False)

    def test_post_with_json(self):
        response = self.client.post(
            self.URL, json={"length": 8, "lowercase": False, "digits": True,
                            "uppercase": False, "symbols": False}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["password"].isdigit())

    def test_invalid_options_return_400(self):
        cases = [
            self.client.get(self.URL + "?length=abc"),
            self.client.get(self.URL + "?length=2"),
            self.client.get(self.URL + "?length=500"),
            self.client.get(self.URL + "?digits=talvez"),
            self.client.post(self.URL, json={"length": "16.5"}),
            self.client.post(self.URL, json=[1, 2]),
            self.client.post(self.URL, json={
                "uppercase": False, "lowercase": False,
                "digits": False, "symbols": False,
            }),
        ]
        for response in cases:
            with self.subTest(body=response.json):
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json)


if __name__ == "__main__":
    unittest.main()
