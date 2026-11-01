import os
import tempfile
import unittest
from unittest import mock

import numpy as np

from app.ml_analysis import dataset
from app.ml_analysis.dataset import (
    MAX_PASSWORD_LENGTH,
    build_labeled_dataset,
    load_labeled_dataset,
    load_sample,
    read_rockyou,
    sample_passwords,
    save_labeled_dataset,
)
from app.ml_analysis.features import common_passwords
from app.ml_analysis.labels import (
    LABELS,
    SCORE_TO_LABEL,
    create_label_encoder,
    decode_labels,
    encode_labels,
    label_password,
    label_passwords,
)


class LabelTest(unittest.TestCase):
    """Rótulos a partir do score do zxcvbn."""

    def test_every_score_has_a_label(self):
        self.assertEqual(set(SCORE_TO_LABEL), {0, 1, 2, 3, 4})
        self.assertEqual(set(SCORE_TO_LABEL.values()), set(LABELS))

    def test_score_ranges(self):
        self.assertEqual(SCORE_TO_LABEL[0], "fraca")
        self.assertEqual(SCORE_TO_LABEL[1], "fraca")
        self.assertEqual(SCORE_TO_LABEL[2], "média")
        self.assertEqual(SCORE_TO_LABEL[3], "forte")
        self.assertEqual(SCORE_TO_LABEL[4], "forte")

    def test_label_uses_zxcvbn_score(self):
        for score, expected in SCORE_TO_LABEL.items():
            with self.subTest(score=score):
                with mock.patch("app.ml_analysis.labels.zxcvbn",
                                return_value={"score": score}):
                    self.assertEqual(label_password("qualquer"), expected)

    def test_known_passwords(self):
        self.assertEqual(label_password("123456"), "fraca")
        self.assertEqual(label_password("password"), "fraca")
        self.assertEqual(label_password("k7GqT2mZr9XbWc4N!"), "forte")

    def test_label_passwords_keeps_order(self):
        self.assertEqual(label_passwords(["123456", "k7GqT2mZr9XbWc4N!"]),
                         ["fraca", "forte"])

    def test_rejects_invalid_input(self):
        for value in ("", None, 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                label_password(value)


class LabelEncoderTest(unittest.TestCase):
    def test_encoder_has_fixed_classes(self):
        encoder = create_label_encoder()
        self.assertEqual(list(encoder.classes_), ["forte", "fraca", "média"])

    def test_encoding_does_not_depend_on_data(self):
        # Mesmo sem a classe "forte" nos dados, "fraca" continua sendo 1.
        self.assertEqual(list(encode_labels(["fraca", "média"])), [1, 2])

    def test_round_trip(self):
        labels = ["fraca", "forte", "média", "fraca"]
        codes = encode_labels(labels)
        self.assertTrue(np.issubdtype(codes.dtype, np.integer))
        self.assertEqual(list(decode_labels(codes)), labels)

    def test_unknown_label_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_labels(["muito forte"])


class SamplingTest(unittest.TestCase):
    def test_excluded_passwords_are_never_sampled(self):
        passwords = ["password", "PASSWORD", "abc", "xyz", "Dragon", "qwe"]
        sample = sample_passwords(passwords, 10, excluded={"password", "dragon"})
        self.assertEqual(sorted(sample), ["abc", "qwe", "xyz"])

    def test_size_and_uniqueness(self):
        passwords = [f"senha{i}" for i in range(1000)]
        sample = sample_passwords(passwords, 100)
        self.assertEqual(len(sample), 100)
        self.assertEqual(len(set(sample)), 100)
        self.assertLessEqual(set(sample), set(passwords))

    def test_same_seed_gives_same_sample(self):
        passwords = [f"senha{i}" for i in range(1000)]
        self.assertEqual(sample_passwords(passwords, 50, seed=7),
                         sample_passwords(passwords, 50, seed=7))
        self.assertNotEqual(sample_passwords(passwords, 50, seed=7),
                            sample_passwords(passwords, 50, seed=8))

    def test_sample_is_spread_over_the_file(self):
        # Amostragem por reservatório: não fica só com o começo do arquivo.
        passwords = [f"senha{i}" for i in range(10_000)]
        indexes = [int(p[5:]) for p in sample_passwords(passwords, 500)]
        self.assertGreater(max(indexes), 9000)
        self.assertLess(min(indexes), 1000)

    def test_read_rockyou_skips_invalid_lines(self):
        content = (
            b"senha123\n"
            b"com espaco\r\n"
            b"\n"
            b"\xe7\xe3o_latin1\n"           # não é UTF-8 válido
            b"ol\xc3\xa1\n"                 # "olá" em UTF-8
            b"tab\there\n"
            + b"x" * (MAX_PASSWORD_LENGTH + 1) + b"\n"
        )
        with tempfile.NamedTemporaryFile(delete=False) as file:
            file.write(content)
        self.addCleanup(os.remove, file.name)
        self.assertEqual(list(read_rockyou(file.name)),
                         ["senha123", "com espaco", "olá"])


class TrainingSampleTest(unittest.TestCase):
    """A amostra da RockYou salva no projeto."""

    @classmethod
    def setUpClass(cls):
        cls.sample = load_sample()

    def test_sample_is_not_empty_and_unique(self):
        self.assertGreater(len(self.sample), 1000)
        self.assertEqual(len(self.sample), len(set(self.sample)))

    def test_no_overlap_with_feature_lists(self):
        common = common_passwords()
        overlap = [p for p in self.sample if p.lower() in common]
        self.assertEqual(overlap, [])

    def test_all_passwords_are_valid(self):
        self.assertTrue(all(dataset.is_valid_password(p) for p in self.sample))


class LabeledDatasetTest(unittest.TestCase):
    PASSWORDS = ["123456", "k7GqT2mZr9XbWc4N!", "null", "NaN", "ol á"]

    def test_columns_are_consistent(self):
        data = build_labeled_dataset(self.PASSWORDS)
        self.assertEqual(list(data.columns),
                         ["password", "zxcvbn_score", "label", "label_code"])
        self.assertEqual(data["password"].tolist(), self.PASSWORDS)
        for row in data.itertuples():
            self.assertEqual(row.label, SCORE_TO_LABEL[row.zxcvbn_score])
        self.assertEqual(list(decode_labels(data["label_code"])),
                         data["label"].tolist())

    def test_csv_round_trip_keeps_passwords_as_text(self):
        data = build_labeled_dataset(self.PASSWORDS)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "labels.csv")
            save_labeled_dataset(data, path)
            loaded = load_labeled_dataset(path)
        self.assertEqual(loaded["password"].tolist(), self.PASSWORDS)
        self.assertEqual(loaded["label"].tolist(), data["label"].tolist())
        self.assertEqual(loaded["label_code"].tolist(), data["label_code"].tolist())


if __name__ == "__main__":
    unittest.main()
