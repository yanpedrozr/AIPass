import json
import os
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np

from app.ml_analysis.dataset import (
    build_labeled_dataset,
    load_sample,
    save_labeled_dataset,
)
from app.ml_analysis.features import FEATURE_NAMES, to_matrix
from app.ml_analysis.labels import LABELS
from app.ml_analysis.train import MODEL_FILE, load_model, run, split_dataset


class TrainingTest(unittest.TestCase):
    """Treino completo numa base pequena, em uma pasta temporária."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        base = Path(cls.directory.name)
        cls.dataset_path = base / "labels.csv"
        cls.model_path = base / "model.joblib"
        cls.metrics_path = base / "metrics.json"

        cls.dataset = build_labeled_dataset(load_sample()[:1500])
        save_labeled_dataset(cls.dataset, cls.dataset_path)
        cls.model, cls.metrics = run(cls.dataset_path, cls.model_path,
                                     cls.metrics_path)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_split_is_stratified_and_disjoint(self):
        x_train, x_test, y_train, y_test = split_dataset(self.dataset)
        self.assertEqual(len(y_test), 300)
        self.assertEqual(x_train.shape[1], len(FEATURE_NAMES))
        for code in np.unique(self.dataset["label_code"]):
            share_train = np.mean(y_train == code)
            share_test = np.mean(y_test == code)
            self.assertAlmostEqual(share_train, share_test, delta=0.02)

    def test_model_beats_baseline(self):
        test = self.metrics["test"]
        self.assertGreater(test["accuracy"],
                           self.metrics["baseline_most_frequent_accuracy"])

    def test_metrics_file(self):
        with open(self.metrics_path, encoding="utf-8") as file:
            saved = json.load(file)
        self.assertEqual(set(saved["test"]["per_class"]), set(LABELS))
        self.assertEqual(saved["test"]["confusion_matrix"]["labels"], list(LABELS))
        matrix = np.array(saved["test"]["confusion_matrix"]["rows_true_columns_predicted"])
        self.assertEqual(matrix.sum(), saved["dataset"]["test"])
        self.assertEqual(set(saved["feature_importances"]), set(FEATURE_NAMES))
        self.assertAlmostEqual(sum(saved["feature_importances"].values()), 1.0)

    def test_saved_model_predicts_labels(self):
        bundle = load_model(self.model_path)
        passwords = ["123456", "k7GqT2mZr9XbWc4N!"]
        codes = bundle["model"].predict(to_matrix(passwords))
        labels = bundle["label_encoder"].inverse_transform(codes)
        self.assertTrue(set(labels) <= set(LABELS))

    def test_load_rejects_model_with_other_features(self):
        bundle = joblib.load(self.model_path)
        bundle["feature_names"] = FEATURE_NAMES[:-1]
        path = Path(self.directory.name) / "old.joblib"
        joblib.dump(bundle, path)
        with self.assertRaises(ValueError):
            load_model(path)


@unittest.skipUnless(os.path.exists(MODEL_FILE), "modelo ainda não treinado")
class TrainedModelTest(unittest.TestCase):
    """O modelo salvo no projeto classifica casos óbvios corretamente."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = load_model()

    def predict(self, passwords):
        codes = self.bundle["model"].predict(to_matrix(passwords))
        return list(self.bundle["label_encoder"].inverse_transform(codes))

    def test_obvious_cases(self):
        self.assertEqual(self.predict(["123456", "password", "abc123"]),
                         ["fraca"] * 3)
        self.assertEqual(self.predict(["k7GqT2mZr9XbWc4N!", "V#9pLq2$Xm8!Rt4z"]),
                         ["forte"] * 2)


if __name__ == "__main__":
    unittest.main()
