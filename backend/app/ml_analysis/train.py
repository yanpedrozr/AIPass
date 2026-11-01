"""Treinamento do Random Forest que classifica a força das senhas.

Lê a base rotulada (dataset.py), extrai os atributos de cada senha
(features.py), separa treino e teste, treina o modelo e salva o modelo e as
métricas de avaliação.

Uso, a partir da pasta backend:

    python -m app.ml_analysis.train
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split

from .dataset import LABELED_FILE, load_labeled_dataset
from .features import FEATURE_NAMES, to_matrix
from .labels import LABELS, create_label_encoder

MODELS_DIR = Path(__file__).parent / "models"
MODEL_FILE = MODELS_DIR / "password_strength_rf.joblib"
METRICS_FILE = MODELS_DIR / "metrics.json"

TEST_SIZE = 0.2
RANDOM_STATE = 42

# Escolhidos por validação cruzada de 5 partes, só no conjunto de treino.
# Entre 50 e 300 árvores e 2 a 20 amostras por folha, o F1 macro ficou
# entre 0,804 e 0,808 (desvio de ±0,0035), ou seja, empatado. Esta
# configuração tem o mesmo desempenho com um modelo bem menor (≈10 MB
# contra 78 MB com 300 árvores e 2 por folha).
RF_PARAMS = {
    "n_estimators": 100,
    "min_samples_leaf": 10,
    # As classes estão razoavelmente equilibradas (28% a 36%), mas o peso
    # evita que "forte", a menor, seja prejudicada.
    "class_weight": "balanced",
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
}


def split_dataset(dataset):
    """Treino e teste estratificados: a proporção de cada rótulo é mantida."""
    features = np.array(to_matrix(dataset["password"]), dtype=float)
    labels = dataset["label_code"].to_numpy()
    return train_test_split(
        features, labels,
        test_size=TEST_SIZE,
        stratify=labels,
        random_state=RANDOM_STATE,
    )


def train_model(features, labels):
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(features, labels)
    return model


def evaluate(model, features, labels, encoder):
    """Métricas no conjunto de teste, com os rótulos em texto."""
    predicted = model.predict(features)
    # Ordem de força nas tabelas (fraca, média, forte), e não a ordem
    # alfabética do LabelEncoder.
    ordered_codes = encoder.transform(LABELS)
    return {
        "accuracy": accuracy_score(labels, predicted),
        "f1_macro": f1_score(labels, predicted, average="macro"),
        "per_class": {
            name: values
            for name, values in classification_report(
                labels, predicted,
                labels=ordered_codes, target_names=LABELS,
                output_dict=True, zero_division=0,
            ).items()
            if name in LABELS
        },
        "confusion_matrix": {
            "labels": list(LABELS),
            "rows_true_columns_predicted":
                confusion_matrix(labels, predicted, labels=ordered_codes).tolist(),
        },
    }


def baseline_accuracy(train_labels, test_labels):
    """Acurácia de quem sempre chuta a classe mais frequente do treino."""
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(np.zeros((len(train_labels), 1)), train_labels)
    return dummy.score(np.zeros((len(test_labels), 1)), test_labels)


def feature_importances(model):
    """Importância de cada atributo, da maior para a menor."""
    pairs = zip(FEATURE_NAMES, model.feature_importances_)
    return dict(sorted(((name, float(value)) for name, value in pairs),
                       key=lambda item: item[1], reverse=True))


def save_model(model, encoder, path=MODEL_FILE):
    """Salva o modelo junto com o que é preciso para usá-lo depois."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "label_encoder": encoder,
        "feature_names": FEATURE_NAMES,
        "sklearn_version": sklearn.__version__,
    }, path, compress=3)


def load_model(path=MODEL_FILE):
    """Carrega o modelo e confere se os atributos são os mesmos do código."""
    bundle = joblib.load(path)
    if tuple(bundle["feature_names"]) != FEATURE_NAMES:
        raise ValueError(
            "O modelo foi treinado com outros atributos. Treine novamente."
        )
    return bundle


def run(dataset_path=LABELED_FILE, model_path=MODEL_FILE,
        metrics_path=METRICS_FILE):
    dataset = load_labeled_dataset(dataset_path)
    encoder = create_label_encoder()
    x_train, x_test, y_train, y_test = split_dataset(dataset)

    model = train_model(x_train, y_train)
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {
            "file": Path(dataset_path).name,
            "total": len(dataset),
            "train": len(y_train),
            "test": len(y_test),
            "test_size": TEST_SIZE,
            "random_state": RANDOM_STATE,
        },
        "model": {"type": "RandomForestClassifier", "params": RF_PARAMS},
        "label_codes": {
            label: int(code)
            for label, code in zip(LABELS, encoder.transform(LABELS))
        },
        "train_accuracy": accuracy_score(y_train, model.predict(x_train)),
        "test": evaluate(model, x_test, y_test, encoder),
        "baseline_most_frequent_accuracy": baseline_accuracy(y_train, y_test),
        "feature_importances": feature_importances(model),
    }

    save_model(model, encoder, model_path)
    Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_path, "w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)
    return model, metrics


def print_summary(metrics):
    test = metrics["test"]
    print(f"Treino: {metrics['dataset']['train']} senhas | "
          f"Teste: {metrics['dataset']['test']} senhas")
    print(f"Acurácia no treino: {metrics['train_accuracy']:.4f}")
    print(f"Acurácia no teste:  {test['accuracy']:.4f} "
          f"(linha de base: {metrics['baseline_most_frequent_accuracy']:.4f})")
    print(f"F1 macro no teste:  {test['f1_macro']:.4f}")
    print("\nPor classe (teste):")
    for label, values in test["per_class"].items():
        print(f"  {label:6} precisão={values['precision']:.4f} "
              f"revocação={values['recall']:.4f} f1={values['f1-score']:.4f} "
              f"n={int(values['support'])}")
    print("\nMatriz de confusão (linha = real, coluna = previsto):")
    labels = test["confusion_matrix"]["labels"]
    print("         " + "".join(f"{label:>8}" for label in labels))
    for label, row in zip(labels, test["confusion_matrix"]["rows_true_columns_predicted"]):
        print(f"  {label:6} " + "".join(f"{value:>8}" for value in row))
    print("\nImportância dos atributos:")
    for name, value in metrics["feature_importances"].items():
        print(f"  {name:26} {value:.4f}")


if __name__ == "__main__":
    _, summary = run()
    print_summary(summary)
    print(f"\nModelo salvo em {MODEL_FILE}")
    print(f"Métricas salvas em {METRICS_FILE}")
