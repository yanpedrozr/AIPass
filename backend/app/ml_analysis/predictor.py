"""Classificação da força de uma senha com o Random Forest treinado."""
from functools import lru_cache

from .features import extract_features, to_vector
from .labels import LABELS
from .train import MODEL_FILE, load_model

# Limite de tamanho para a análise. Os atributos de padrões comuns crescem
# com o quadrado do comprimento, e o gerador também para em 128.
MAX_PASSWORD_LENGTH = 128


class ModelNotAvailableError(RuntimeError):
    """O modelo ainda não foi treinado ou não pôde ser carregado."""


@lru_cache(maxsize=1)
def get_model():
    """Carrega o modelo do disco uma única vez e reaproveita nas requisições."""
    if not MODEL_FILE.exists():
        raise ModelNotAvailableError(
            "Modelo não encontrado. Treine com: python -m app.ml_analysis.train"
        )
    try:
        bundle = load_model(MODEL_FILE)
    except Exception as error:
        raise ModelNotAvailableError(f"Não foi possível carregar o modelo: {error}")
    # Uma senha por requisição: paralelizar entre núcleos só adiciona atraso.
    bundle["model"].set_params(n_jobs=1)
    return bundle


def validate_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Informe a senha no campo 'password'.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"A senha deve ter no máximo {MAX_PASSWORD_LENGTH} caracteres."
        )


def analyze(password):
    """Rótulo previsto, probabilidade de cada rótulo e atributos da senha."""
    validate_password(password)
    bundle = get_model()
    model, encoder = bundle["model"], bundle["label_encoder"]

    probabilities = model.predict_proba([to_vector(password)])[0]
    by_label = dict(zip(encoder.inverse_transform(model.classes_), probabilities))
    strength = max(by_label, key=by_label.get)

    features = extract_features(password)
    features["entropy_bits"] = round(features["entropy_bits"], 2)
    return {
        "strength": strength,
        "probabilities": {
            label: round(float(by_label.get(label, 0.0)), 4) for label in LABELS
        },
        "features": features,
    }
