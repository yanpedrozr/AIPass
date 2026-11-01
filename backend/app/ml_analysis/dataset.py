"""Base de treino: amostra da RockYou rotulada com o zxcvbn.

A amostra é sorteada da RockYou completa e não contém nenhuma senha das
listas usadas nos atributos (features.common_passwords). Assim, o modelo
não é treinado com as mesmas senhas que definem os atributos
is_common_password e common_substring_length (vazamento de dados).

Uso, a partir da pasta backend:

    # 1. Sortear a amostra (precisa do rockyou.txt completo, só uma vez)
    python -m app.ml_analysis.dataset sample --rockyou caminho/rockyou.txt

    # 2. Rotular a amostra e salvar o CSV
    python -m app.ml_analysis.dataset label
"""
import argparse
import random
from pathlib import Path

import pandas as pd

from .features import common_passwords
from .labels import SCORE_TO_LABEL, create_label_encoder, zxcvbn_score

DATA_DIR = Path(__file__).parent / "data"
SAMPLE_FILE = DATA_DIR / "rockyou-sample.txt"
LABELED_FILE = DATA_DIR / "training-labels.csv"

DEFAULT_SAMPLE_SIZE = 100_000
DEFAULT_SEED = 42

# Senhas muito longas na RockYou são quase sempre lixo (trechos de HTML,
# e-mails colados) e deixam o zxcvbn lento.
MAX_PASSWORD_LENGTH = 64


def is_valid_password(password):
    """Descarta linhas vazias, longas demais ou com caracteres de controle."""
    return 0 < len(password) <= MAX_PASSWORD_LENGTH and password.isprintable()


def read_rockyou(path):
    """Senhas válidas da RockYou, uma por linha.

    O arquivo mistura codificações. Linhas que não são UTF-8 válido são
    descartadas.
    """
    with open(path, "rb") as file:
        for raw in file:
            try:
                password = raw.rstrip(b"\r\n").decode("utf-8")
            except UnicodeDecodeError:
                continue
            if is_valid_password(password):
                yield password


def sample_passwords(passwords, size, seed=DEFAULT_SEED, excluded=frozenset()):
    """Amostra aleatória de até `size` senhas distintas.

    Usa amostragem por reservatório, que lê o arquivo uma única vez sem
    carregar os 14 milhões de linhas na memória. Senhas cuja versão em
    minúsculas está em `excluded` são ignoradas. O rockyou.txt já tem uma
    linha por senha distinta; repetições eventuais são removidas no fim.
    """
    rng = random.Random(seed)
    reservoir = []
    count = 0
    for password in passwords:
        if password.lower() in excluded:
            continue
        count += 1
        if len(reservoir) < size:
            reservoir.append(password)
        else:
            index = rng.randrange(count)
            if index < size:
                reservoir[index] = password
    return list(dict.fromkeys(reservoir))


def sample_rockyou(rockyou_path, size=DEFAULT_SAMPLE_SIZE, seed=DEFAULT_SEED):
    """Amostra da RockYou sem as senhas das listas dos atributos."""
    return sample_passwords(
        read_rockyou(rockyou_path), size, seed, excluded=common_passwords()
    )


def save_sample(passwords, path=SAMPLE_FILE):
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        file.writelines(password + "\n" for password in passwords)


def load_sample(path=SAMPLE_FILE):
    with open(path, encoding="utf-8") as file:
        return [line.rstrip("\n") for line in file if line.rstrip("\n")]


def build_labeled_dataset(passwords, encoder=None):
    """Tabela com a senha, o score do zxcvbn, o rótulo e o rótulo codificado."""
    encoder = encoder or create_label_encoder()
    scores = [zxcvbn_score(password) for password in passwords]
    labels = [SCORE_TO_LABEL[score] for score in scores]
    return pd.DataFrame({
        "password": passwords,
        "zxcvbn_score": scores,
        "label": labels,
        "label_code": encoder.transform(labels),
    })


def save_labeled_dataset(dataset, path=LABELED_FILE):
    dataset.to_csv(path, index=False, encoding="utf-8")


def load_labeled_dataset(path=LABELED_FILE):
    # keep_default_na=False: senhas como "null" ou "NaN" continuam texto.
    return pd.read_csv(path, encoding="utf-8", keep_default_na=False,
                       dtype={"password": str})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    sample = commands.add_parser("sample", help="sorteia a amostra da RockYou")
    sample.add_argument("--rockyou", required=True, type=Path,
                        help="caminho do rockyou.txt completo")
    sample.add_argument("--size", type=int, default=DEFAULT_SAMPLE_SIZE)
    sample.add_argument("--seed", type=int, default=DEFAULT_SEED)

    commands.add_parser("label", help="rotula a amostra com o zxcvbn")

    args = parser.parse_args(argv)
    if args.command == "sample":
        passwords = sample_rockyou(args.rockyou, args.size, args.seed)
        save_sample(passwords)
        print(f"{len(passwords)} senhas salvas em {SAMPLE_FILE}")
    else:
        dataset = build_labeled_dataset(load_sample())
        save_labeled_dataset(dataset)
        print(f"{len(dataset)} senhas rotuladas salvas em {LABELED_FILE}")
        print(dataset["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
