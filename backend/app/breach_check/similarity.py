"""Análise de similaridade da senha com senhas vazadas, por machine learning.

O HIBP só responde se a senha exata vazou: "Dragon2024!" pode nunca ter
aparecido, mas "dragon" aparece milhões de vezes, e ataques de dicionário
testam justamente variações assim (maiúsculas, leet, anos e símbolos no fim).
Esta análise procura senhas vazadas parecidas com a senha informada, em duas
etapas:

1. Busca por vizinhos mais próximos (k-NN): cada senha vazada vira um vetor
   TF-IDF de n-gramas de 2 a 4 caracteres, depois de passar para minúsculas e
   desfazer o leet. A senha consultada é vetorizada do mesmo jeito e as senhas
   vazadas mais próximas são as de maior similaridade do cosseno. Como os
   vetores TF-IDF são normalizados, o cosseno é o produto escalar.
2. Palavra-base vazada: testa se a senha é uma senha vazada com poucos
   dígitos ou símbolos antes ou depois ("Dragon2024!" = "dragon" + "2024!"),
   que é a regra mais usada por ferramentas como o hashcat.

A base de senhas vazadas é a amostra da RockYou e as listas de senhas comuns
do SecLists, as mesmas de ml_analysis/data. Nada é enviado para fora do
servidor.
"""
from functools import lru_cache

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from ..ml_analysis.dataset import load_sample
from ..ml_analysis.features import LEET_TABLE, _variants, common_passwords

# Mesmo limite da análise de força: a busca da palavra-base cresce com o
# quadrado do comprimento.
MAX_PASSWORD_LENGTH = 128

# Quantas senhas vazadas parecidas são devolvidas.
TOP_K = 5

# Palavra-base: pelo menos 4 caracteres (como common_substring_length) e no
# máximo 6 dígitos ou símbolos somados antes e depois, o bastante para um ano
# com símbolo ("2024!", "@2026"). Com mais que isso, o acréscimo já é longo
# demais para as regras comuns de ataque.
MIN_BASE_LENGTH = 4
MAX_AFFIX_LENGTH = 6

# Limites de similaridade do cosseno para o risco, calibrados comparando
# variações de senhas vazadas com senhas aleatórias do gerador (ver README).
HIGH_SIMILARITY = 0.7
MEDIUM_SIMILARITY = 0.45

RISKS = ("baixo", "médio", "alto")


def validate_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Informe a senha no campo 'password'.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"A senha deve ter no máximo {MAX_PASSWORD_LENGTH} caracteres."
        )


def normalize(password):
    """Minúsculas e leet desfeito, para "P@ssw0rd" e "password" ficarem iguais."""
    return password.lower().translate(LEET_TABLE)


class LeakIndex:
    """Senhas vazadas vetorizadas para a busca por similaridade."""

    def __init__(self, passwords):
        self.passwords = sorted(set(passwords))
        if not self.passwords:
            raise ValueError("A base de senhas vazadas está vazia.")
        self.lowered = frozenset(password.lower() for password in self.passwords)
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(2, 4), sublinear_tf=True,
            lowercase=False,
        )
        self.matrix = self.vectorizer.fit_transform(
            [normalize(password) for password in self.passwords]
        )

    def nearest(self, password, k=TOP_K):
        """As k senhas vazadas mais parecidas, com a similaridade do cosseno."""
        query = self.vectorizer.transform([normalize(password)])
        scores = (self.matrix @ query.T).toarray().ravel()
        k = min(k, len(scores))
        top = np.argpartition(-scores, k - 1)[:k]
        top = top[np.argsort(-scores[top], kind="stable")]
        return [(self.passwords[i], float(scores[i])) for i in top if scores[i] > 0]

    def leaked_base(self, password):
        """Maior senha vazada que forma a senha com poucos dígitos/símbolos em volta.

        Retorna (base vazada, início, fim) do trecho na senha ou None. O
        trecho é comparado sem diferenciar maiúsculas e com o leet desfeito,
        então "S3nh@123!" tem a base "senha" (trecho "S3nh@").
        """
        lowered = password.lower()
        size = len(lowered)
        lead = next((i for i, char in enumerate(lowered) if char.isalpha()), size)
        trail = next((i for i, char in enumerate(reversed(lowered)) if char.isalpha()),
                     size)

        best = None
        for start in range(min(lead, MAX_AFFIX_LENGTH) + 1):
            for end in range(size, start + MIN_BASE_LENGTH - 1, -1):
                affixes = start + size - end
                if affixes > MAX_AFFIX_LENGTH or size - end > trail:
                    break
                if best and end - start <= best[2] - best[1]:
                    break
                matches = _variants(lowered[start:end]) & self.lowered
                if matches:
                    best = (min(matches), start, end)
                    break
        return best


@lru_cache(maxsize=1)
def get_index():
    """Monta o índice uma única vez (≈4 s) e reaproveita nas requisições."""
    return LeakIndex(set(load_sample()) | common_passwords())


def transformations(password, leaked, start, end):
    """Como a senha difere da palavra-base vazada, sem repetir a senha."""
    base = password[start:end]
    found = []
    if base != base.lower():
        found.append("letras maiúsculas")
    if base.lower() != leaked:
        found.append("substituições leet (ex.: @ → a, 0 → o)")
    if start:
        found.append(f"prefixo de {start} dígito(s)/símbolo(s)")
    if end < len(password):
        found.append(f"sufixo de {len(password) - end} dígito(s)/símbolo(s)")
    return found


def risk_level(similarity, base):
    if base is not None or similarity >= HIGH_SIMILARITY:
        return "alto"
    if similarity >= MEDIUM_SIMILARITY:
        return "médio"
    return "baixo"


def analyze_similarity(password, index=None):
    """Risco, senhas vazadas parecidas e palavra-base vazada (se houver)."""
    validate_password(password)
    index = index or get_index()

    similar = index.nearest(password)
    similarity = similar[0][1] if similar else 0.0
    base = index.leaked_base(password)

    result = {
        "risk": risk_level(similarity, base),
        "similarity": round(similarity, 4),
        "similar_passwords": [
            {"password": leaked, "similarity": round(score, 4)}
            for leaked, score in similar
        ],
        "leaked_base": None,
    }
    if base is not None:
        leaked, start, end = base
        result["leaked_base"] = {
            "password": leaked,
            "exact": start == 0 and end == len(password),
            "transformations": transformations(password, leaked, start, end),
        }
    return result
