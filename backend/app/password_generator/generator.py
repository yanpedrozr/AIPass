"""Geração de senhas fortes com o módulo secrets (CSPRNG do sistema operacional)."""
import math
import secrets
import string
from itertools import combinations

MIN_LENGTH = 4
MAX_LENGTH = 128
DEFAULT_LENGTH = 16

CHARSETS = {
    "uppercase": string.ascii_uppercase,  # 26
    "lowercase": string.ascii_lowercase,  # 26
    "digits": string.digits,              # 10
    "symbols": string.punctuation,        # 32
}


def _selected_charsets(uppercase, lowercase, digits, symbols):
    flags = {
        "uppercase": uppercase,
        "lowercase": lowercase,
        "digits": digits,
        "symbols": symbols,
    }
    return [CHARSETS[name] for name, enabled in flags.items() if enabled]


def _validate(length, charsets):
    if not charsets:
        raise ValueError("Selecione pelo menos uma categoria de caracteres.")
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("O comprimento deve ser um número inteiro.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(
            f"O comprimento deve estar entre {MIN_LENGTH} e {MAX_LENGTH}."
        )
    if length < len(charsets):
        raise ValueError(
            "O comprimento deve ser pelo menos o número de categorias selecionadas."
        )


def generate_password(
    length=DEFAULT_LENGTH, uppercase=True, lowercase=True, digits=True, symbols=True
):
    """Gera uma senha com pelo menos um caractere de cada categoria selecionada.

    Usa amostragem por rejeição: sorteia todos os caracteres do conjunto
    completo e, se faltar alguma categoria, descarta e sorteia de novo.
    Assim toda senha válida tem a mesma probabilidade, sem o viés da
    abordagem "um de cada categoria + embaralhar". No pior caso permitido
    (4 caracteres com as 4 categorias) são ~15 tentativas em média; com
    comprimentos usuais quase sempre basta uma.
    """
    charsets = _selected_charsets(uppercase, lowercase, digits, symbols)
    _validate(length, charsets)
    pool = "".join(charsets)
    required = [set(charset) for charset in charsets]

    while True:
        password = "".join(secrets.choice(pool) for _ in range(length))
        chars = set(password)
        if all(chars & charset for charset in required):
            return password


def entropy_bits(
    length=DEFAULT_LENGTH, uppercase=True, lowercase=True, digits=True, symbols=True
):
    """Entropia exata (em bits) de uma senha gerada com essas opções.

    Como a distribuição é uniforme, a entropia é log2 do número de senhas
    válidas, calculado por inclusão-exclusão: todas as combinações do conjunto,
    menos as que não usam alguma das categorias exigidas.
    """
    charsets = _selected_charsets(uppercase, lowercase, digits, symbols)
    _validate(length, charsets)
    pool_size = sum(len(c) for c in charsets)

    valid = 0
    for k in range(len(charsets) + 1):
        for missing in combinations(charsets, k):
            remaining = pool_size - sum(len(c) for c in missing)
            valid += (-1) ** k * remaining**length
    return math.log2(valid)
