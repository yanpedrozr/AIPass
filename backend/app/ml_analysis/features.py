"""Extração de características das senhas para o modelo de machine learning.

Converte cada senha em um vetor de atributos numéricos (comprimento,
contagem por categoria de caractere, entropia e presença de padrões comuns)
que o Random Forest usa como entrada.
"""
import math
import re
import string
from functools import lru_cache
from pathlib import Path

UPPERCASE = frozenset(string.ascii_uppercase)  # 26
LOWERCASE = frozenset(string.ascii_lowercase)  # 26
DIGITS = frozenset(string.digits)              # 10
SYMBOLS_POOL_SIZE = len(string.punctuation)    # 32

# Listas públicas de senhas comuns do SecLists (licença MIT): as 10.000 mais
# comuns em geral e as 150 mais comuns em português. Detalhes da origem em
# data/README.md.
DATA_DIR = Path(__file__).parent / "data"
COMMON_PASSWORDS_FILES = (
    DATA_DIR / "10k-most-common.txt",
    DATA_DIR / "Portugese_Pwdb_common-password-list-top-150.txt",
)

# Tamanho mínimo para uma sequência, repetição ou trecho da lista contar
# como padrão. Abaixo disso quase toda senha teria "padrões" por acaso.
MIN_PATTERN_LENGTH = 3
MIN_COMMON_SUBSTRING_LENGTH = 4

# Substituições "leet" mais usadas (p@ssw0rd -> password).
LEET_TABLE = str.maketrans({
    "@": "a", "4": "a",
    "8": "b",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
})

# Linhas do teclado QWERTY, com e sem Shift, para detectar "qwerty", "asdf",
# "!@#$" etc.
KEYBOARD_ROWS = (
    "1234567890-=",
    "!@#$%^&*()_+",
    "qwertyuiop[]",
    "asdfghjkl;'",
    "zxcvbnm,./",
)
KEYBOARD_POSITIONS = {
    char: (row, column)
    for row, keys in enumerate(KEYBOARD_ROWS)
    for column, char in enumerate(keys)
}

YEAR_PATTERN = re.compile(r"(19|20)\d\d")
TRAILING_DIGITS = re.compile(r"(.*?)(\d*)", re.DOTALL)

# Ordem fixa das colunas: o modelo precisa receber sempre a mesma ordem
# no treino e na predição.
FEATURE_NAMES = (
    "length",
    "uppercase_count",
    "lowercase_count",
    "digit_count",
    "special_count",
    "entropy_bits",
    "is_common_password",
    "common_substring_length",
    "sequence_length",
    "keyboard_sequence_length",
    "repeated_char_length",
    "contains_year",
)


def entropy_bits(password):
    """Entropia estimada (em bits) pelo tamanho do conjunto de caracteres.

    E = L * log2(N), em que L é o comprimento e N é a soma dos tamanhos das
    categorias presentes na senha (maiúsculas, minúsculas, dígitos e
    especiais). Qualquer caractere fora das três primeiras conta como
    especial.
    """
    if not password:
        return 0.0

    chars = set(password)
    pool_size = 0
    if chars & UPPERCASE:
        pool_size += len(UPPERCASE)
    if chars & LOWERCASE:
        pool_size += len(LOWERCASE)
    if chars & DIGITS:
        pool_size += len(DIGITS)
    if chars - UPPERCASE - LOWERCASE - DIGITS:
        pool_size += SYMBOLS_POOL_SIZE
    return len(password) * math.log2(pool_size)


@lru_cache(maxsize=1)
def common_passwords():
    """Senhas de todas as listas juntas (minúsculas), lidas uma única vez."""
    passwords = set()
    for path in COMMON_PASSWORDS_FILES:
        with open(path, encoding="utf-8") as file:
            passwords.update(line.strip().lower() for line in file if line.strip())
    return frozenset(passwords)


def _variants(password):
    """A senha em minúsculas e também com as substituições leet desfeitas.

    Há duas versões com leet desfeito: uma na senha inteira e outra que
    preserva os dígitos do final, para o padrão palavra + números
    ("s3nh@123" -> "senha123", e não "senhai23").
    """
    lowered = password.lower()
    word, digits = TRAILING_DIGITS.fullmatch(lowered).groups()
    return {lowered, lowered.translate(LEET_TABLE), word.translate(LEET_TABLE) + digits}


def is_common_password(password):
    """True se a senha inteira está na lista, ignorando maiúsculas e leet."""
    common = common_passwords()
    return any(variant in common for variant in _variants(password))


def common_substring_length(password):
    """Comprimento do maior trecho da senha que é uma senha da lista.

    Pega casos como "Dragon2024!" (contém "dragon") ou "xX_m0nk3y_Xx"
    (contém "monkey" com leet). Trechos com menos de
    MIN_COMMON_SUBSTRING_LENGTH caracteres são ignorados; retorna 0 se não
    houver nenhum.
    """
    common = common_passwords()
    longest = 0
    for variant in _variants(password):
        for start in range(len(variant)):
            for end in range(start + max(longest + 1, MIN_COMMON_SUBSTRING_LENGTH),
                             len(variant) + 1):
                if variant[start:end] in common:
                    longest = end - start
    return longest


def _longest_run(password, step):
    """Maior trecho em que cada par de caracteres vizinhos dá o mesmo passo.

    `step(a, b)` devolve um identificador do passo entre dois caracteres
    (ex.: +1 para "a" -> "b") ou None se não houver relação. Trechos menores
    que MIN_PATTERN_LENGTH não contam e o resultado é 0.
    """
    longest = run = 1 if password else 0
    previous_step = None
    for a, b in zip(password, password[1:]):
        current = step(a, b)
        if current is not None and current == previous_step:
            run += 1
        elif current is not None:
            run = 2
        else:
            run = 1
        previous_step = current
        longest = max(longest, run)
    return longest if longest >= MIN_PATTERN_LENGTH else 0


def _alphabet_step(a, b):
    """+1/-1 entre letras ou dígitos consecutivos ("abc", "321")."""
    a, b = a.lower(), b.lower()
    # Testa a classe antes do ord(): alguns caracteres Unicode viram dois ao
    # passar por lower() ("İ" -> "i̇").
    same_class = (a in LOWERCASE and b in LOWERCASE) or (a in DIGITS and b in DIGITS)
    if not same_class:
        return None
    diff = ord(b) - ord(a)
    return diff if diff in (1, -1) else None


def _keyboard_step(a, b):
    """(linha, +1/-1) entre teclas vizinhas na mesma linha do teclado."""
    pos_a = KEYBOARD_POSITIONS.get(a.lower())
    pos_b = KEYBOARD_POSITIONS.get(b.lower())
    if pos_a is None or pos_b is None or pos_a[0] != pos_b[0]:
        return None
    diff = pos_b[1] - pos_a[1]
    return (pos_a[0], diff) if diff in (1, -1) else None


def _repeat_step(a, b):
    return 0 if a == b else None


def sequence_length(password):
    """Maior sequência alfabética ou numérica ("abcd", "4321")."""
    return _longest_run(password, _alphabet_step)


def keyboard_sequence_length(password):
    """Maior sequência de teclas vizinhas ("qwerty", "asdf", "!@#$")."""
    return _longest_run(password, _keyboard_step)


def repeated_char_length(password):
    """Maior repetição do mesmo caractere ("aaa", "1111")."""
    return _longest_run(password, _repeat_step)


def contains_year(password):
    """True se a senha contém um ano entre 1900 e 2099."""
    return YEAR_PATTERN.search(password) is not None


def extract_features(password):
    """Retorna os atributos numéricos da senha como dicionário."""
    if not isinstance(password, str):
        raise ValueError("A senha deve ser um texto.")

    uppercase = sum(char in UPPERCASE for char in password)
    lowercase = sum(char in LOWERCASE for char in password)
    digits = sum(char in DIGITS for char in password)

    return {
        "length": len(password),
        "uppercase_count": uppercase,
        "lowercase_count": lowercase,
        "digit_count": digits,
        "special_count": len(password) - uppercase - lowercase - digits,
        "entropy_bits": entropy_bits(password),
        "is_common_password": int(is_common_password(password)),
        "common_substring_length": common_substring_length(password),
        "sequence_length": sequence_length(password),
        "keyboard_sequence_length": keyboard_sequence_length(password),
        "repeated_char_length": repeated_char_length(password),
        "contains_year": int(contains_year(password)),
    }


def to_vector(password):
    """Atributos da senha como lista, na ordem de FEATURE_NAMES."""
    features = extract_features(password)
    return [features[name] for name in FEATURE_NAMES]


def to_matrix(passwords):
    """Matriz de atributos (uma linha por senha) para o scikit-learn."""
    return [to_vector(password) for password in passwords]
