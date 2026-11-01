"""Rótulos de força das senhas para treinar o Random Forest.

Cada senha recebe um rótulo ("fraca", "média" ou "forte") a partir do score
do zxcvbn, que estima quantas tentativas um atacante precisaria para
adivinhá-la. O LabelEncoder do scikit-learn converte os rótulos em números.
"""
from sklearn.preprocessing import LabelEncoder
from zxcvbn import zxcvbn

WEAK = "fraca"
MEDIUM = "média"
STRONG = "forte"
LABELS = (WEAK, MEDIUM, STRONG)

# Score do zxcvbn (0 a 4) -> rótulo.
#   0: muito fácil de adivinhar (< 10^3 tentativas)
#   1: fácil de adivinhar (< 10^6)
#   2: razoavelmente difícil (< 10^8)
#   3: difícil (< 10^10)
#   4: muito difícil (>= 10^10)
SCORE_TO_LABEL = {
    0: WEAK,
    1: WEAK,
    2: MEDIUM,
    3: STRONG,
    4: STRONG,
}


def zxcvbn_score(password):
    """Score de 0 a 4 do zxcvbn."""
    return zxcvbn(password)["score"]


def label_password(password):
    """Rótulo ("fraca", "média" ou "forte") de uma senha."""
    if not isinstance(password, str) or not password:
        raise ValueError("A senha deve ser um texto não vazio.")
    return SCORE_TO_LABEL[zxcvbn_score(password)]


def label_passwords(passwords):
    """Rótulos de uma lista de senhas, na mesma ordem."""
    return [label_password(password) for password in passwords]


def create_label_encoder():
    """LabelEncoder já ajustado com os três rótulos.

    O ajuste é feito com a lista fixa LABELS, e não com os rótulos da base,
    para que a codificação seja sempre a mesma, mesmo que alguma classe
    esteja ausente numa amostra. O LabelEncoder ordena as classes em ordem
    alfabética: forte = 0, fraca = 1, média = 2. Os números identificam as
    classes e não indicam ordem de força, o que não é problema para o
    Random Forest.
    """
    encoder = LabelEncoder()
    encoder.fit(LABELS)
    return encoder


def encode_labels(labels, encoder=None):
    """Rótulos em texto -> números."""
    encoder = encoder or create_label_encoder()
    return encoder.transform(labels)


def decode_labels(codes, encoder=None):
    """Números -> rótulos em texto."""
    encoder = encoder or create_label_encoder()
    return encoder.inverse_transform(codes)
