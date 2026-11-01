"""Derivação e verificação da senha mestra com PBKDF2-HMAC-SHA256."""
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LENGTH = 16  # bytes
KEY_LENGTH = 32  # bytes (256 bits)


def _kdf(salt: bytes, iterations: int) -> PBKDF2HMAC:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )


def hash_master_password(password: str, iterations: int) -> tuple[bytes, bytes]:
    """Gera um salt aleatório e deriva o hash da senha mestra.

    Retorna (salt, hash).
    """
    salt = os.urandom(SALT_LENGTH)
    derived = _kdf(salt, iterations).derive(password.encode("utf-8"))
    return salt, derived


def verify_master_password(
    password: str, salt: bytes, expected_hash: bytes, iterations: int
) -> bool:
    """Deriva a chave novamente e compara com o hash salvo.

    PBKDF2HMAC.verify usa comparação em tempo constante.
    """
    try:
        _kdf(salt, iterations).verify(password.encode("utf-8"), expected_hash)
        return True
    except InvalidKey:
        return False


def dummy_verify(password: str, iterations: int) -> None:
    """Executa uma derivação descartável quando o usuário não existe,
    para que o tempo de resposta não revele quais usuários estão cadastrados."""
    _kdf(os.urandom(SALT_LENGTH), iterations).derive(password.encode("utf-8"))
