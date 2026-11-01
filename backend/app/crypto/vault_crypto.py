"""Criptografia do cofre: derivação da chave (PBKDF2) e cifragem com AES-GCM."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LENGTH = 16  # bytes
KEY_LENGTH = 32  # bytes -> AES-256
NONCE_LENGTH = 12  # bytes (96 bits), tamanho recomendado para o GCM


def generate_vault_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def derive_vault_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Deriva a chave do cofre a partir da senha mestra.

    Usa um salt diferente do salt de autenticação, então a chave do cofre
    é independente do hash de login salvo no banco.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: str, aad: bytes) -> tuple[bytes, bytes]:
    """Cifra com AES-GCM usando um nonce aleatório novo a cada chamada.

    Retorna (nonce, ciphertext). O ciphertext já inclui a tag de autenticação.
    """
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
    """Decifra e valida a tag. Lança cryptography.exceptions.InvalidTag se a
    chave estiver errada ou se os dados tiverem sido adulterados."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
