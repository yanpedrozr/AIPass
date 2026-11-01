"""Guarda as chaves do cofre apenas na memória do processo.

A chave do cofre é derivada da senha mestra no login e fica aqui, associada
ao identificador (jti) do token JWT, até o token expirar ou o usuário fazer
logout. Ela nunca é gravada no banco, em disco ou dentro do token.

Consequências:
- Reiniciar o servidor apaga todas as chaves e os usuários precisam logar de novo.
- Funciona com um único processo. Para rodar vários workers (ex.: gunicorn -w 4),
  seria preciso um armazenamento compartilhado em memória, como Redis.
"""
import threading
import time


class VaultKeyStore:
    def __init__(self):
        self._entries = {}  # jti -> (chave, expira_em)
        self._lock = threading.Lock()

    def put(self, jti: str, key: bytes, expires_at: float) -> None:
        with self._lock:
            self._purge_expired()
            self._entries[jti] = (key, expires_at)

    def get(self, jti: str) -> bytes | None:
        with self._lock:
            entry = self._entries.get(jti)
            if entry is None:
                return None
            key, expires_at = entry
            if expires_at <= time.time():
                del self._entries[jti]
                return None
            return key

    def remove(self, jti: str) -> None:
        with self._lock:
            self._entries.pop(jti, None)

    def _purge_expired(self) -> None:
        now = time.time()
        for jti in [j for j, (_, exp) in self._entries.items() if exp <= now]:
            del self._entries[jti]


vault_keys = VaultKeyStore()
