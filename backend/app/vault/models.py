from datetime import datetime, timezone

from ..extensions import db


def _utcnow():
    return datetime.now(timezone.utc)


class Credential(db.Model):
    __tablename__ = "credentials"

    # UUID gerado antes da cifragem, pois faz parte do AAD do AES-GCM
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    # service, username e password são cifrados juntos (JSON) com AES-GCM.
    # Nonce único de 12 bytes + ciphertext (com a tag GCM). Nada da
    # credencial fica em texto puro no banco.
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def aad(self) -> bytes:
        # Vincula o ciphertext ao dono e à credencial: se alguém copiar os dados
        # cifrados de uma linha para outra no banco, a decifragem falha.
        return f"credential:{self.user_id}:{self.id}".encode("utf-8")
