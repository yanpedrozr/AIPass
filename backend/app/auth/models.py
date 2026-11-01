from datetime import datetime, timezone

from ..extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    # Salt aleatório (16 bytes) e hash PBKDF2 (32 bytes) da senha mestra.
    # A senha mestra em si nunca é armazenada.
    salt = db.Column(db.LargeBinary(16), nullable=False)
    password_hash = db.Column(db.LargeBinary(32), nullable=False)
    # Guardado por usuário para permitir aumentar as iterações no futuro
    # sem invalidar os hashes já existentes.
    iterations = db.Column(db.Integer, nullable=False)
    # Salt próprio para derivar a chave de criptografia do cofre, diferente do
    # salt de login. A chave derivada NÃO é armazenada, só o salt.
    vault_salt = db.Column(db.LargeBinary(16), nullable=False)
    vault_iterations = db.Column(db.Integer, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "created_at": self.created_at.isoformat(),
        }
