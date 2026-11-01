"""Cofre de credenciais do usuário (senhas cifradas com AES-GCM)."""
from flask import Blueprint

bp = Blueprint("vault", __name__)

from . import routes  # noqa: E402,F401
