"""Criptografia do cofre de senhas (derivação de chave, AES-GCM)."""
from flask import Blueprint

bp = Blueprint("crypto", __name__)

from . import routes  # noqa: E402,F401
