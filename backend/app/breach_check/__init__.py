"""Verificação de senhas vazadas (API Have I Been Pwned, k-anonimato) e
similaridade com senhas vazadas (TF-IDF + k-NN)."""
from flask import Blueprint

bp = Blueprint("breach_check", __name__)

from . import routes  # noqa: E402,F401
