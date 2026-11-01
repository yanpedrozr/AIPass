"""Análise de força de senhas com machine learning (scikit-learn)."""
from flask import Blueprint

bp = Blueprint("ml_analysis", __name__)

from . import routes  # noqa: E402,F401
