"""Geração de senhas seguras."""
from flask import Blueprint

bp = Blueprint("password_generator", __name__)

from . import routes  # noqa: E402,F401
