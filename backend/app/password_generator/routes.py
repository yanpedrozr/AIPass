from flask import jsonify, request

from . import bp
from .generator import DEFAULT_LENGTH, entropy_bits, generate_password

OPTION_NAMES = ("uppercase", "lowercase", "digits", "symbols")
TRUE_VALUES = {"true", "1", "yes", "sim"}
FALSE_VALUES = {"false", "0", "no", "nao", "não"}


def _parse_bool(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
    raise ValueError(f"O parâmetro '{name}' deve ser true ou false.")


def _parse_length(value):
    if isinstance(value, bool):
        raise ValueError("O comprimento deve ser um número inteiro.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    raise ValueError("O comprimento deve ser um número inteiro.")


def _read_options():
    """Aceita as opções como query string (GET) ou corpo JSON (POST)."""
    if request.method == "POST":
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError("Envie as opções como um objeto JSON.")
    else:
        data = request.args

    options = {"length": _parse_length(data.get("length", DEFAULT_LENGTH))}
    for name in OPTION_NAMES:
        options[name] = _parse_bool(data.get(name, True), name)
    return options


@bp.route("/generate-password", methods=["GET", "POST"])
def generate():
    try:
        options = _read_options()
        password = generate_password(**options)
    except ValueError as error:
        return jsonify(error=str(error)), 400

    response = jsonify(
        password=password,
        entropy_bits=round(entropy_bits(**options), 2),
        options=options,
    )
    response.headers["Cache-Control"] = "no-store"
    return response
