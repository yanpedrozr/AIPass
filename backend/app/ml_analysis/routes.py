from flask import jsonify, request

from . import bp
from .predictor import ModelNotAvailableError, analyze, get_model


@bp.post("")
@bp.post("/")
def analyze_password():
    """Classifica a força da senha enviada no corpo JSON.

    A senha vai só no corpo (nunca na URL, que costuma aparecer em logs e no
    histórico do navegador) e não é armazenada nem registrada.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Envie um objeto JSON com o campo 'password'."), 400

    try:
        result = analyze(data.get("password"))
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except ModelNotAvailableError as error:
        return jsonify(error=str(error)), 503

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/status")
def status():
    try:
        bundle = get_model()
    except ModelNotAvailableError as error:
        return jsonify(module="ml_analysis", status="model unavailable",
                       error=str(error)), 503
    return jsonify(
        module="ml_analysis",
        status="ok",
        model=type(bundle["model"]).__name__,
        labels=list(bundle["label_encoder"].classes_),
        features=list(bundle["feature_names"]),
    )
