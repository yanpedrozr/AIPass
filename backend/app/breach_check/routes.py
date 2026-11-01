from flask import current_app, jsonify, request

from . import bp
from .hibp import HIBPUnavailableError, pwned_count
from .similarity import analyze_similarity


@bp.post("")
@bp.post("/")
def check_password():
    """Verifica se a senha enviada no corpo JSON aparece em vazamentos.

    Só os 5 primeiros caracteres do SHA-1 da senha são enviados ao HIBP
    (k-anonimato). A senha vai só no corpo (nunca na URL) e não é armazenada
    nem registrada.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Envie um objeto JSON com o campo 'password'."), 400

    config = current_app.config
    try:
        count = pwned_count(
            data.get("password"),
            api_url=config["HIBP_API_URL"],
            timeout=config["HIBP_TIMEOUT_SECONDS"],
            user_agent=config["HIBP_USER_AGENT"],
        )
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except HIBPUnavailableError as error:
        return jsonify(error=f"{error} Tente novamente mais tarde."), 503

    response = jsonify(pwned=count > 0, count=count)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/similarity")
def check_similarity():
    """Procura senhas vazadas parecidas com a senha enviada no corpo JSON.

    A comparação é feita localmente, com a base de senhas vazadas do
    servidor: a senha não sai do servidor, não é armazenada nem registrada e
    não volta na resposta.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Envie um objeto JSON com o campo 'password'."), 400

    try:
        result = analyze_similarity(data.get("password"))
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except OSError:
        return jsonify(error="A base de senhas vazadas não está disponível."), 503

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/status")
def status():
    return jsonify(module="breach_check", status="ok",
                   provider="Have I Been Pwned (Pwned Passwords)")
