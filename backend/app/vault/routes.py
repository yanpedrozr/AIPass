import json
import uuid
from functools import wraps

from cryptography.exceptions import InvalidTag
from flask import current_app, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from ..auth.routes import SESSION_EXPIRED_MESSAGE
from ..crypto.key_store import vault_keys
from ..crypto.vault_crypto import decrypt, encrypt
from ..extensions import db
from . import bp
from .models import Credential
from .security import credential_alerts, hibp_settings, security_report

FIELD_LIMITS = {"service": 128, "username": 256, "password": 4096}
DECRYPT_ERROR_MESSAGE = "Não foi possível descriptografar a credencial."


def vault_session_required(fn):
    """Exige um JWT válido e entrega à rota a chave do cofre (vinda da memória)
    e o id do usuário. A chave é passada como argumento, sem ficar em globais."""

    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        key = vault_keys.get(get_jwt()["jti"])
        if key is None:
            return jsonify(error=SESSION_EXPIRED_MESSAGE), 401
        return fn(key, int(get_jwt_identity()), *args, **kwargs)

    return wrapper


@bp.after_request
def _no_store(response):
    # Respostas do cofre contêm senhas: impede cache no navegador/proxies
    response.headers["Cache-Control"] = "no-store"
    return response


def _validate(data, partial):
    """Valida o corpo do request. Retorna (campos, erro)."""
    if not isinstance(data, dict):
        return None, "Envie um JSON com 'service', 'username' e 'password'."

    fields = {}
    for name, max_length in FIELD_LIMITS.items():
        if name not in data:
            if not partial and name != "username":
                return None, f"O campo '{name}' é obrigatório."
            continue
        value = data[name]
        if not isinstance(value, str):
            return None, f"O campo '{name}' deve ser texto."
        if name == "service":
            value = value.strip()
        if name != "username" and not value:
            return None, f"O campo '{name}' não pode ficar vazio."
        if len(value) > max_length:
            return None, f"O campo '{name}' deve ter no máximo {max_length} caracteres."
        fields[name] = value

    if partial and not fields:
        return None, "Informe ao menos um campo para atualizar."
    return fields, None


def _encrypt_fields(credential, key, fields):
    """Cifra service, username e password juntos. Cada cifragem gera um nonce
    novo, inclusive ao editar."""
    plaintext = json.dumps(
        {name: fields[name] for name in FIELD_LIMITS}, ensure_ascii=False
    )
    credential.nonce, credential.ciphertext = encrypt(key, plaintext, credential.aad())


def _decrypt_fields(credential, key):
    """Decifra os campos só em memória, durante o request."""
    return json.loads(
        decrypt(key, credential.nonce, credential.ciphertext, credential.aad())
    )


def _serialize(credential, fields):
    return {
        "id": credential.id,
        **fields,
        "created_at": credential.created_at.isoformat(),
        "updated_at": credential.updated_at.isoformat(),
    }


def _get_owned(user_id, credential_id):
    return Credential.query.filter_by(id=credential_id, user_id=user_id).first()


def _decrypt_all(key, user_id):
    """Todas as credenciais do usuário decifradas (só em memória).

    Pode lançar InvalidTag, que as rotas transformam em erro 500.
    """
    return [
        _serialize(credential, _decrypt_fields(credential, key))
        for credential in Credential.query.filter_by(user_id=user_id).all()
    ]


def _with_alerts(credential_id, key, user_id, status=200):
    """Resposta com a credencial salva e os alertas da senha dela."""
    try:
        items = _decrypt_all(key, user_id)
    except InvalidTag:
        return jsonify(error=DECRYPT_ERROR_MESSAGE), 500
    security = credential_alerts(
        credential_id, items, hibp_settings(current_app.config)
    )
    credential = next(item for item in items if item["id"] == credential_id)
    return jsonify(credential=credential, **security), status


@bp.get("")
@vault_session_required
def list_credentials(key, user_id):
    try:
        items = _decrypt_all(key, user_id)
    except InvalidTag:
        return jsonify(error=DECRYPT_ERROR_MESSAGE), 500
    # O banco não conhece o nome do serviço, então a ordenação é feita aqui
    items.sort(key=lambda item: item["service"].casefold())
    return jsonify(credentials=items)


@bp.post("")
@vault_session_required
def create_credential(key, user_id):
    fields, error = _validate(request.get_json(silent=True), partial=False)
    if error:
        return jsonify(error=error), 400
    fields.setdefault("username", "")

    credential = Credential(id=str(uuid.uuid4()), user_id=user_id)
    _encrypt_fields(credential, key, fields)
    db.session.add(credential)
    db.session.commit()
    return _with_alerts(credential.id, key, user_id, status=201)


@bp.get("/security-report")
@vault_session_required
def get_security_report(key, user_id):
    """Alertas e recomendações para todas as credenciais do usuário.

    As senhas são decifradas só em memória e passam pela análise de força,
    pelo HIBP (k-anonimato) e pela similaridade com vazamentos. A resposta
    cita os serviços, nunca as senhas.
    """
    try:
        items = _decrypt_all(key, user_id)
    except InvalidTag:
        return jsonify(error=DECRYPT_ERROR_MESSAGE), 500
    return jsonify(security_report(items, hibp_settings(current_app.config)))


@bp.get("/<credential_id>")
@vault_session_required
def get_credential(key, user_id, credential_id):
    credential = _get_owned(user_id, credential_id)
    if credential is None:
        return jsonify(error="Credencial não encontrada."), 404
    try:
        fields = _decrypt_fields(credential, key)
    except InvalidTag:
        return jsonify(error=DECRYPT_ERROR_MESSAGE), 500
    return jsonify(credential=_serialize(credential, fields))


@bp.route("/<credential_id>", methods=["PUT", "PATCH"])
@vault_session_required
def update_credential(key, user_id, credential_id):
    credential = _get_owned(user_id, credential_id)
    if credential is None:
        return jsonify(error="Credencial não encontrada."), 404

    changes, error = _validate(request.get_json(silent=True), partial=True)
    if error:
        return jsonify(error=error), 400

    try:
        fields = _decrypt_fields(credential, key)
    except InvalidTag:
        return jsonify(error=DECRYPT_ERROR_MESSAGE), 500
    fields.update(changes)
    _encrypt_fields(credential, key, fields)
    db.session.commit()
    return _with_alerts(credential.id, key, user_id)


@bp.delete("/<credential_id>")
@vault_session_required
def delete_credential(key, user_id, credential_id):
    credential = _get_owned(user_id, credential_id)
    if credential is None:
        return jsonify(error="Credencial não encontrada."), 404
    db.session.delete(credential)
    db.session.commit()
    return "", 204
