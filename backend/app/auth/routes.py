import re

from flask import current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    decode_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy.exc import IntegrityError

from ..crypto.key_store import vault_keys
from ..crypto.vault_crypto import derive_vault_key, generate_vault_salt
from ..extensions import db, jwt
from . import bp
from .models import User
from .security import dummy_verify, hash_master_password, verify_master_password

SESSION_EXPIRED_MESSAGE = "Sessão expirada ou encerrada. Faça login novamente."


# Um token só é aceito enquanto a chave do cofre dele estiver na memória.
# Assim, logout e reinício do servidor invalidam o token automaticamente.
@jwt.token_in_blocklist_loader
def _token_without_vault_key(jwt_header, jwt_payload):
    return vault_keys.get(jwt_payload["jti"]) is None


@jwt.revoked_token_loader
def _revoked_token_response(jwt_header, jwt_payload):
    return jsonify(error=SESSION_EXPIRED_MESSAGE), 401

USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
MIN_MASTER_PASSWORD_LENGTH = 12
# Limite superior para evitar abuso de CPU com senhas gigantes no PBKDF2
MAX_MASTER_PASSWORD_LENGTH = 1024


def _read_credentials():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("master_password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None
    return username.strip().lower(), password


@bp.post("/register")
def register():
    username, password = _read_credentials()
    if username is None:
        return jsonify(error="Informe 'username' e 'master_password'."), 400

    if not USERNAME_PATTERN.fullmatch(username):
        return jsonify(
            error="O nome de usuário deve ter de 3 a 32 caracteres: letras, números, '_', '.' ou '-'."
        ), 400

    if not MIN_MASTER_PASSWORD_LENGTH <= len(password) <= MAX_MASTER_PASSWORD_LENGTH:
        return jsonify(
            error=f"A senha mestra deve ter pelo menos {MIN_MASTER_PASSWORD_LENGTH} caracteres."
        ), 400

    if User.query.filter_by(username=username).first():
        return jsonify(error="Nome de usuário já está em uso."), 409

    iterations = current_app.config["PBKDF2_ITERATIONS"]
    salt, password_hash = hash_master_password(password, iterations)
    user = User(
        username=username,
        salt=salt,
        password_hash=password_hash,
        iterations=iterations,
        vault_salt=generate_vault_salt(),
        vault_iterations=iterations,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        # Dois cadastros simultâneos com o mesmo nome
        db.session.rollback()
        return jsonify(error="Nome de usuário já está em uso."), 409

    return jsonify(user=user.to_dict()), 201


@bp.post("/login")
def login():
    username, password = _read_credentials()
    if username is None:
        return jsonify(error="Informe 'username' e 'master_password'."), 400

    if len(password) > MAX_MASTER_PASSWORD_LENGTH:
        return jsonify(error="Usuário ou senha mestra inválidos."), 401

    user = User.query.filter_by(username=username).first()
    if user is None:
        dummy_verify(password, current_app.config["PBKDF2_ITERATIONS"])
        return jsonify(error="Usuário ou senha mestra inválidos."), 401

    if not verify_master_password(password, user.salt, user.password_hash, user.iterations):
        return jsonify(error="Usuário ou senha mestra inválidos."), 401

    # Senha correta: deriva a chave do cofre e a mantém só em memória,
    # vinculada ao jti deste token, até ele expirar ou haver logout.
    vault_key = derive_vault_key(password, user.vault_salt, user.vault_iterations)
    access_token = create_access_token(identity=str(user.id))
    claims = decode_token(access_token)
    vault_keys.put(claims["jti"], vault_key, claims["exp"])

    return jsonify(access_token=access_token, token_type="Bearer", user=user.to_dict())


@bp.post("/logout")
@jwt_required()
def logout():
    vault_keys.remove(get_jwt()["jti"])
    return jsonify(message="Logout realizado.")


@bp.get("/me")
@jwt_required()
def me():
    user = db.session.get(User, int(get_jwt_identity()))
    if user is None:
        return jsonify(error="Usuário não encontrado."), 404
    return jsonify(user=user.to_dict())
