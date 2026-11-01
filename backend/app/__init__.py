import os

from flask import Flask, jsonify
from flask_cors import CORS

from .config import Config
from .extensions import db, jwt


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"sqlite:///{os.path.join(app.instance_path, 'vault.db')}"
        )

    # Libera as rotas /api/* para o frontend React (Vite)
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    db.init_app(app)
    jwt.init_app(app)

    from .auth import bp as auth_bp
    from .crypto import bp as crypto_bp
    from .password_generator import bp as generator_bp
    from .ml_analysis import bp as ml_bp
    from .breach_check import bp as breach_bp
    from .vault import bp as vault_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(vault_bp, url_prefix="/api/vault")
    app.register_blueprint(crypto_bp, url_prefix="/api/crypto")
    app.register_blueprint(generator_bp, url_prefix="/api/generator")
    app.register_blueprint(ml_bp, url_prefix="/api/analysis")
    app.register_blueprint(breach_bp, url_prefix="/api/breach")

    with app.app_context():
        db.create_all()

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    return app
