import base64
import io
import logging
import os
import tempfile
import unittest
from unittest import mock

from flask_jwt_extended import decode_token

from app import create_app
from app.auth.models import User
from app.breach_check import hibp
from app.config import Config
from app.crypto.key_store import vault_keys
from app.extensions import db
from app.vault.models import Credential

MASTER_PASSWORD = "minha-senha-mestra-forte"
URL = "/api/vault"


class VaultTestCase(unittest.TestCase):
    """Base: cada teste usa um banco SQLite novo em arquivo temporário (para
    poder inspecionar os bytes gravados) e já começa com 'alice' logada."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.tmpdir.name, "test_vault.db")
        self.db_path = db_path

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
            # Menos iterações só para os testes rodarem rápido
            PBKDF2_ITERATIONS = 1_000

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.token, self.headers = self.login_new_user("alice")

        # Salvar uma credencial consulta o HIBP para os alertas: simula uma
        # resposta vazia (nenhum vazamento) para os testes não usarem a rede.
        patcher = mock.patch.object(hibp.requests, "get")
        self.hibp_get = patcher.start()
        self.hibp_get.return_value = mock.Mock(status_code=200, text="")
        self.addCleanup(patcher.stop)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()
        self.tmpdir.cleanup()

    def login(self, username):
        response = self.client.post(
            "/api/auth/login",
            json={"username": username, "master_password": MASTER_PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        token = response.json["access_token"]
        return token, {"Authorization": f"Bearer {token}"}

    def login_new_user(self, username):
        self.client.post(
            "/api/auth/register",
            json={"username": username, "master_password": MASTER_PASSWORD},
        )
        return self.login(username)

    def create(self, service, username, password, headers=None):
        response = self.client.post(
            URL,
            headers=headers or self.headers,
            json={"service": service, "username": username, "password": password},
        )
        self.assertEqual(response.status_code, 201)
        return response.json["credential"]

    def vault_key(self, token=None):
        with self.app.app_context():
            jti = decode_token(token or self.token)["jti"]
        return vault_keys.get(jti)

    def raw_database(self):
        with self.app.app_context():
            db.engine.dispose()
        with open(self.db_path, "rb") as file:
            return file.read()


class VaultCrudTest(VaultTestCase):
    def test_requires_token(self):
        self.assertEqual(self.client.get(URL).status_code, 401)
        self.assertEqual(self.client.post(URL, json={}).status_code, 401)

    def test_create_returns_decrypted_credential(self):
        cred = self.create("Gmail", "alice@gmail.com", "S3nh@-do-Gmail!")
        self.assertEqual(cred["service"], "Gmail")
        self.assertEqual(cred["username"], "alice@gmail.com")
        self.assertEqual(cred["password"], "S3nh@-do-Gmail!")
        self.assertIn("id", cred)

    def test_username_is_optional(self):
        response = self.client.post(
            URL, headers=self.headers, json={"service": "Wi-Fi", "password": "abc"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["credential"]["username"], "")

    def test_invalid_bodies_return_400(self):
        bodies = [
            {"username": "x", "password": "abc"},       # sem service
            {"service": "X", "username": "x"},          # sem password
            {"service": "   ", "password": "abc"},      # service vazio
            {"service": "X", "password": ""},           # password vazia
            {"service": 123, "password": "abc"},        # tipo errado
            {"service": "X" * 129, "password": "abc"},  # longo demais
            ["não", "é", "objeto"],
        ]
        for body in bodies:
            with self.subTest(body=body):
                response = self.client.post(URL, headers=self.headers, json=body)
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json)

    def test_list_is_sorted_by_service_ignoring_case(self):
        for service in ("gmail", "Banco", "amazon"):
            self.create(service, "alice", "senha")
        credentials = self.client.get(URL, headers=self.headers).json["credentials"]
        self.assertEqual([c["service"] for c in credentials], ["amazon", "Banco", "gmail"])

    def test_list_decrypts_every_field(self):
        self.create("Gmail", "alice@gmail.com", "senha-1")
        self.create("Banco", "ag-0001", "senha-2")
        credentials = self.client.get(URL, headers=self.headers).json["credentials"]
        self.assertEqual(
            [(c["service"], c["username"], c["password"]) for c in credentials],
            [("Banco", "ag-0001", "senha-2"), ("Gmail", "alice@gmail.com", "senha-1")],
        )

    def test_get_one(self):
        cred = self.create("Gmail", "alice", "senha")
        response = self.client.get(f"{URL}/{cred['id']}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["credential"]["password"], "senha")

    def test_patch_changes_only_given_fields(self):
        cred = self.create("Gmail", "alice", "senha-antiga")
        response = self.client.patch(
            f"{URL}/{cred['id']}", headers=self.headers, json={"service": "Google"}
        )
        self.assertEqual(response.status_code, 200)
        updated = response.json["credential"]
        self.assertEqual(
            (updated["service"], updated["username"], updated["password"]),
            ("Google", "alice", "senha-antiga"),
        )

    def test_put_updates_password(self):
        cred = self.create("Gmail", "alice", "senha-antiga")
        self.client.put(
            f"{URL}/{cred['id']}", headers=self.headers, json={"password": "senha-nova"}
        )
        response = self.client.get(f"{URL}/{cred['id']}", headers=self.headers)
        self.assertEqual(response.json["credential"]["password"], "senha-nova")

    def test_update_without_fields_returns_400(self):
        cred = self.create("Gmail", "alice", "senha")
        response = self.client.patch(f"{URL}/{cred['id']}", headers=self.headers, json={})
        self.assertEqual(response.status_code, 400)

    def test_delete(self):
        cred = self.create("Gmail", "alice", "senha")
        response = self.client.delete(f"{URL}/{cred['id']}", headers=self.headers)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(
            self.client.get(f"{URL}/{cred['id']}", headers=self.headers).status_code, 404
        )
        self.assertEqual(self.client.get(URL, headers=self.headers).json["credentials"], [])

    def test_unknown_id_returns_404(self):
        for method in ("get", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    f"{URL}/nao-existe", headers=self.headers, json={"service": "X"}
                )
                self.assertEqual(response.status_code, 404)

    def test_responses_are_not_cached(self):
        response = self.client.get(URL, headers=self.headers)
        self.assertEqual(response.headers["Cache-Control"], "no-store")


class VaultEncryptionTest(VaultTestCase):
    def test_model_has_no_plaintext_columns(self):
        columns = set(Credential.__table__.columns.keys())
        self.assertFalse({"service", "username", "password"} & columns)

    def test_database_has_no_plaintext_fields(self):
        secrets = ["ServicoSecreto", "usuario.secreto@exemplo.com", "SenhaSecreta!123"]
        self.create(*secrets)
        raw = self.raw_database()
        for value in secrets:
            with self.subTest(value=value):
                self.assertNotIn(value.encode("utf-8"), raw)

    def test_each_credential_has_unique_12_byte_nonce(self):
        for i in range(20):
            self.create("Mesmo serviço", "mesmo usuário", "mesma senha")
        with self.app.app_context():
            rows = Credential.query.all()
            nonces = [row.nonce for row in rows]
            ciphertexts = [row.ciphertext for row in rows]
        self.assertTrue(all(len(n) == 12 for n in nonces))
        self.assertEqual(len(set(nonces)), 20)
        # Mesmo conteúdo, nonces diferentes -> ciphertexts diferentes
        self.assertEqual(len(set(ciphertexts)), 20)

    def test_nonce_changes_on_every_edit(self):
        cred = self.create("Gmail", "alice", "senha")
        seen = set()
        for change in ({"service": "Google"}, {"username": "bob"}, {"password": "outra"}):
            with self.app.app_context():
                seen.add(db.session.get(Credential, cred["id"]).nonce)
            self.client.patch(f"{URL}/{cred['id']}", headers=self.headers, json=change)
        with self.app.app_context():
            seen.add(db.session.get(Credential, cred["id"]).nonce)
        self.assertEqual(len(seen), 4)

    def test_ciphertext_copied_to_another_row_is_rejected(self):
        first = self.create("Gmail", "alice", "senha-1")
        second = self.create("Banco", "alice", "senha-2")
        with self.app.app_context():
            source = db.session.get(Credential, first["id"])
            target = db.session.get(Credential, second["id"])
            target.nonce, target.ciphertext = source.nonce, source.ciphertext
            db.session.commit()
        response = self.client.get(f"{URL}/{second['id']}", headers=self.headers)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("senha-1", response.get_data(as_text=True))

    def test_tampered_ciphertext_is_rejected(self):
        cred = self.create("Gmail", "alice", "senha")
        with self.app.app_context():
            row = db.session.get(Credential, cred["id"])
            tampered = bytearray(row.ciphertext)
            tampered[0] ^= 0x01
            row.ciphertext = bytes(tampered)
            db.session.commit()
        self.assertEqual(self.client.get(URL, headers=self.headers).status_code, 500)


class VaultKeyTest(VaultTestCase):
    def test_key_is_kept_in_memory(self):
        key = self.vault_key()
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)

    def test_key_is_not_in_token(self):
        key = self.vault_key()
        payload = base64.urlsafe_b64decode(self.token.split(".")[1] + "==")
        for encoded in (key, key.hex().encode(), base64.b64encode(key)):
            self.assertNotIn(encoded, payload)

    def test_key_is_not_in_database(self):
        self.create("Gmail", "alice", "senha")
        key = self.vault_key()
        raw = self.raw_database()
        for encoded in (key, key.hex().encode(), base64.b64encode(key)):
            self.assertNotIn(encoded, raw)

    def test_vault_key_is_independent_from_login_hash(self):
        with self.app.app_context():
            user = User.query.filter_by(username="alice").one()
            salt, vault_salt, password_hash = user.salt, user.vault_salt, user.password_hash
        self.assertNotEqual(salt, vault_salt)
        self.assertNotEqual(self.vault_key(), password_hash)

    def test_new_login_derives_same_key(self):
        self.create("Gmail", "alice", "senha")
        token, headers = self.login("alice")
        self.assertEqual(self.vault_key(token), self.vault_key())
        credentials = self.client.get(URL, headers=headers).json["credentials"]
        self.assertEqual(credentials[0]["password"], "senha")

    def test_logout_removes_key_and_blocks_access(self):
        response = self.client.post("/api/auth/logout", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.vault_key())
        self.assertEqual(self.client.get(URL, headers=self.headers).status_code, 401)


class VaultIsolationTest(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.alice_cred = self.create("Gmail", "alice", "senha-da-alice")
        _, self.bob_headers = self.login_new_user("bob")

    def test_other_user_sees_empty_vault(self):
        response = self.client.get(URL, headers=self.bob_headers)
        self.assertEqual(response.json["credentials"], [])

    def test_other_user_cannot_touch_credential(self):
        path = f"{URL}/{self.alice_cred['id']}"
        for method in ("get", "patch", "put", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    path, headers=self.bob_headers, json={"password": "hack"}
                )
                self.assertEqual(response.status_code, 404)
        # A credencial da alice continua intacta
        response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.json["credential"]["password"], "senha-da-alice")


class VaultLoggingTest(VaultTestCase):
    def test_logs_do_not_contain_credentials(self):
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        root = logging.getLogger()
        sql_logger = logging.getLogger("sqlalchemy.engine")
        previous_levels = (root.level, sql_logger.level)
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        sql_logger.setLevel(logging.INFO)  # inclui SQL com parâmetros
        try:
            cred = self.create("ServicoSecreto", "usuario.secreto", "SenhaSecreta!123")
            self.client.get(URL, headers=self.headers)
            self.client.patch(
                f"{URL}/{cred['id']}", headers=self.headers, json={"password": "NovaSecreta!456"}
            )
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_levels[0])
            sql_logger.setLevel(previous_levels[1])

        logs = buffer.getvalue()
        self.assertIn("INSERT INTO credentials", logs)  # os logs foram capturados
        for value in ("ServicoSecreto", "usuario.secreto", "SenhaSecreta!123",
                      "NovaSecreta!456", MASTER_PASSWORD):
            with self.subTest(value=value):
                self.assertNotIn(value, logs)


if __name__ == "__main__":
    unittest.main()
