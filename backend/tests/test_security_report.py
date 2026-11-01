import random
import string
import unittest
from unittest import mock

import requests

from app.breach_check import hibp
from app.vault import security
from app.vault.security import SEVERITIES, similar_password_groups, weakness_reasons
from tests.test_vault import URL, VaultTestCase

REPORT_URL = URL + "/security-report"
ALPHABET = string.ascii_letters + string.digits + string.punctuation


def random_passwords(seed):
    """Gera senhas aleatórias com semente fixa, para os testes não variarem
    de uma execução para outra (cerca de 0,2% das senhas aleatórias ficam
    com similaridade "médio" com vazamentos por acaso)."""
    rng = random.Random(seed)

    def strong_password(length=20):
        return "".join(rng.choice(ALPHABET) for _ in range(length))

    return strong_password


class SecurityTestCase(VaultTestCase):
    """Cofre de teste com o HIBP simulado por uma tabela de senhas vazadas."""

    def setUp(self):
        super().setUp()
        self.strong_password = random_passwords(self.id())
        self.leaked = {}
        self.hibp_get.side_effect = self.fake_hibp

    def fake_hibp(self, url, **kwargs):
        prefix = url.rsplit("/", 1)[1]
        lines = []
        for password, count in self.leaked.items():
            digest = hibp.sha1_hex(password)
            if digest.startswith(prefix):
                lines.append(f"{digest[5:]}:{count}")
        return mock.Mock(status_code=200, text="\r\n".join(lines))

    def report(self):
        response = self.client.get(REPORT_URL, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        return response

    def alerts_of_type(self, body, kind):
        return [alert for alert in body["alerts"] if alert["type"] == kind]


class SecurityReportTest(SecurityTestCase):
    def test_requires_token(self):
        self.assertEqual(self.client.get(REPORT_URL).status_code, 401)

    def test_empty_vault(self):
        body = self.report().get_json()
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["summary"]["credentials"], 0)
        self.assertEqual(body["summary"]["score"], 100)

    def test_strong_unique_passwords_have_no_alerts(self):
        for service in ("Gmail", "Banco", "Netflix"):
            self.create(service, "alice", self.strong_password())
        body = self.report().get_json()
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["summary"]["at_risk"], 0)
        self.assertEqual(body["summary"]["score"], 100)
        self.assertEqual(body["checks"],
                         {"strength": True, "breach": True, "similarity": True})
        self.assertTrue(all(c["strength"] == "forte" for c in body["credentials"]))

    def test_breached_password_is_critical(self):
        self.leaked["senha123"] = 1128261
        cred = self.create("Gmail", "alice", "senha123")
        body = self.report().get_json()
        alert = body["alerts"][0]
        self.assertEqual(alert["severity"], "crítico")
        self.assertEqual(alert["type"], "breached")
        self.assertEqual(alert["credential_ids"], [cred["id"]])
        self.assertIn("Gmail", alert["message"])
        self.assertIn("1.128.261", alert["message"])
        self.assertIn("Troque agora", alert["message"])
        self.assertEqual(body["credentials"][0]["pwned_count"], 1128261)
        self.assertEqual(body["credentials"][0]["severity"], "crítico")

    def test_breached_password_has_no_leak_variation_alert(self):
        self.leaked["Dragon2024!"] = 64
        self.create("Gmail", "alice", "Dragon2024!")
        body = self.report().get_json()
        self.assertEqual(len(self.alerts_of_type(body, "breached")), 1)
        self.assertEqual(self.alerts_of_type(body, "leak_variation"), [])

    def test_leak_variation(self):
        self.create("Gmail", "alice", "Dragon2024!")
        body = self.report().get_json()
        [alert] = self.alerts_of_type(body, "leak_variation")
        self.assertEqual(alert["severity"], "alto")
        self.assertIn("variação de uma senha vazada", alert["message"])
        self.assertIn("sufixo de 5", alert["message"])

    def test_reused_password(self):
        password = self.strong_password()
        gmail = self.create("Gmail", "alice", password)
        face = self.create("Facebook", "alice", password)
        self.create("Banco", "alice", self.strong_password())
        body = self.report().get_json()
        [alert] = body["alerts"]
        self.assertEqual(alert["type"], "reused")
        self.assertEqual(alert["severity"], "alto")
        self.assertEqual(set(alert["credential_ids"]), {gmail["id"], face["id"]})
        self.assertIn("usam a mesma senha", alert["message"])
        self.assertIn("credential stuffing", alert["recommendation"])
        self.assertEqual(body["summary"]["at_risk"], 2)
        self.assertEqual(body["summary"]["score"], 33)

    def test_similar_passwords(self):
        self.create("Gmail", "alice", "SenhaForte!Gmail")
        self.create("Facebook", "alice", "SenhaForte!Face")
        body = self.report().get_json()
        [alert] = self.alerts_of_type(body, "similar")
        self.assertEqual(alert["severity"], "médio")
        self.assertEqual(sorted(alert["services"]), ["Facebook", "Gmail"])
        self.assertIn("muito parecidas", alert["message"])

    def test_weak_password_with_reasons(self):
        self.create("Wi-Fi", "", "abc123")
        body = self.report().get_json()
        [alert] = self.alerts_of_type(body, "weak")
        self.assertEqual(alert["severity"], "alto")
        self.assertIn("é fraca", alert["message"])
        self.assertIn("tem só 6 caracteres", alert["message"])
        self.assertIn("gerador", alert["recommendation"])

    def test_alerts_are_sorted_by_severity(self):
        self.leaked["senha123"] = 10
        self.create("A", "", "senha123")
        self.create("B", "", "senha123")
        body = self.report().get_json()
        order = [SEVERITIES.index(alert["severity"]) for alert in body["alerts"]]
        self.assertEqual(order, sorted(order))
        counts = body["summary"]["alerts_by_severity"]
        self.assertEqual(sum(counts.values()), len(body["alerts"]))

    def test_duplicate_services_are_labeled_with_username(self):
        password = self.strong_password()
        self.create("Gmail", "alice@gmail.com", password)
        self.create("Gmail", "trabalho@gmail.com", password)
        [alert] = self.report().get_json()["alerts"]
        self.assertEqual(sorted(alert["services"]),
                         ["Gmail (alice@gmail.com)", "Gmail (trabalho@gmail.com)"])

    def test_report_never_contains_passwords(self):
        passwords = ["senha123", "Dragon2024!", "SenhaForte!Gmail",
                     "SenhaForte!Face", "abc123"]
        self.leaked["senha123"] = 5
        for i, password in enumerate(passwords):
            self.create(f"Serviço {i}", "alice", password)
        response = self.report()
        for password in passwords:
            self.assertNotIn(password.encode(), response.data)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_only_hash_prefixes_are_sent_to_hibp(self):
        self.create("Gmail", "alice", "senha123")
        self.hibp_get.reset_mock()
        self.report()
        [call] = self.hibp_get.call_args_list
        self.assertTrue(call.args[0].endswith("/range/" + hibp.sha1_hex("senha123")[:5]))
        self.assertNotIn("senha123", repr(call))

    def test_reused_password_is_checked_once(self):
        password = self.strong_password()
        for service in ("A", "B", "C"):
            self.create(service, "", password)
        self.hibp_get.reset_mock()
        self.report()
        self.assertEqual(self.hibp_get.call_count, 1)

    def test_hibp_unavailable_still_returns_report(self):
        self.create("Wi-Fi", "", "abc123")
        self.hibp_get.side_effect = requests.Timeout()
        body = self.report().get_json()
        self.assertFalse(body["checks"]["breach"])
        self.assertIsNone(body["credentials"][0]["pwned_count"])
        self.assertTrue(self.alerts_of_type(body, "weak"))

    def test_very_long_passwords(self):
        self.create("Longa", "", self.strong_password(200))
        self.create("Enorme", "", self.strong_password(2000))
        self.hibp_get.reset_mock()
        body = self.report().get_json()
        self.assertEqual(body["alerts"], [])
        self.assertEqual(self.hibp_get.call_count, 1)  # só a de 200 caracteres

    def test_isolation_between_users(self):
        password = self.strong_password()
        self.create("Gmail", "alice", password)
        _, bob = self.login_new_user("bob")
        self.create("Gmail", "bob", password, headers=bob)
        self.assertEqual(self.report().get_json()["alerts"], [])


class RealTimeAlertsTest(SecurityTestCase):
    def test_create_returns_alerts_for_the_new_password(self):
        response = self.client.post(URL, headers=self.headers, json={
            "service": "Wi-Fi", "password": "abc123"})
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body["credential"]["service"], "Wi-Fi")
        self.assertIn("weak", [alert["type"] for alert in body["alerts"]])
        self.assertIn("checks", body)

    def test_create_with_strong_password_has_no_alerts(self):
        response = self.client.post(URL, headers=self.headers, json={
            "service": "Banco", "password": self.strong_password()})
        self.assertEqual(response.get_json()["alerts"], [])

    def test_create_detects_reuse_with_existing_credential(self):
        password = self.strong_password()
        self.create("Gmail", "alice", password)
        response = self.client.post(URL, headers=self.headers, json={
            "service": "Facebook", "password": password})
        [alert] = response.get_json()["alerts"]
        self.assertEqual(alert["type"], "reused")
        self.assertEqual(sorted(alert["services"]), ["Facebook", "Gmail"])

    def test_alerts_only_concern_the_saved_credential(self):
        password = self.strong_password()
        self.create("A", "", password)
        self.create("B", "", password)
        self.create("Wi-Fi", "", "abc123")
        response = self.client.post(URL, headers=self.headers, json={
            "service": "Banco", "password": self.strong_password()})
        self.assertEqual(response.get_json()["alerts"], [])

    def test_create_checks_only_the_new_password_in_hibp(self):
        self.create("A", "", self.strong_password())
        self.create("B", "", self.strong_password())
        self.hibp_get.reset_mock()
        self.create("C", "", self.strong_password())
        self.assertEqual(self.hibp_get.call_count, 1)

    def test_update_refreshes_alerts(self):
        self.leaked["senha123"] = 99
        cred = self.create("Gmail", "alice", "senha123")
        url = f"{URL}/{cred['id']}"

        response = self.client.patch(url, headers=self.headers, json={"service": "E-mail"})
        [breached] = [a for a in response.get_json()["alerts"] if a["type"] == "breached"]
        self.assertIn("E-mail", breached["message"])

        response = self.client.patch(url, headers=self.headers,
                                     json={"password": self.strong_password()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["alerts"], [])

    def test_save_still_works_when_hibp_is_down(self):
        self.hibp_get.side_effect = requests.ConnectionError()
        response = self.client.post(URL, headers=self.headers, json={
            "service": "Banco", "password": self.strong_password()})
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.get_json()["checks"]["breach"])


class SimilarGroupsTest(unittest.TestCase):
    def setUp(self):
        self.strong_password = random_passwords(self.id())

    def test_groups(self):
        groups = similar_password_groups([
            "SenhaForte!Gmail", "SenhaForte!Face",     # prefixo comum
            "Gmail2023!", "Gmail2024!",                # só o ano muda
            "dragon2024", "dr4g0n!",                   # mesma palavra-base vazada
            "flamengo10", "k7GqT2mZr9XbWc4N!",
        ])
        self.assertCountEqual([sorted(group) for group in groups], [
            ["SenhaForte!Face", "SenhaForte!Gmail"],
            ["Gmail2023!", "Gmail2024!"],
            ["dr4g0n!", "dragon2024"],
        ])

    def test_unrelated_passwords(self):
        for pair in (["flamengo10", "dragon2024"], ["Gmail2023!", "Brasil2023!"],
                     ["Maria2020", "Mario2021"], ["senha123", "amor123"]):
            with self.subTest(pair=pair):
                self.assertEqual(similar_password_groups(pair), [])

    def test_generated_passwords_are_not_similar(self):
        self.assertEqual(similar_password_groups(
            [self.strong_password(16) for _ in range(40)]), [])

    def test_groups_are_transitive(self):
        [group] = similar_password_groups(["casa1234!", "casa1235!", "casa1236!"])
        self.assertEqual(len(group), 3)


class WeaknessReasonsTest(unittest.TestCase):
    def test_reasons(self):
        strong_password = random_passwords(self.id())
        from app.ml_analysis.features import extract_features
        reasons = weakness_reasons(extract_features("qwerty2024"))
        self.assertIn("tem só 10 caracteres", reasons)
        self.assertIn("contém uma sequência de teclado (ex.: qwerty)", reasons)
        self.assertIn("contém um ano", reasons)
        self.assertIn("usa poucos tipos de caractere", reasons)
        self.assertEqual(weakness_reasons(extract_features(strong_password(20))), [])


if __name__ == "__main__":
    unittest.main()
