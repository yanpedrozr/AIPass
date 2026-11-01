"""Alertas e recomendações de segurança para as credenciais do cofre.

Junta os três analisadores (força pelo Random Forest, vazamentos pelo HIBP e
similaridade com senhas vazadas) e acrescenta o que nenhum deles vê sozinho:
senhas reutilizadas ou muito parecidas entre credenciais do próprio usuário,
a porta de entrada do credential stuffing.

As funções recebem as credenciais já decifradas (em memória, durante o
request) e devolvem alertas que citam o serviço, nunca a senha.
"""
from concurrent.futures import ThreadPoolExecutor

from ..breach_check.hibp import MAX_PASSWORD_LENGTH as HIBP_MAX_LENGTH
from ..breach_check.hibp import HIBPUnavailableError, pwned_count
from ..breach_check.similarity import analyze_similarity, get_index, normalize
from ..ml_analysis import predictor
from ..ml_analysis.predictor import ModelNotAvailableError

# Da mais para a menos grave; os alertas saem nessa ordem.
SEVERITIES = ("crítico", "alto", "médio", "baixo")

# Abaixo disso a senha recebe alerta de "curta" mesmo que o modelo a
# classifique como forte.
MIN_RECOMMENDED_LENGTH = 12

# Duas senhas do usuário são "muito parecidas" com similaridade do cosseno
# (TF-IDF de n-gramas, o mesmo vetorizador da similaridade com vazamentos) a
# partir deste valor ou com a mesma palavra-base vazada. Com 0,6, pares como
# "SenhaForte!Gmail" e "SenhaForte!Face" são detectados, e nenhum de 3.000
# pares aleatórios da RockYou nem de 2.000 pares do gerador passa (ver README).
SIMILAR_PASSWORDS_THRESHOLD = 0.6

# Consultas ao HIBP em paralelo no relatório completo.
HIBP_WORKERS = 8

GENERATOR_TIP = (
    "Use o gerador para criar uma senha com 16 ou mais caracteres, misturando "
    "letras maiúsculas, minúsculas, números e símbolos."
)


def hibp_settings(config):
    return {
        "api_url": config["HIBP_API_URL"],
        "timeout": config["HIBP_TIMEOUT_SECONDS"],
        "user_agent": config["HIBP_USER_AGENT"],
    }


# --- Análise de cada senha ---------------------------------------------------

def _breach_count(password, settings):
    """Vezes que a senha vazou, ou None se o HIBP não respondeu."""
    if len(password) > HIBP_MAX_LENGTH:
        return 0  # longa demais para estar numa base de vazamentos
    try:
        return pwned_count(password, **settings)
    except HIBPUnavailableError:
        return None


def analyze_passwords(passwords, settings):
    """{senha: análise} para cada senha distinta.

    A análise tem "strength" e "features" (Random Forest), "pwned_count"
    (HIBP) e "similarity" (similaridade com vazamentos). Um analisador
    indisponível deixa o campo como None, sem impedir os outros.
    """
    passwords = list(dict.fromkeys(passwords))
    workers = max(1, min(HIBP_WORKERS, len(passwords)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        counts = list(pool.map(lambda p: _breach_count(p, settings), passwords))

    analyses = {}
    for password, count in zip(passwords, counts):
        analysis = {"strength": None, "features": None, "pwned_count": count,
                    "similarity": None}
        # Acima de 128 caracteres a senha é forte pelo comprimento e os dois
        # analisadores locais recusam a entrada.
        if len(password) <= predictor.MAX_PASSWORD_LENGTH:
            try:
                result = predictor.analyze(password)
                analysis["strength"] = result["strength"]
                analysis["features"] = result["features"]
            except ModelNotAvailableError:
                pass
            try:
                analysis["similarity"] = analyze_similarity(password)
            except OSError:
                pass
        analyses[password] = analysis
    return analyses


# --- Reutilização entre credenciais -------------------------------------------

def _components(size, linked):
    """Grupos ligados (union-find) de índices 0..size-1."""
    parent = list(range(size))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, j in linked:
        parent[find(i)] = find(j)
    groups = {}
    for i in range(size):
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def similar_password_groups(passwords):
    """Grupos de senhas distintas muito parecidas entre si.

    Duas senhas ficam no mesmo grupo se a similaridade do cosseno for pelo
    menos SIMILAR_PASSWORDS_THRESHOLD ou se tiverem a mesma palavra-base
    vazada ("dragon2024" e "dr4g0n!"). A ligação é transitiva.
    """
    passwords = [p for p in dict.fromkeys(passwords)
                 if len(p) <= predictor.MAX_PASSWORD_LENGTH]
    if len(passwords) < 2:
        return []
    try:
        index = get_index()
    except OSError:
        return []

    vectors = index.vectorizer.transform([normalize(p) for p in passwords])
    scores = (vectors @ vectors.T).toarray()
    bases = [index.leaked_base(p) for p in passwords]

    linked = []
    for i in range(len(passwords)):
        for j in range(i + 1, len(passwords)):
            same_base = bases[i] and bases[j] and bases[i][0] == bases[j][0]
            if scores[i, j] >= SIMILAR_PASSWORDS_THRESHOLD or same_base:
                linked.append((i, j))
    return [[passwords[i] for i in group]
            for group in _components(len(passwords), linked) if len(group) > 1]


# --- Alertas -------------------------------------------------------------------

def _join(names):
    """"A", "A e B", "A, B e C"."""
    names = list(names)
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " e " + names[-1]


def _labels(entries):
    """Nome de cada credencial nas mensagens: o serviço, e também o usuário
    quando há mais de uma credencial do mesmo serviço."""
    totals = {}
    for entry in entries:
        key = entry["service"].casefold()
        totals[key] = totals.get(key, 0) + 1
    labels = {}
    for entry in entries:
        label = entry["service"]
        if totals[entry["service"].casefold()] > 1 and entry["username"]:
            label = f"{label} ({entry['username']})"
        labels[entry["id"]] = label
    return labels


def _alert(severity, kind, entries, labels, message, recommendation):
    return {
        "severity": severity,
        "type": kind,
        "credential_ids": [entry["id"] for entry in entries],
        "services": [labels[entry["id"]] for entry in entries],
        "message": message,
        "recommendation": recommendation,
    }


def _format_count(count):
    return f"{count:,}".replace(",", ".")


def weakness_reasons(features):
    """Motivos legíveis a partir dos atributos usados pelo modelo."""
    reasons = []
    if features["length"] < MIN_RECOMMENDED_LENGTH:
        reasons.append(f"tem só {features['length']} caracteres")
    if features["is_common_password"]:
        reasons.append("está entre as senhas mais comuns")
    elif features["common_substring_length"]:
        reasons.append("contém uma senha comum")
    if features["sequence_length"]:
        reasons.append("contém uma sequência (ex.: abc, 123)")
    if features["keyboard_sequence_length"]:
        reasons.append("contém uma sequência de teclado (ex.: qwerty)")
    if features["repeated_char_length"]:
        reasons.append("repete o mesmo caractere")
    if features["contains_year"]:
        reasons.append("contém um ano")
    categories = sum(features[name] > 0 for name in (
        "uppercase_count", "lowercase_count", "digit_count", "special_count"))
    if categories < 3:
        reasons.append("usa poucos tipos de caractere")
    return reasons


def _password_alerts(entry, analysis, labels):
    """Alertas de uma credencial olhando só a própria senha."""
    alerts = []
    label = labels[entry["id"]]
    count = analysis["pwned_count"]

    if count:
        alerts.append(_alert(
            "crítico", "breached", [entry], labels,
            f"A senha de {label} apareceu {_format_count(count)} vez(es) em "
            "vazamentos conhecidos. Troque agora.",
            "Troque a senha no site do serviço por uma nova, criada pelo "
            "gerador, e não a use em nenhum outro lugar.",
        ))

    similarity = analysis["similarity"]
    if similarity and not count and similarity["risk"] in ("alto", "médio"):
        base = similarity["leaked_base"]
        details = f" ({', '.join(base['transformations'])})" if (
            base and base["transformations"]) else ""
        if similarity["risk"] == "alto":
            alerts.append(_alert(
                "alto", "leak_variation", [entry], labels,
                f"A senha de {label} é uma variação de uma senha vazada "
                f"conhecida{details}.",
                "Maiúsculas, leet e números ou símbolos no fim não protegem: "
                "essas variações são as primeiras testadas em ataques de "
                f"dicionário. {GENERATOR_TIP}",
            ))
        else:
            alerts.append(_alert(
                "baixo", "leak_similarity", [entry], labels,
                f"A senha de {label} é parecida com senhas vazadas conhecidas.",
                "Evite palavras e padrões comuns. " + GENERATOR_TIP,
            ))

    features = analysis["features"]
    strength = analysis["strength"]
    length = len(entry["password"])
    if strength in ("fraca", "média"):
        reasons = weakness_reasons(features)
        detail = f": {_join(reasons)}" if reasons else ""
        alerts.append(_alert(
            "alto" if strength == "fraca" else "médio", "weak", [entry], labels,
            f"A senha de {label} é {strength}{detail}.", GENERATOR_TIP,
        ))
    elif length < MIN_RECOMMENDED_LENGTH:
        alerts.append(_alert(
            "baixo", "short", [entry], labels,
            f"A senha de {label} é curta ({length} caracteres).", GENERATOR_TIP,
        ))
    return alerts


def _reuse_alerts(entries, labels):
    """Alertas de senhas iguais ou muito parecidas entre credenciais."""
    by_password = {}
    for entry in entries:
        by_password.setdefault(entry["password"], []).append(entry)

    alerts = []
    for group in by_password.values():
        if len(group) > 1:
            names = _join(labels[entry["id"]] for entry in group)
            alerts.append(_alert(
                "alto", "reused", group, labels,
                f"{names} usam a mesma senha.",
                "Se um desses serviços vazar, atacantes testam a mesma senha "
                "nos outros (credential stuffing). Use uma senha diferente "
                "para cada serviço.",
            ))

    for passwords in similar_password_groups(by_password):
        group = [entry for password in passwords for entry in by_password[password]]
        names = _join(labels[entry["id"]] for entry in group)
        alerts.append(_alert(
            "médio", "similar", group, labels,
            f"{names} usam senhas muito parecidas.",
            "Atacantes testam variações de senhas vazadas, como trocar um "
            "número ou o nome do serviço. Gere senhas independentes para cada "
            "serviço.",
        ))
    return alerts


def _sort(alerts):
    return sorted(alerts, key=lambda alert: (
        SEVERITIES.index(alert["severity"]), alert["services"][0].casefold()))


def _checks(analyses):
    """Quais analisadores rodaram para todas as senhas analisadas."""
    local = [a for p, a in analyses.items() if len(p) <= predictor.MAX_PASSWORD_LENGTH]
    return {
        "strength": all(a["strength"] is not None for a in local),
        "breach": all(a["pwned_count"] is not None for a in analyses.values()),
        "similarity": all(a["similarity"] is not None for a in local),
    }


# --- Pontos de entrada ---------------------------------------------------------

def security_report(entries, settings):
    """Relatório de todas as credenciais.

    `entries`: lista de dicionários com id, service, username e password
    (decifrados). O retorno não contém nenhuma senha.
    """
    labels = _labels(entries)
    analyses = analyze_passwords([entry["password"] for entry in entries], settings)

    alerts = []
    for entry in entries:
        alerts += _password_alerts(entry, analyses[entry["password"]], labels)
    alerts = _sort(alerts + _reuse_alerts(entries, labels))

    credentials = []
    for entry in sorted(entries, key=lambda e: e["service"].casefold()):
        own = [a for a in alerts if entry["id"] in a["credential_ids"]]
        analysis = analyses[entry["password"]]
        similarity = analysis["similarity"]
        credentials.append({
            "id": entry["id"],
            "service": entry["service"],
            "username": entry["username"],
            "severity": own[0]["severity"] if own else None,
            "strength": analysis["strength"],
            "pwned_count": analysis["pwned_count"],
            "leak_similarity": similarity["risk"] if similarity else None,
            "alerts": len(own),
        })

    at_risk = sum(c["severity"] in ("crítico", "alto", "médio") for c in credentials)
    total = len(credentials)
    return {
        "summary": {
            "credentials": total,
            "at_risk": at_risk,
            "score": round(100 * (total - at_risk) / total) if total else 100,
            "alerts_by_severity": {
                severity: sum(a["severity"] == severity for a in alerts)
                for severity in SEVERITIES
            },
        },
        "alerts": alerts,
        "credentials": credentials,
        "checks": _checks(analyses),
    }


def credential_alerts(credential_id, entries, settings):
    """Alertas de uma credencial recém-salva ("em tempo real").

    Analisa só a senha dessa credencial (uma consulta ao HIBP) e a compara com
    as senhas das outras credenciais do usuário, sem chamadas externas.
    """
    labels = _labels(entries)
    entry = next(e for e in entries if e["id"] == credential_id)
    analyses = analyze_passwords([entry["password"]], settings)

    alerts = _password_alerts(entry, analyses[entry["password"]], labels)
    alerts += [alert for alert in _reuse_alerts(entries, labels)
               if credential_id in alert["credential_ids"]]
    return {"alerts": _sort(alerts), "checks": _checks(analyses)}
