"""Consulta de senhas vazadas na API Pwned Passwords do Have I Been Pwned.

Usa o modelo de k-anonimato da API: a senha nunca sai do servidor.

1. Calcula o SHA-1 da senha (em UTF-8), em hexadecimal maiúsculo.
2. Envia ao HIBP só os 5 primeiros caracteres do hash (o prefixo).
3. O HIBP devolve os finais (sufixos) de todos os hashes vazados que
   começam com esse prefixo, centenas deles, cada um com o número de
   vezes que apareceu em vazamentos.
4. A comparação com o sufixo da senha é feita aqui, localmente.

Com o cabeçalho "Add-Padding", o HIBP completa a resposta com sufixos falsos
(contagem 0), para que nem o tamanho da resposta revele o prefixo consultado.

Documentação: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib

import requests

PREFIX_LENGTH = 5

# O hash tem tamanho fixo, então o comprimento da senha não importa para o
# HIBP. O limite só evita corpos de requisição enormes.
MAX_PASSWORD_LENGTH = 1024


class HIBPUnavailableError(RuntimeError):
    """O HIBP não respondeu ou respondeu com erro."""


def validate_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Informe a senha no campo 'password'.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"A senha deve ter no máximo {MAX_PASSWORD_LENGTH} caracteres."
        )


def sha1_hex(password):
    """SHA-1 da senha em hexadecimal maiúsculo, como o HIBP usa."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(password):
    """(prefixo de 5 caracteres enviado ao HIBP, sufixo que fica aqui)."""
    digest = sha1_hex(password)
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def parse_range(text):
    """Converte a resposta do HIBP ("SUFIXO:CONTAGEM" por linha) em dicionário.

    Linhas com contagem 0 são o preenchimento falso e são descartadas.
    """
    counts = {}
    for line in text.splitlines():
        suffix, separator, count = line.strip().partition(":")
        if not separator:
            continue
        try:
            value = int(count)
        except ValueError:
            continue
        if value > 0:
            counts[suffix.upper()] = value
    return counts


def fetch_range(prefix, api_url, timeout, user_agent):
    """Sufixos vazados que começam com o prefixo informado."""
    try:
        response = requests.get(
            f"{api_url.rstrip('/')}/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": user_agent},
            timeout=timeout,
        )
    except requests.RequestException as error:
        raise HIBPUnavailableError(
            "Não foi possível consultar o Have I Been Pwned."
        ) from error
    if response.status_code != 200:
        raise HIBPUnavailableError(
            f"O Have I Been Pwned respondeu com erro ({response.status_code})."
        )
    return parse_range(response.text)


def pwned_count(password, api_url, timeout, user_agent):
    """Quantas vezes a senha apareceu em vazamentos (0 se nunca apareceu)."""
    validate_password(password)
    prefix, suffix = split_hash(password)
    return fetch_range(prefix, api_url, timeout, user_agent).get(suffix, 0)
