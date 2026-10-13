"""Lógica de segurança do SafeCheck: senhas, URLs e gerador de senhas.

Nada aqui é gravado em disco ou em log: as senhas só existem na memória
durante a requisição.
"""
import math
import re
import secrets
import string
from urllib.parse import urlparse

SENHAS_COMUNS = {
    "123456", "123456789", "12345678", "senha", "senha123", "password",
    "qwerty", "abc123", "111111", "123123", "admin", "admin123",
    "iloveyou", "brasil", "flamengo", "corinthians", "mudar123",
    "qwerty123", "letmein", "welcome", "1q2w3e4r", "q1w2e3r4",
}

SEQUENCIAS = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]

ENCURTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at",
}

TLDS_SUSPEITOS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
    "support", "country", "work", "loan",
}

PALAVRAS_SUSPEITAS = [
    "login", "signin", "verify", "verificar", "secure", "seguro", "conta",
    "account", "update", "atualizar", "banco", "bank", "pix", "senha",
    "password", "premio", "prize", "gratis", "free", "suporte", "support",
]


# ---------------------------------------------------------------- senhas
def _tamanho_alfabeto(senha: str) -> int:
    tamanho = 0
    if re.search(r"[a-z]", senha):
        tamanho += 26
    if re.search(r"[A-Z]", senha):
        tamanho += 26
    if re.search(r"\d", senha):
        tamanho += 10
    if re.search(r"[^A-Za-z0-9]", senha):
        tamanho += 32
    return tamanho


def _tem_sequencia(senha: str, minimo: int = 4) -> bool:
    s = senha.lower()
    for seq in SEQUENCIAS:
        for base in (seq, seq[::-1]):
            for i in range(len(base) - minimo + 1):
                if base[i:i + minimo] in s:
                    return True
    return False


def _formatar_tempo(segundos: float) -> str:
    if segundos < 1:
        return "instantâneo"
    unidades = [
        ("segundos", 60), ("minutos", 60), ("horas", 24),
        ("dias", 365), ("anos", 1000), ("milênios", 1000),
    ]
    valor = segundos
    for nome, divisor in unidades:
        if valor < divisor:
            return f"{valor:.0f} {nome}"
        valor /= divisor
    return "bilhões de anos"


def analisar_senha(senha: str) -> dict:
    if not senha:
        return {"erro": "Informe uma senha."}

    dicas = []
    entropia = len(senha) * math.log2(max(_tamanho_alfabeto(senha), 1))

    if senha.lower() in SENHAS_COMUNS:
        entropia = min(entropia, 10)
        dicas.append("Essa senha está entre as mais usadas e vazadas.")
    if len(senha) < 12:
        dicas.append("Use pelo menos 12 caracteres.")
    if not re.search(r"[A-Z]", senha) or not re.search(r"[a-z]", senha):
        dicas.append("Misture letras maiúsculas e minúsculas.")
    if not re.search(r"\d", senha):
        dicas.append("Inclua números.")
    if not re.search(r"[^A-Za-z0-9]", senha):
        dicas.append("Inclua símbolos (!@#$%...).")
    if re.search(r"(.)\1{2,}", senha):
        entropia *= 0.8
        dicas.append("Evite repetir o mesmo caractere várias vezes seguidas.")
    if _tem_sequencia(senha):
        entropia *= 0.8
        dicas.append("Evite sequências como 1234, abcd ou qwerty.")

    # 10 bilhões de tentativas por segundo (ataque offline com GPU)
    segundos = (2 ** entropia) / 1e10

    if entropia < 28:
        nivel, pontos = "Muito fraca", 0
    elif entropia < 40:
        nivel, pontos = "Fraca", 1
    elif entropia < 60:
        nivel, pontos = "Razoável", 2
    elif entropia < 80:
        nivel, pontos = "Forte", 3
    else:
        nivel, pontos = "Muito forte", 4

    if not dicas:
        dicas.append("Ótima senha! Use um gerenciador de senhas para guardá-la.")

    return {
        "nivel": nivel,
        "pontos": pontos,
        "entropia_bits": round(entropia, 1),
        "tempo_para_quebrar": _formatar_tempo(segundos),
        "dicas": dicas,
    }


# ------------------------------------------------------------------ URLs
def analisar_url(url: str) -> dict:
    url = (url or "").strip()
    if not url:
        return {"erro": "Informe uma URL."}
    if "://" not in url:
        url = "http://" + url

    try:
        partes = urlparse(url)
        host = (partes.hostname or "").lower()
    except ValueError:
        return {"erro": "URL inválida."}
    if not host or "." not in host:
        return {"erro": "URL inválida."}

    alertas = []
    risco = 0

    if partes.scheme != "https":
        risco += 2
        alertas.append("Não usa HTTPS: os dados trafegam sem criptografia.")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        risco += 3
        alertas.append("Usa um endereço IP em vez de um domínio.")
    if "@" in partes.netloc:
        risco += 3
        alertas.append("Contém '@' antes do domínio (técnica para disfarçar o destino).")
    if host.startswith("xn--") or ".xn--" in host:
        risco += 2
        alertas.append("Domínio com punycode (pode imitar letras de outro alfabeto).")
    if host in ENCURTADORES:
        risco += 2
        alertas.append("Link encurtado: não dá para ver o destino real.")

    tld = host.rsplit(".", 1)[-1]
    if tld in TLDS_SUSPEITOS:
        risco += 1
        alertas.append(f"Extensão .{tld} é muito usada em golpes.")
    if host.count(".") >= 4:
        risco += 1
        alertas.append("Excesso de subdomínios.")
    if host.count("-") >= 3:
        risco += 1
        alertas.append("Muitos hífens no domínio.")
    if len(url) > 100:
        risco += 1
        alertas.append("URL muito longa.")

    achadas = [p for p in PALAVRAS_SUSPEITAS if p in url.lower()]
    if len(achadas) >= 2:
        risco += 2
        alertas.append("Palavras típicas de phishing: " + ", ".join(achadas[:4]) + ".")

    if risco >= 5:
        nivel = "Alto"
    elif risco >= 2:
        nivel = "Médio"
    else:
        nivel = "Baixo"
    if not alertas:
        alertas.append("Nenhum sinal óbvio de risco. Mesmo assim, desconfie de links inesperados.")

    return {
        "dominio": host,
        "risco": nivel,
        "pontuacao": risco,
        "alertas": alertas,
    }


# -------------------------------------------------------------- gerador
def gerar_senha(tamanho: int = 16, simbolos: bool = True) -> str:
    tamanho = max(8, min(int(tamanho), 64))
    grupos = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if simbolos:
        grupos.append("!@#$%&*?-_+=")
    # garante ao menos um caractere de cada grupo
    senha = [secrets.choice(g) for g in grupos]
    todos = "".join(grupos)
    senha += [secrets.choice(todos) for _ in range(tamanho - len(senha))]
    secrets.SystemRandom().shuffle(senha)
    return "".join(senha)
