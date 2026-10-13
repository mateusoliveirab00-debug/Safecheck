import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from app import app
from checker import analisar_senha, analisar_url, gerar_senha


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_senha_fraca():
    r = analisar_senha("123456")
    assert r["pontos"] == 0


def test_senha_forte():
    r = analisar_senha("Tr0ub4dor&3-cavalo-Bateria!")
    assert r["pontos"] >= 3


def test_url_golpe_alto():
    r = analisar_url("http://192.168.0.1/login-verificar-conta")
    assert r["risco"] == "Alto"


def test_url_segura_baixo():
    r = analisar_url("https://www.python.org/")
    assert r["risco"] == "Baixo"


def test_gerador_respeita_tamanho_e_grupos():
    s = gerar_senha(20)
    assert len(s) == 20
    assert any(c.isdigit() for c in s)
    assert any(c.isupper() for c in s)
    assert any(c.islower() for c in s)


def test_rotas(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").get_json() == {"status": "ok"}
    r = client.post("/api/senha", json={"senha": "abc"})
    assert r.status_code == 200
    assert client.post("/api/senha", json={}).status_code == 400
    assert client.post("/api/url", json={"url": "https://github.com"}).status_code == 200
    assert len(client.get("/api/gerar?tamanho=24").get_json()["senha"]) == 24
