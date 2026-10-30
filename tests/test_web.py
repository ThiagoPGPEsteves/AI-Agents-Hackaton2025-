import pytest
import json
from cybersecurityteam.web import app
from cybersecurityteam.config import settings

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_web_index_serves_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"XenDefender" in response.data

def test_web_api_status_endpoint(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "online"
    assert "model" in data
    assert "total_blocked_ips" in data
    assert "recent_incidents" in data

def test_web_analisar_empty_payload(client):
    response = client.post("/analisar", json={"texto": ""})
    assert response.status_code == 400
    data = response.get_json()
    assert "Nenhum texto informado" in data["mensagem"]

def test_web_analisar_clean_query(client):
    response = client.post(
        "/analisar",
        json={"texto": "SELECT id, name FROM users WHERE active = 1 LIMIT 10"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "clean"
    assert "Nenhuma ameaça" in data["mensagem"]

def test_web_analisar_threat_detection(client, monkeypatch):
    # Teste de detecção com bypass da chamada de LLM via mock para rapidez no teste
    response = client.post(
        "/analisar",
        json={"texto": "SELECT id FROM products WHERE id = 1; DROP TABLE accounts; --"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "threat_detected"
    assert data["detalhes"]["tipo_ataque"] == "sqli"
    assert "DROP TABLE" in data["detalhes"]["padrao_detectado"].upper()
