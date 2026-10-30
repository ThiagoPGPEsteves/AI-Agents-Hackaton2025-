import time
import json
import pytest
from cybersecurityteam.models import Incident, ThreatAssessment, ResponsePlan, Severity
from cybersecurityteam.response.policy import PolicyEngine
from cybersecurityteam.response.firewall import SimulatedFirewall
from cybersecurityteam.response.audit import AuditLogger
from cybersecurityteam.response.notifier import SecurityNotifier
from cybersecurityteam.config import settings

def test_firewall_ttl_expiration(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "dry_run", False)
    block_file = str(tmp_path / "test_blocklist.json")
    fw = SimulatedFirewall(blocklist_file=block_file)
    
    ip = "203.0.113.50"
    # Bloqueio com TTL de apenas 1 segundo
    blocked = fw.block_ip(ip, reason="Teste TTL", ttl_seconds=1)
    assert blocked is True
    assert fw.is_blocked(ip) is True
    
    # Aguarda o TTL expirar
    time.sleep(1.2)
    
    # Deve expirar e ser removido
    assert fw.is_blocked(ip) is False
    assert len(fw.get_active_blocks()) == 0

def test_policy_engine_fail_safe_mode():
    engine = PolicyEngine()
    incident = Incident(
        id="inc-failsafe",
        source_ip="203.0.113.99",
        attack_type="cmd_injection",
        heuristic_severity=Severity.HIGH,
        high_confidence=True
    )
    
    # Simula falha do LLM: assessment=None, response_plan=None, llm_status="fallback"
    result = engine.execute_policy(
        incident=incident,
        assessment=None,
        response_plan=None,
        llm_status="fallback"
    )
    
    assert result["incident_id"] == "inc-failsafe"
    assert result["final_severity"] == Severity.HIGH.value
    assert "blocked_ip" in result["actions_taken"]
    assert result["llm_status"] == "fallback"

def test_audit_tampering_verification(tmp_path):
    audit_file = str(tmp_path / "audit_tamper.jsonl")
    logger = AuditLogger(audit_file=audit_file)
    
    rec1 = logger.log_incident("inc-1", "1.1.1.1", Severity.LOW, ["audit_only"], "Test 1")
    rec2 = logger.log_incident("inc-2", "2.2.2.2", Severity.HIGH, ["blocked_ip"], "Test 2")
    
    # Verifica que rec2 aponta para rec1
    assert rec2.previous_hash == rec1.current_hash
    
    # Lê os registros gravados
    records = logger.get_recent_records(limit=10)
    assert len(records) == 2
    assert records[0]["incident_id"] == "inc-2" # mais recente primeiro
    assert records[1]["incident_id"] == "inc-1"

def test_security_notifier_execution():
    # Testa notificador com todas as severidades sem levantar exceções
    for sev in [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
        SecurityNotifier.notify(
            incident_id="test-notify",
            ip="203.0.113.1",
            severity=sev,
            attack_type="sqli",
            summary=f"Alerta de teste para {sev.value}"
        )
