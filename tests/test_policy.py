import pytest
from cybersecurityteam.models import Incident, ThreatAssessment, ResponsePlan, Severity
from cybersecurityteam.response.policy import PolicyEngine
from cybersecurityteam.response.firewall import SimulatedFirewall

def test_allowlist_protection():
    fw = SimulatedFirewall()
    # IPs protegidos na allowlist nunca podem ser bloqueados
    assert fw.block_ip("127.0.0.1", reason="test") is False
    assert fw.block_ip("10.0.0.1", reason="test") is False

def test_severity_floor_cannot_be_downgraded():
    engine = PolicyEngine()
    # Incidente com alta confiança (DROP TABLE)
    incident = Incident(
        id="test-floor",
        source_ip="203.0.113.77",
        attack_type="sqli",
        heuristic_severity=Severity.CRITICAL,
        high_confidence=True
    )

    # Suponha que o LLM respondesse incorretamente que é LOW ou falso positivo
    assessment = ThreatAssessment(
        incident_id="test-floor",
        severity=Severity.LOW,
        confidence=0.5,
        false_positive=True,
        rationale="Tentativa de bypass pelo LLM"
    )

    plan = ResponsePlan(
        incident_id="test-floor",
        actions=["audit_only"],
        summary="Apenas auditoria"
    )

    result = engine.execute_policy(incident, assessment, plan)
    # O piso de severidade DEVE manter a severidade em CRITICAL!
    assert result["final_severity"] == Severity.CRITICAL.value

def test_audit_hash_chain(tmp_path):
    from cybersecurityteam.response.audit import AuditLogger
    audit_file = str(tmp_path / "test_audit.jsonl")
    logger = AuditLogger(audit_file=audit_file)

    rec1 = logger.log_incident("inc-1", "203.0.113.1", Severity.HIGH, ["blocked_ip"], "Ataque 1")
    rec2 = logger.log_incident("inc-2", "203.0.113.2", Severity.CRITICAL, ["blocked_ip"], "Ataque 2")

    assert rec1.previous_hash == "0" * 64
    assert rec2.previous_hash == rec1.current_hash
