import pytest
from unittest.mock import MagicMock, patch
from cybersecurityteam.models import Incident, Severity, ThreatAssessment, ResponsePlan
from cybersecurityteam.flow import IncidentFlow
from cybersecurityteam.crew import IncidentCrew
from cybersecurityteam.security.mitre_map import get_attack_metadata

def test_incident_flow_low_severity_routes_to_skip_llm():
    # Incidente LOW severity sem alta confiança não deve acionar CrewAI
    incident = Incident(
        id="inc-low-001",
        source_ip="192.168.1.100",
        attack_type="sqli",
        heuristic_severity=Severity.LOW,
        high_confidence=False,
        samples=["SELECT * FROM public_catalog LIMIT 5"]
    )

    flow = IncidentFlow(incident)
    result = flow.kickoff()

    assert flow.state.llm_status == "skipped"
    assert result["incident_id"] == "inc-low-001"
    assert result["final_severity"] == Severity.LOW.value
    assert "notification_sent" in result["actions_taken"]
    assert "blocked_ip" not in result["actions_taken"]

def test_incident_flow_fallback_on_crew_error(monkeypatch):
    incident = Incident(
        id="inc-err-002",
        source_ip="203.0.113.88",
        attack_type="sqli",
        heuristic_severity=Severity.CRITICAL,
        high_confidence=True,
        samples=["'; DROP TABLE users; --"]
    )

    flow = IncidentFlow(incident)

    # Simula falha na API ou timeout da Crew
    def mock_kickoff(*args, **kwargs):
        raise RuntimeError("API Timeout / Out of Quota")

    with patch("cybersecurityteam.crew.IncidentCrew.crew") as mock_crew_cls:
        mock_instance = MagicMock()
        mock_instance.kickoff.side_effect = mock_kickoff
        mock_crew_cls.return_value = mock_instance

        result = flow.kickoff()

        # O fluxo deve acionar o fallback graciosamente
        assert flow.state.llm_status == "fallback"
        assert result["incident_id"] == "inc-err-002"
        # Piso de severidade garante CRITICAL mesmo no erro
        assert result["final_severity"] == Severity.CRITICAL.value
        assert "blocked_ip" in result["actions_taken"]

def test_crew_structure_and_agents_definition():
    incident_crew = IncidentCrew()
    
    # Valida LLM configurado
    assert incident_crew.llm is not None
    
    # Valida instanciação dos agentes
    analyst = incident_crew.analyst_agent()
    responder = incident_crew.responder_agent()
    assert analyst.role is not None
    assert responder.role is not None
    
    # Valida instanciação e contratos Pydantic das tarefas
    task1 = incident_crew.analyst_task()
    task2 = incident_crew.responder_task()
    assert task1.output_pydantic == ThreatAssessment
    assert task2.output_pydantic == ResponsePlan

def test_mitre_and_owasp_mapping():
    mitre, owasp, desc = get_attack_metadata("sqli")
    assert mitre == "T1190"
    assert owasp == "A03:2021-Injection"

    mitre, owasp, desc = get_attack_metadata("brute_force")
    assert mitre == "T1110"
    assert "Authentication" in owasp

    mitre, owasp, desc = get_attack_metadata("cmd_injection")
    assert mitre == "T1059"
