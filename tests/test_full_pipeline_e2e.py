import time
import pytest
from cybersecurityteam.simulator import LogSimulator
from cybersecurityteam.ingestion.tailer import LogTailer
from cybersecurityteam.ingestion.parsers import parse_log_line
from cybersecurityteam.detection.signatures import scan_signatures
from cybersecurityteam.detection.stateful import StatefulAnomalyDetector
from cybersecurityteam.detection.aggregator import IncidentAggregator
from cybersecurityteam.flow import IncidentFlow
from cybersecurityteam.response.firewall import SimulatedFirewall
from cybersecurityteam.response.audit import AuditLogger
from cybersecurityteam.models import Severity

def test_full_pipeline_integration(tmp_path, monkeypatch):
    # Diretórios e arquivos isolados para o teste
    test_log = tmp_path / "server_test.log"
    test_offset = tmp_path / "offset_test.json"
    test_blocklist = tmp_path / "blocklist_test.json"
    test_audit = tmp_path / "audit_test.jsonl"

    # Injeta instâncias isoladas
    firewall = SimulatedFirewall(blocklist_file=str(test_blocklist))
    audit = AuditLogger(audit_file=str(test_audit))

    tailer = LogTailer(file_path=str(test_log), offset_file=str(test_offset))
    stateful = StatefulAnomalyDetector(brute_force_threshold=3, brute_force_window=60)
    aggregator = IncidentAggregator(cooldown_seconds=5)

    # 1. Escreve logs diretamente (3 logins com falha do mesmo IP + 1 SQLi crítico)
    attack_ip_bf = "203.0.113.111"
    attack_ip_sqli = "203.0.113.222"

    entries_raw = [
        # Linha legítima
        '{"timestamp": "2026-10-30T10:00:00Z", "source_ip": "10.0.0.50", "user": "alice", "action_type": "QUERY", "payload": "SELECT 1", "status_code": 200}',
        # 3 falhas de login (Brute Force)
        f'{{"timestamp": "2026-10-30T10:00:01Z", "source_ip": "{attack_ip_bf}", "user": "admin", "action_type": "AUTH_LOGIN", "payload": "Login failed", "status_code": 401}}',
        f'{{"timestamp": "2026-10-30T10:00:02Z", "source_ip": "{attack_ip_bf}", "user": "admin", "action_type": "AUTH_LOGIN", "payload": "Login failed", "status_code": 401}}',
        f'{{"timestamp": "2026-10-30T10:00:03Z", "source_ip": "{attack_ip_bf}", "user": "admin", "action_type": "AUTH_LOGIN", "payload": "Login failed", "status_code": 401}}',
        # SQLi crítico
        f'{{"timestamp": "2026-10-30T10:00:04Z", "source_ip": "{attack_ip_sqli}", "user": "anonymous", "action_type": "QUERY", "payload": "SELECT * FROM orders; DROP TABLE orders; --", "status_code": 500}}'
    ]

    with open(test_log, "w", encoding="utf-8") as f:
        for line in entries_raw:
            f.write(line + "\n")

    # 2. Executa processamento da fila de logs
    processed_incidents = []
    for raw_line in tailer.read_new_lines():
        entry = parse_log_line(raw_line)
        if not entry:
            continue

        detection = scan_signatures(entry.payload)
        if not detection:
            detection = stateful.analyze(entry)

        if detection:
            incident, should_dispatch = aggregator.process(entry, detection)
            if should_dispatch:
                # Usa modo fail-safe/determinístico rápido para validação de pipeline E2E
                flow = IncidentFlow(incident)
                flow.policy_engine.firewall = firewall
                flow.policy_engine.audit = audit
                res = flow.policy_engine.execute_policy(
                    incident=incident,
                    assessment=None,
                    response_plan=None,
                    llm_status="fallback"
                )
                processed_incidents.append(res)

    # 3. Asserções do ciclo de vida
    assert len(processed_incidents) == 2  # Brute Force + SQLi

    # Brute Force gerou incidente e foi tratado
    bf_result = next(r for r in processed_incidents if r["target_ip"] == attack_ip_bf)
    assert bf_result["final_severity"] == Severity.HIGH.value
    assert "notification_sent" in bf_result["actions_taken"]

    # SQLi Crítico gerou incidente e foi tratado
    sqli_result = next(r for r in processed_incidents if r["target_ip"] == attack_ip_sqli)
    assert sqli_result["final_severity"] == Severity.CRITICAL.value
    assert "notification_sent" in sqli_result["actions_taken"]

    # Trilha de auditoria gerada e encadeada
    records = audit.get_recent_records(limit=10)
    assert len(records) == 2
    # Registro mais recente aponta para o anterior via SHA-256
    assert records[0]["previous_hash"] == records[1]["current_hash"]
