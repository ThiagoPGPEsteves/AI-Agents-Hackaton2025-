import time
from pathlib import Path
from cybersecurityteam.ingestion.tailer import LogTailer
from cybersecurityteam.security.redact import redact_sensitive_data
from cybersecurityteam.detection.aggregator import IncidentAggregator
from cybersecurityteam.simulator import LogSimulator
from cybersecurityteam.models import LogEntry, Detection, Severity

def test_tailer_incremental_reading_and_buffering(tmp_path):
    log_file = tmp_path / "test.log"
    offset_file = tmp_path / "offset.json"
    
    # Escreve duas linhas completas
    log_file.write_text("linha 1\nlinha 2\n", encoding="utf-8")
    
    tailer = LogTailer(str(log_file), str(offset_file))
    lines = list(tailer.read_new_lines())
    assert lines == ["linha 1", "linha 2"]
    
    # Nova leitura sem alterações não retorna nada
    assert list(tailer.read_new_lines()) == []
    
    # Escreve linha parcial
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("linha incompleta")
    
    # Não deve emitir linha incompleta ainda
    assert list(tailer.read_new_lines()) == []
    
    # Completa a linha
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(" completada!\n")
        
    lines = list(tailer.read_new_lines())
    assert lines == ["linha incompleta completada!"]

def test_tailer_log_rotation(tmp_path):
    log_file = tmp_path / "rotate.log"
    offset_file = tmp_path / "rotate_offset.json"
    
    log_file.write_text("antigo log de 50 bytes com muito conteudo\n", encoding="utf-8")
    tailer = LogTailer(str(log_file), str(offset_file))
    assert len(list(tailer.read_new_lines())) == 1
    
    # Simula rotação/truncamento com arquivo menor
    log_file.write_text("novo!\n", encoding="utf-8")
    lines = list(tailer.read_new_lines())
    assert lines == ["novo!"]

def test_redact_sensitive_data():
    raw_text = "senha: superSecret123 token=abc123456789xyz cpf: 123.456.789-00 card: 4111 2222 3333 4444 email: user@test.com"
    redacted = redact_sensitive_data(raw_text)
    
    assert "superSecret123" not in redacted
    assert "abc123456789xyz" not in redacted
    assert "123.456.789-00" not in redacted
    assert "4111 2222 3333 4444" not in redacted
    assert "user@test.com" not in redacted
    
    assert "[REDACTED]" in redacted
    assert "[CPF_REDACTED]" in redacted
    assert "[CARD_REDACTED]" in redacted
    assert "[EMAIL_REDACTED]" in redacted

def test_redact_truncation():
    long_text = "A" * 500
    redacted = redact_sensitive_data(long_text, max_length=50)
    assert len(redacted) <= 80
    assert "[TRUNCATED...]" in redacted

def test_incident_aggregator_deduplication_and_escalation():
    aggregator = IncidentAggregator(cooldown_seconds=10)
    entry = LogEntry(
        source_ip="203.0.113.88",
        user="attacker",
        action_type="QUERY",
        payload="SELECT * FROM users WHERE username = 'admin' OR 1=1 --",
        status_code=200
    )
    
    # 1ª detecção: Medium -> Dispara True
    det_medium = Detection(
        attack_type="sqli",
        matched_pattern="OR 1=1",
        heuristic_severity=Severity.MEDIUM,
        high_confidence=False,
        details="Medium SQLi"
    )
    incident, should_dispatch = aggregator.process(entry, det_medium)
    assert should_dispatch is True
    assert incident.event_count == 1
    assert incident.heuristic_severity == Severity.MEDIUM
    
    # 2ª detecção idêntica dentro do cooldown -> should_dispatch é False (deduplicado)
    incident, should_dispatch = aggregator.process(entry, det_medium)
    assert should_dispatch is False
    assert incident.event_count == 2
    
    # 3ª detecção com escalada para CRITICAL -> Deve disparar imediatamente ignorando cooldown!
    det_critical = Detection(
        attack_type="sqli",
        matched_pattern="; DROP TABLE users;",
        heuristic_severity=Severity.CRITICAL,
        high_confidence=True,
        details="Critical SQLi"
    )
    incident, should_dispatch = aggregator.process(entry, det_critical)
    assert should_dispatch is True
    assert incident.heuristic_severity == Severity.CRITICAL

def test_log_simulator_generation(tmp_path):
    sim = LogSimulator(log_path=str(tmp_path / "sim.log"))
    
    # Log legítimo
    legit = sim.generate_single_log(force_attack=False)
    assert "source_ip" in legit
    assert "payload" in legit
    assert legit["status_code"] == 200
    
    # Log de ataque forçado
    attack = sim.generate_single_log(force_attack=True, attack_type="sqli")
    assert attack["status_code"] in (401, 403, 500)
    assert "source_ip" in attack
