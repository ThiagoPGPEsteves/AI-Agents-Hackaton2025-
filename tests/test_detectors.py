import pytest
from cybersecurityteam.detection.signatures import scan_signatures
from cybersecurityteam.detection.stateful import StatefulAnomalyDetector
from cybersecurityteam.models import LogEntry, Severity

def test_detect_sqli_drop_table():
    payload = "SELECT * FROM products WHERE id = 1; DROP TABLE users; --"
    detection = scan_signatures(payload)
    assert detection is not None
    assert detection.attack_type == "sqli"
    assert detection.heuristic_severity == Severity.CRITICAL
    assert detection.high_confidence is True

def test_detect_sqli_union_select():
    payload = "SELECT id FROM items WHERE id = -1 UNION SELECT username, password FROM accounts"
    detection = scan_signatures(payload)
    assert detection is not None
    assert detection.attack_type == "sqli"
    assert detection.heuristic_severity == Severity.HIGH

def test_detect_command_injection():
    payload = "file.txt; whoami"
    detection = scan_signatures(payload)
    assert detection is not None
    assert detection.attack_type == "cmd_injection"
    assert detection.heuristic_severity == Severity.CRITICAL

def test_detect_path_traversal():
    payload = "/download?file=../../../../etc/passwd"
    detection = scan_signatures(payload)
    assert detection is not None
    assert detection.attack_type == "lfi"
    assert detection.heuristic_severity == Severity.HIGH

def test_clean_query_no_detection():
    payload = "SELECT id, name FROM users WHERE status = 'active'"
    detection = scan_signatures(payload)
    assert detection is None

def test_stateful_brute_force():
    detector = StatefulAnomalyDetector(brute_force_threshold=3, brute_force_window=60)
    ip = "203.0.113.99"

    entry_fail = LogEntry(
        source_ip=ip, user="admin", action_type="AUTH_LOGIN",
        payload="Login failed for user admin", status_code=401
    )

    # 1ª e 2ª tentativa: não dispara
    assert detector.analyze(entry_fail) is None
    assert detector.analyze(entry_fail) is None

    # 3ª tentativa: dispara detecção de força bruta!
    det = detector.analyze(entry_fail)
    assert det is not None
    assert det.attack_type == "brute_force"
    assert det.heuristic_severity == Severity.HIGH
