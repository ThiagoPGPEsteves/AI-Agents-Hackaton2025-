import pytest
from cybersecurityteam.ingestion.parsers import parse_log_line

def test_parse_valid_jsonl():
    raw = '{"source_ip": "203.0.113.10", "user": "alice", "action_type": "QUERY", "payload": "SELECT * FROM users", "status_code": 200}'
    entry = parse_log_line(raw)
    assert entry is not None
    assert entry.source_ip == "203.0.113.10"
    assert entry.user == "alice"
    assert entry.payload == "SELECT * FROM users"
    assert entry.status_code == 200

def test_parse_apache_style_line():
    raw = '192.168.1.50 - bob [30/Oct/2026:10:00:00 +0000] "GET /api/v1/orders HTTP/1.1" 200 450'
    entry = parse_log_line(raw)
    assert entry is not None
    assert entry.source_ip == "192.168.1.50"
    assert entry.user == "bob"
    assert entry.payload == "/api/v1/orders"
    assert entry.status_code == 200

def test_parse_empty_line():
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None
