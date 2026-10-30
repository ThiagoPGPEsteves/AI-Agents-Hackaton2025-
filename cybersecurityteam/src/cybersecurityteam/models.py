from enum import Enum
from datetime import datetime, timezone
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    user: str = "anonymous"
    action_type: str = "QUERY"  # QUERY, AUTH_LOGIN, HTTP_REQUEST
    payload: str
    status_code: Optional[int] = 200
    session_id: Optional[str] = None
    raw_line: str = ""

class Detection(BaseModel):
    attack_type: str  # sqli, brute_force, exfiltration, lfi, cmd_injection
    matched_pattern: str
    heuristic_severity: Severity
    high_confidence: bool = False
    details: str

class Incident(BaseModel):
    id: str  # Determinístico: sha1(ip + attack_type + window)
    source_ip: str
    attack_type: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_count: int = 1
    samples: List[str] = Field(default_factory=list, max_length=5)
    heuristic_severity: Severity = Severity.MEDIUM
    high_confidence: bool = False

class ThreatAssessment(BaseModel):
    """Saída estruturada do Analyst Agent."""
    incident_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, description="Nível de certeza da análise (0.0 a 1.0)")
    mitre_technique: Optional[str] = Field(default=None, description="Identificador MITRE ATT&CK (ex: T1190, T1078)")
    owasp_category: Optional[str] = Field(default=None, description="Categoria OWASP (ex: A03:2021-Injection)")
    false_positive: bool = Field(default=False, description="Indica se o evento é tráfego legítimo")
    rationale: str = Field(..., max_length=600, description="Justificativa técnica detalhada")

class ResponsePlan(BaseModel):
    """Saída estruturada do Responder Agent."""
    incident_id: str
    actions: List[Literal["block_ip", "notify", "audit_only"]] = Field(
        ..., description="Lista de ações recomendadas"
    )
    summary: str = Field(..., max_length=600, description="Resumo das contramedidas tomadas")

class AuditRecord(BaseModel):
    record_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    incident_id: str
    source_ip: str
    final_severity: Severity
    actions_taken: List[str]
    llm_status: Literal["ok", "fallback", "skipped"]
    threat_summary: str
    previous_hash: str
    current_hash: str
