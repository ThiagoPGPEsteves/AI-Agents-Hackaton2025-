import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from ..models import LogEntry, Detection, Incident, Severity
from ..security.redact import redact_sensitive_data

class IncidentAggregator:
    """
    Agrupa detecções em incidentes estruturados.
    Aplica deduplicação por hash determinístico, cooldown por IP e controle de taxa.
    """
    def __init__(self, cooldown_seconds: int = 30, window_bucket_seconds: int = 300):
        self.cooldown = cooldown_seconds
        self.window_bucket = window_bucket_seconds
        # { incident_id: Incident }
        self._active_incidents: Dict[str, Incident] = {}
        # { incident_id: last_dispatched_timestamp }
        self._last_dispatched: Dict[str, float] = {}

    def _generate_incident_id(self, ip: str, attack_type: str) -> str:
        bucket = int(time.time() // self.window_bucket)
        raw = f"{ip}:{attack_type}:{bucket}".encode("utf-8")
        return hashlib.sha1(raw).hexdigest()[:16]

    def process(self, entry: LogEntry, detection: Detection) -> Tuple[Incident, bool]:
        """
        Registra uma detecção.
        Retorna (incident, should_dispatch), onde should_dispatch é True se o incidente
        deve ser encaminhado para análise imediata (respeitando cooldown e novas escaladas).
        """
        now = datetime.now(timezone.utc)
        now_ts = time.time()
        incident_id = self._generate_incident_id(entry.source_ip, detection.attack_type)

        redacted_sample = redact_sensitive_data(entry.payload)

        if incident_id not in self._active_incidents:
            incident = Incident(
                id=incident_id,
                source_ip=entry.source_ip,
                attack_type=detection.attack_type,
                first_seen=now,
                last_seen=now,
                event_count=1,
                samples=[redacted_sample],
                heuristic_severity=detection.heuristic_severity,
                high_confidence=detection.high_confidence
            )
            self._active_incidents[incident_id] = incident
            self._last_dispatched[incident_id] = now_ts
            return incident, True

        incident = self._active_incidents[incident_id]
        incident.event_count += 1
        incident.last_seen = now

        # Adiciona amostra se ainda houver espaço e não for duplicada
        if len(incident.samples) < 5 and redacted_sample not in incident.samples:
            incident.samples.append(redacted_sample)

        # Atualiza severidade se a nova detecção for mais grave
        severity_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        if severity_order.get(detection.heuristic_severity, 1) > severity_order.get(incident.heuristic_severity, 1):
            incident.heuristic_severity = detection.heuristic_severity
            incident.high_confidence = incident.high_confidence or detection.high_confidence
            self._last_dispatched[incident_id] = now_ts
            return incident, True

        # Verifica cooldown para reenvio
        last_disp = self._last_dispatched.get(incident_id, 0)
        if (now_ts - last_disp) >= self.cooldown:
            self._last_dispatched[incident_id] = now_ts
            return incident, True

        return incident, False
