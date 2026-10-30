import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from ..config import settings
from ..models import AuditRecord, Severity

GENESIS_HASH = "0" * 64

class AuditLogger:
    """
    Trilha de auditoria append-only em JSONL com encadeamento criptográfico SHA-256.
    Garante integridade e rastreabilidade para conformidade e análise forense.
    """
    def __init__(self, audit_file: Optional[str] = None):
        base = settings.base_dir / settings.state_dir
        base.mkdir(parents=True, exist_ok=True)
        self.file_path = Path(audit_file) if audit_file else base / "audit.jsonl"
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if not self.file_path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            last_hash = record.get("current_hash", last_hash)
                        except Exception:
                            pass
        except Exception:
            return GENESIS_HASH
        return last_hash

    def log_incident(
        self,
        incident_id: str,
        source_ip: str,
        final_severity: Severity,
        actions_taken: List[str],
        threat_summary: str,
        llm_status: str = "ok"
    ) -> AuditRecord:
        """Registra um incidente e encadeia com o hash do evento anterior."""
        now = datetime.now(timezone.utc)
        record_id = hashlib.sha1(f"{incident_id}:{now.isoformat()}".encode("utf-8")).hexdigest()[:12]

        prev_hash = self._last_hash
        payload_to_hash = f"{prev_hash}:{record_id}:{incident_id}:{source_ip}:{final_severity.value}:{now.isoformat()}"
        current_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

        record = AuditRecord(
            record_id=record_id,
            timestamp=now,
            incident_id=incident_id,
            source_ip=source_ip,
            final_severity=final_severity,
            actions_taken=actions_taken,
            llm_status=llm_status,
            threat_summary=threat_summary,
            previous_hash=prev_hash,
            current_hash=current_hash
        )

        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(record.model_dump_json() + "\n")
            self._last_hash = current_hash
        except Exception as e:
            print(f"[Audit Error] Falha ao gravar auditoria: {e}")

        return record

    def get_recent_records(self, limit: int = 50) -> List[dict]:
        """Retorna os registros mais recentes para exibição no dashboard."""
        if not self.file_path.exists():
            return []
        records = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            return []
        return records[-limit:][::-1]  # Mais recentes primeiro
