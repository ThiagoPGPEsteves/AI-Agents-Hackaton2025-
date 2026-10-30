import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from ..config import settings
from ..models import Incident, ThreatAssessment, ResponsePlan, Severity
from .firewall import SimulatedFirewall
from .notifier import SecurityNotifier
from .audit import AuditLogger

class PolicyEngine:
    """
    Motor central de políticas de resposta a incidentes.
    Garante execução determinística, proteção de allowlist, piso de severidade e fail-safe.
    """
    def __init__(self):
        self.firewall = SimulatedFirewall()
        self.audit = AuditLogger()
        self.notifier = SecurityNotifier()
        base = settings.base_dir / settings.state_dir
        base.mkdir(parents=True, exist_ok=True)
        self.pending_file = base / "pending_actions.jsonl"

    def execute_policy(
        self,
        incident: Incident,
        assessment: Optional[ThreatAssessment] = None,
        response_plan: Optional[ResponsePlan] = None,
        llm_status: str = "ok"
    ) -> dict:
        """
        Executa as ações aprovadas pelas políticas de segurança.
        Retorna dicionário com o resumo da contenção aplicada.
        """
        target_ip = incident.source_ip  # IP sempre extraído da fonte rastreada, nunca do LLM!
        actions_taken: List[str] = []

        # 1. Determinação do piso de severidade
        heuristic_level = incident.heuristic_severity
        if assessment and not assessment.false_positive:
            llm_level = assessment.severity
            severity_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            # Se for alta confiança (ex: DROP TABLE), o LLM não pode rebaixar a severidade
            if incident.high_confidence:
                final_level = max(
                    heuristic_level,
                    llm_level,
                    key=lambda s: severity_order[s]
                )
            else:
                final_level = llm_level
        elif assessment and assessment.false_positive and not incident.high_confidence:
            final_level = Severity.LOW
        else:
            final_level = heuristic_level

        # 2. Resumo da ameaça
        if assessment:
            summary = assessment.rationale
        else:
            summary = f"Mitigação automática (Fail-Safe): {incident.attack_type.upper()} detectado em {incident.event_count} eventos."

        # 3. Execução de Bloqueio (Firewall)
        should_block = False
        if response_plan and "block_ip" in response_plan.actions:
            should_block = True
        elif final_level in (Severity.HIGH, Severity.CRITICAL):
            should_block = True

        if should_block:
            # Se for crítico em ambiente não dry-run, registra como ação pendente
            if final_level == Severity.CRITICAL and not settings.dry_run:
                self._record_pending_action(incident.id, target_ip, "block_ip", summary)
                actions_taken.append("queued_for_approval")
            else:
                success = self.firewall.block_ip(target_ip, reason=f"{incident.attack_type}: {summary}")
                if success:
                    actions_taken.append("blocked_ip")
                else:
                    actions_taken.append("allowlisted_bypass")

        # 4. Notificação
        self.notifier.notify(incident.id, target_ip, final_level, incident.attack_type, summary)
        actions_taken.append("notification_sent")

        # 5. Registro em Trilha de Auditoria
        audit_record = self.audit.log_incident(
            incident_id=incident.id,
            source_ip=target_ip,
            final_severity=final_level,
            actions_taken=actions_taken,
            threat_summary=summary,
            llm_status=llm_status
        )

        return {
            "incident_id": incident.id,
            "target_ip": target_ip,
            "final_severity": final_level.value,
            "actions_taken": actions_taken,
            "audit_record_id": audit_record.record_id,
            "llm_status": llm_status
        }

    def _record_pending_action(self, incident_id: str, ip: str, action: str, reason: str):
        record = {
            "incident_id": incident_id,
            "ip": ip,
            "action": action,
            "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        try:
            with open(self.pending_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            print(f"⚠️ [Ação Crítica Pendente] Bloqueio do IP {ip} registrado para aprovação.")
        except Exception as e:
            print(f"[Policy Error] Falha ao registrar ação pendente: {e}")
