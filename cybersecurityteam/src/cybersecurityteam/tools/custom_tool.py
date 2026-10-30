from typing import Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from ..response.firewall import SimulatedFirewall
from ..response.audit import AuditLogger

class IpHistoryInput(BaseModel):
    """Schema de entrada para consulta de histórico de IP."""
    ip_address: str = Field(..., description="Endereço IP para consulta de histórico.")

class IpHistoryTool(BaseTool):
    name: str = "Ip_History_Checker"
    description: str = "Consulta se um endereço IP possui histórico recente de bloqueios ou incidentes de segurança."
    args_schema: Type[BaseModel] = IpHistoryInput

    def _run(self, ip_address: str) -> str:
        firewall = SimulatedFirewall()
        audit = AuditLogger()

        is_blocked = firewall.is_blocked(ip_address)
        recent_records = audit.get_recent_records(limit=20)
        matching = [r for r in recent_records if r.get("source_ip") == ip_address]

        res = f"Histórico para IP {ip_address}:\n"
        res += f"- Bloqueado atualmente no Firewall: {'Sim' if is_blocked else 'Não'}\n"
        res += f"- Total de incidentes recentes registrados: {len(matching)}\n"
        if matching:
            res += "- Última severidade: " + matching[0].get("final_severity", "N/A") + "\n"
            res += "- Detalhes: " + matching[0].get("threat_summary", "")[:100]

        return res
