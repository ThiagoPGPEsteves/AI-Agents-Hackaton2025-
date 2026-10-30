from typing import Optional
from pydantic import BaseModel
from crewai.flow.flow import Flow, start, router, listen
from .models import Incident, Severity, ThreatAssessment, ResponsePlan
from .crew import IncidentCrew
from .response.policy import PolicyEngine

class IncidentFlowState(BaseModel):
    incident: Optional[Incident] = None
    assessment: Optional[ThreatAssessment] = None
    response_plan: Optional[ResponsePlan] = None
    execution_result: Optional[dict] = None
    llm_status: str = "ok"

class IncidentFlow(Flow[IncidentFlowState]):
    """
    Fluxo de processamento de incidentes de segurança.
    Roteia eventos leves diretamente para auditoria e aciona a IncidentCrew para ameaças relevantes.
    """
    def __init__(self, incident: Incident):
        super().__init__()
        self.state.incident = incident
        self.policy_engine = PolicyEngine()

    @start()
    def receive_incident(self):
        return self.state.incident

    @router(receive_incident)
    def route_by_severity(self):
        inc = self.state.incident
        if inc.heuristic_severity == Severity.LOW and not inc.high_confidence:
            return "low_severity_route"
        return "crew_investigation_route"

    @listen("low_severity_route")
    def handle_low_severity(self):
        inc = self.state.incident
        self.state.llm_status = "skipped"
        self.state.execution_result = self.policy_engine.execute_policy(
            incident=inc,
            assessment=None,
            response_plan=None,
            llm_status="skipped"
        )
        return self.state.execution_result

    @listen("crew_investigation_route")
    def run_crew_investigation(self):
        inc = self.state.incident
        samples_formatted = "\n".join(f"  - [Amostra]: {s}" for s in inc.samples)

        inputs = {
            "incident_id": inc.id,
            "source_ip": inc.source_ip,
            "attack_type": inc.attack_type,
            "heuristic_severity": inc.heuristic_severity.value,
            "samples_text": samples_formatted or "Nenhuma amostra textual registrada."
        }

        max_retries = 2
        for attempt in range(max_retries):
            try:
                crew_instance = IncidentCrew().crew()
                crew_result = crew_instance.kickoff(inputs=inputs)

                # Extrai saídas estruturadas
                if hasattr(crew_result, "pydantic") and isinstance(crew_result.pydantic, ResponsePlan):
                    self.state.response_plan = crew_result.pydantic
                elif hasattr(crew_result, "pydantic") and isinstance(crew_result.pydantic, ThreatAssessment):
                    self.state.assessment = crew_result.pydantic

                # Tenta resgatar o assessment da primeira task
                for t in crew_instance.tasks:
                    if hasattr(t, "output") and t.output and hasattr(t.output, "pydantic"):
                        if isinstance(t.output.pydantic, ThreatAssessment):
                            self.state.assessment = t.output.pydantic
                        elif isinstance(t.output.pydantic, ResponsePlan):
                            self.state.response_plan = t.output.pydantic

                self.state.llm_status = "ok"
                break

            except Exception as e:
                err_str = str(e)
                if attempt < max_retries - 1 and any(c in err_str for c in ("503", "429", "UNAVAILABLE", "ResourceExhausted")):
                    import time
                    print(f"🔄 [Flow Retry] Provedor Gemini ocupado ({err_str[:60]}...). Tentativa {attempt + 2}/{max_retries} em 2s...")
                    time.sleep(2)
                    continue

                print(f"⚠️ [Flow Warning] Falha na execução da Crew LLM ({e}). Acionando Fail-Safe determinístico.")
                self.state.llm_status = "fallback"
                break

        # Aplica a política com as evidências disponíveis (mesmo em modo fallback)
        self.state.execution_result = self.policy_engine.execute_policy(
            incident=inc,
            assessment=self.state.assessment,
            response_plan=self.state.response_plan,
            llm_status=self.state.llm_status
        )
        return self.state.execution_result
