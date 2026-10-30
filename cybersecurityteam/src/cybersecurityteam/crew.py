import os
from pathlib import Path
from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from .config import settings
from .models import ThreatAssessment, ResponsePlan

CONFIG_DIR = Path(__file__).resolve().parent / "config"

@CrewBase
class IncidentCrew:
    """Crew especializada em triagem forense e resposta a incidentes de segurança."""
    agents_config = str(CONFIG_DIR / "agents.yaml")
    tasks_config = str(CONFIG_DIR / "tasks.yaml")

    def __init__(self):
        # Garante que a chave da API esteja disponível no ambiente para o SDK do Gemini
        if settings.gemini_api_key:
            os.environ["GEMINI_API_KEY"] = settings.gemini_api_key
        self.llm = LLM(
            model=settings.model,
            api_key=settings.gemini_api_key,
            temperature=0.2
        )

    @agent
    def analyst_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["analyst_agent"],
            llm=self.llm,
            max_iter=3,
            max_rpm=30,
            verbose=False
        )

    @agent
    def responder_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["responder_agent"],
            llm=self.llm,
            max_iter=3,
            max_rpm=30,
            verbose=False
        )

    @task
    def analyst_task(self) -> Task:
        return Task(
            config=self.tasks_config["analyst_task"],
            output_pydantic=ThreatAssessment
        )

    @task
    def responder_task(self) -> Task:
        return Task(
            config=self.tasks_config["responder_task"],
            output_pydantic=ResponsePlan
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=False
        )
