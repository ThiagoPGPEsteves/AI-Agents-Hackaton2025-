from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from dotenv import load_dotenv

load_dotenv()


# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class Cybersecurityteam():
    """Cybersecurityteam crew"""

    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

   
    @agent
    def monitor_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['monitor_agent'],
            tools=[Analyze_logs(),Activity_Logger() ],
            verbose=True
        )
    @agent
    def analyst_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['analyst_agent'],
            tools=[Threat_Analyzer(),Threat_Report_Generator()],
            verbose=True
        )
    @agent
    def executor_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['executor_agent'],
            tools=[Threat_Mitigator(),Threat_Notifier()],
            verbose=True
        )

  
    @task
    def monitor_task(self) -> Task:
        return Task(
           config=self.tasks_config['monitor_task'],
    )

    @task
    def analyst_task(self) -> Task:
        return Task(
            config=self.tasks_config['analyst_task'],
        )

    @task
    def executor_task(self) -> Task:
        return Task(
            config=self.tasks_config['executor_task'],
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Cybersecurityteam crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
