from crewai.tools import BaseTool, tool
from typing import Type
from pydantic import BaseModel, Field
import requests
from datetime import datetime

# class MyCustomToolInput(BaseModel):
#     """Input schema for MyCustomTool."""
#     argument: str = Field(..., description="Description of the argument.")

# class MyCustomTool(BaseTool):
#     name: str = "Name of my tool"
#     description: str = (
#         "Clear description for what this tool is useful for, your agent will need this information to use it."
#     )
#     args_schema: Type[BaseModel] = MyCustomToolInput

#     def _run(self, argument: str) -> str:
#         # Implementation goes here
#         return "this is an example of a tool output, ignore it and move along."
    


class AnalyzeLogsInput(BaseModel):
     """Input schema for MyCustomTool."""
     logs: List[str] = Field(..., description="Lista de queries SQL para análise.")
     
class AnalyzeLogs(BaseTool):
    name: str = "Analyze_logs"
    descrption: str = (
          "Analisa logs SQL para identificar ataques"
     )
    args_schema: Type[BaseModel] = AnalyzeLogsInput

    def _run(self, logs:List[str]) -> str:
        # Implementation goes here
        suspicious_patterns = [" OR 1=1", "'; DROP", "' UNION SELECT", "xp_cmdshell"]
        suspicious_queries = [query for query in logs if any(pattern in query for pattern in suspicious_patterns)]
        
        if suspicious_queries:
            return f" ALERTA: Queries suspeitas detectadas: {suspicious_queries}"
        return "Nenhuma atividade suspeita detectada."

class ThreatAnalyzerInput(BaseModel):
    """Input schema para classificação de ameaças."""
    queries: List[str] = Field(..., description="Lista de queries suspeitas para classificação.")

class ThreatAnalyzerTool(BaseTool):
    name: str = "Threat_Analyzer"
    description: str = "Classifica queries suspeitas conforme nível de risco."
    args_schema: Type[BaseModel] = ThreatAnalyzerInput

    def _run(self, queries: List[str]) -> str:
        threat_levels = {"baixa": [], "média": [], "alta": []}

        for query in queries:
            if "DROP" in query or "DELETE" in query:
                threat_levels["alta"].append(query)
            elif "UNION SELECT" in query:
                threat_levels["média"].append(query)
            else:
                threat_levels["baixa"].append(query)

        return f" Classificação das ameaças: {threat_levels}"     



class ThreatMitigatorInput(BaseModel):
    """Input schema para as mitigar ameaças."""
    ip_address: str = Field(..., description="Endereço IP suspeito a ser bloqueado.")

class ThreatMitigatorTool(BaseTool):
    name: str = "Threat_Mitigator"
    description: str = "Executa ações para mitigar ameaças, incluindo bloqueio de IPs."
    args_schema: Type[BaseModel] = ThreatMitigatorInput

    def _run(self, ip_address: str) -> str:
        """
        Bloqueia um IP suspeito chamando uma API de firewall.

        Args:
            ip_address (str): O endereço IP suspeito a ser bloqueado.

        Returns:
            str: Mensagem indicando sucesso ou falha no bloqueio do IP.
        """

        #  URL da API do firewall (substituir pela API real)
        firewall_api = "https://firewall.example.com/block"

        #  Dados que serão enviados na requisição POST
        payload = {"ip": ip_address}

        try:
            #  Faz uma requisição POST para a API do firewall
            response = requests.post(firewall_api, json=payload)

            #  Se a resposta for 200 (sucesso), confirma o bloqueio
            if response.status_code == 200:
                return f" IP {ip_address} bloqueado com sucesso!"

            #  Caso contrário, retorna um erro com o status da resposta
            return f" Falha ao bloquear o IP {ip_address}. Código de resposta: {response.status_code}"

        except requests.exceptions.RequestException as e:
            #  Captura erros de requisição (exemplo: timeout, conexão falhou)
            return f" Erro ao conectar com a API do firewall: {str(e)}"




class ActivityLoggerInput(BaseModel):
    """Input schema para o registro de atividades."""
    event: str = Field(..., description="Descrição do evento ocorrido.")
    severity: str = Field(..., description="Nível de severidade do evento (INFO, ALERTA, CRÍTICO).")

class ActivityLoggerTool(BaseTool):
    name: str = "Activity_Logger"
    description: str = "Registra eventos do sistema para auditoria e análise de ameaças."
    args_schema: Type[BaseModel] = ActivityLoggerInput

    def _run(self, event: str, severity: str) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {severity}: {event}"
        
        # Aqui poderíamos salvar em um banco ou arquivo
        print(log_entry)
        
        return f" Evento registrado: {log_entry}"
    
class ThreatReportInput(BaseModel):
    """Input schema para geração de relatórios."""
    threats: List[str] = Field(..., description="Lista de ameaças identificadas.")
    detected_by: str = Field(..., description="Nome do agente que identificou a ameaça.")

class ThreatReportTool(BaseTool):
    name: str = "Threat_Report_Generator"
    description: str = "Gera relatórios detalhados sobre ameaças detectadas."
    args_schema: Type[BaseModel] = ThreatReportInput

    def _run(self, threats: List[str], detected_by: str) -> str:
        report = f" Relatório de Segurança\n\nAmeaças detectadas:\n"
        report += "\n".join(f"- {threat}" for threat in threats)
        report += f"\n\n Detectado por: {detected_by}"

        # Simula salvar um relatório (poderia ser um envio para um sistema)
        print(report)
        
        return f" Relatório gerado com sucesso!"
    
class ThreatNotifierInput(BaseModel):
    """Input schema para envio de alertas."""
    message: str = Field(..., description="Mensagem de alerta para os administradores.")
    contact_email: str = Field(..., description="E-mail do administrador para envio do alerta.")

class ThreatNotifierTool(BaseTool):
    name: str = "Threat_Notifier"
    description: str = "Envia alertas de ameaças para os administradores do sistema."
    args_schema: Type[BaseModel] = ThreatNotifierInput

    def _run(self, message: str, contact_email: str) -> str:
        # Simula envio de e-mail (poderia integrar com um serviço real)
        alert = f" Enviando alerta para {contact_email}:\n\n{message}"
        print(alert)
        
        return f" Alerta enviado para {contact_email}!"








 

# @tool("analyze_logs")
# def analyze_logs(argument: str) -> str:
#     """Analisa as queries do banco de dados"""

#     return ""

# def my_cache_strategy(arguments: dict, result: str) -> bool:
#     # Define custom caching logic
#     return True if some_condition else False

# cached_tool.cache_function = my_cache_strategy


# @tool
# def analyze_queries_tool(arguments: str) -> str:
#         """Analisa logs SQL e identifica possíveis ataques."""
#         suspicious_patterns = [" OR 1=1", "'; DROP", "' UNION SELECT", "xp_cmdshell"]
#         suspicious_queries = [query for query in str if any(pattern in query for pattern in suspicious_patterns)]
        
#         if suspicious_queries:
#             return f" ALERTA: Queries suspeitas detectadas: {suspicious_queries}"
#         return " Nenhuma atividade suspeita detectada."

# def analyze_queries_tool():
#     def analyze_queries(logs):
#         """Analisa logs SQL e identifica possíveis ataques."""
#         suspicious_patterns = [" OR 1=1", "'; DROP", "' UNION SELECT", "xp_cmdshell"]
#         suspicious_queries = [query for query in logs if any(pattern in query for pattern in suspicious_patterns)]
        
#         if suspicious_queries:
#             return f"⚠️ ALERTA: Queries suspeitas detectadas: {suspicious_queries}"
#         return "✅ Nenhuma atividade suspeita detectada."

#     return Tool(name="SQL Monitor", description="Analisa logs SQL para identificar ataques.", function=analyze_queries)
   

