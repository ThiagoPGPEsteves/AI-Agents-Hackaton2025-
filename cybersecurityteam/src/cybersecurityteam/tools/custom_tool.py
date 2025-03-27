from crewai.tools import BaseTool, tool
from typing import Type
from pydantic import BaseModel, Field



class MyCustomToolInput(BaseModel):
    """Input schema for MyCustomTool."""
    argument: str = Field(..., description="Description of the argument.")

class MyCustomTool(BaseTool):
    name: str = "Name of my tool"
    description: str = (
        "Clear description for what this tool is useful for, your agent will need this information to use it."
    )
    args_schema: Type[BaseModel] = MyCustomToolInput

    def _run(self, argument: str) -> str:
        # Implementation goes here
        return "this is an example of a tool output, ignore it and move along."
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

        

@tool("analyze_logs")
def analyze_logs(argument: str) -> str:
    """Analisa as queries do banco de dados"""

    return ""

def my_cache_strategy(arguments: dict, result: str) -> bool:
    # Define custom caching logic
    return True if some_condition else False

cached_tool.cache_function = my_cache_strategy


@tool
def analyze_queries_tool(arguments: str) -> str:
        """Analisa logs SQL e identifica possíveis ataques."""
        suspicious_patterns = [" OR 1=1", "'; DROP", "' UNION SELECT", "xp_cmdshell"]
        suspicious_queries = [query for query in str if any(pattern in query for pattern in suspicious_patterns)]
        
        if suspicious_queries:
            return f" ALERTA: Queries suspeitas detectadas: {suspicious_queries}"
        return " Nenhuma atividade suspeita detectada."

def analyze_queries_tool():
    def analyze_queries(logs):
        """Analisa logs SQL e identifica possíveis ataques."""
        suspicious_patterns = [" OR 1=1", "'; DROP", "' UNION SELECT", "xp_cmdshell"]
        suspicious_queries = [query for query in logs if any(pattern in query for pattern in suspicious_patterns)]
        
        if suspicious_queries:
            return f"⚠️ ALERTA: Queries suspeitas detectadas: {suspicious_queries}"
        return "✅ Nenhuma atividade suspeita detectada."

    return Tool(name="SQL Monitor", description="Analisa logs SQL para identificar ataques.", function=analyze_queries)
   
