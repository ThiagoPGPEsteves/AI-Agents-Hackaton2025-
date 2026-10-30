import os
from pathlib import Path
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # LLM Settings
    model: str = Field(default="gemini/gemini-3.5-flash", alias="MODEL")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    
    # Paths
    base_dir: Path = Path(__file__).resolve().parent.parent.parent.parent
    log_file_path: str = Field(default="logs/server.log", alias="LOG_FILE_PATH")
    state_dir: str = Field(default="state", alias="STATE_DIR")
    
    # Security Policies
    dry_run: bool = Field(default=True, alias="DRY_RUN")
    block_ttl_seconds: int = Field(default=3600, alias="BLOCK_TTL_SECONDS")  # 1 hora
    allowlist_ips: List[str] = Field(
        default=["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "localhost"],
        alias="ALLOWLIST_IPS"
    )
    
    # Thresholds de anomalia com estado
    brute_force_threshold: int = Field(default=5, alias="BRUTE_FORCE_THRESHOLD")
    brute_force_window_seconds: int = Field(default=60, alias="BRUTE_FORCE_WINDOW_SECONDS")
    
    exfiltration_threshold: int = Field(default=15, alias="EXFILTRATION_THRESHOLD")
    exfiltration_window_seconds: int = Field(default=60, alias="EXFILTRATION_WINDOW_SECONDS")
    
    # Notificações
    slack_webhook_url: str = Field(default="", alias="SLACK_WEBHOOK_URL")
    discord_webhook_url: str = Field(default="", alias="DISCORD_WEBHOOK_URL")
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

def get_settings() -> Settings:
    # Busca .env tanto na raiz quanto na pasta do módulo
    root_env = Path(__file__).resolve().parent.parent.parent.parent / ".env"
    module_env = Path(__file__).resolve().parent / ".env"
    from dotenv import load_dotenv
    if root_env.exists():
        load_dotenv(root_env)
    elif module_env.exists():
        load_dotenv(module_env)
    return Settings()

settings = get_settings()
