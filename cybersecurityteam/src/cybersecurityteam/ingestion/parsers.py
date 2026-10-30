import json
import re
from datetime import datetime, timezone
from typing import Optional
from ..models import LogEntry

# Regex para fallback de logs comuns estilo Apache/Nginx ou Syslog
RE_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)[^"]*"\s+(?P<status>\d+)'
)

def parse_log_line(raw_line: str) -> Optional[LogEntry]:
    """
    Normaliza uma linha de log para um objeto LogEntry estruturado.
    Aceita JSON Lines (padrão) ou logs de servidor web/banco de dados.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    # 1. Tentativa via JSON Lines
    if raw_line.startswith("{") and raw_line.endswith("}"):
        try:
            data = json.loads(raw_line)
            ts = data.get("timestamp")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    dt = datetime.now(timezone.utc)
            else:
                dt = datetime.now(timezone.utc)

            return LogEntry(
                timestamp=dt,
                source_ip=data.get("source_ip") or data.get("ip") or "127.0.0.1",
                user=data.get("user") or data.get("username") or "anonymous",
                action_type=data.get("action_type") or data.get("type") or "QUERY",
                payload=str(data.get("payload") or data.get("query") or data.get("message") or ""),
                status_code=int(data.get("status_code", 200)),
                session_id=data.get("session_id"),
                raw_line=raw_line
            )
        except Exception:
            pass

    # 2. Tentativa via formato padrão Web
    match = RE_APACHE.match(raw_line)
    if match:
        return LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip=match.group("ip"),
            user=match.group("user") if match.group("user") != "-" else "anonymous",
            action_type="HTTP_REQUEST",
            payload=match.group("path"),
            status_code=int(match.group("status")),
            raw_line=raw_line
        )

    # 3. Fallback genérico para texto livre ou query SQL simples
    return LogEntry(
        timestamp=datetime.now(timezone.utc),
        source_ip="127.0.0.1",
        user="system",
        action_type="QUERY",
        payload=raw_line,
        status_code=200,
        raw_line=raw_line
    )
