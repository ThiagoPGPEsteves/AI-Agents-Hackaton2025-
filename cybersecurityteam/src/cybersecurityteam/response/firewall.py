import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from ..config import settings

class SimulatedFirewall:
    """
    Firewall simulado com persistência JSON e suporte a TTL (tempo de expiração).
    Garante proteção incondicional para endereços IP na allowlist.
    """
    def __init__(self, blocklist_file: Optional[str] = None):
        base = settings.base_dir / settings.state_dir
        base.mkdir(parents=True, exist_ok=True)
        self.file_path = Path(blocklist_file) if blocklist_file else base / "blocklist.json"
        self._blocks: Dict[str, dict] = self._load()

    def _load(self) -> Dict[str, dict]:
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save(self):
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(self._blocks, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[Firewall Error] Falha ao persistir blocklist: {e}")

    def purge_expired(self):
        """Remove regras de bloqueio cujo TTL expirou."""
        now = time.time()
        expired = [ip for ip, data in self._blocks.items() if data.get("expires_at_ts", 0) <= now]
        for ip in expired:
            del self._blocks[ip]
        if expired:
            self._save()

    def block_ip(self, ip: str, reason: str, ttl_seconds: Optional[int] = None) -> bool:
        """
        Bloqueia um IP. Retorna True se bloqueado com sucesso,
        ou False se o IP estiver protegido na allowlist ou em modo DRY_RUN.
        """
        self.purge_expired()

        # Proteção rígida da Allowlist
        if ip in settings.allowlist_ips or ip.startswith("127.") or ip == "::1":
            print(f"🛡️ [Firewall Allowlist] IP protegido {ip} ignorado para bloqueio.")
            return False

        if settings.dry_run:
            print(f"🔍 [Firewall DRY-RUN] Simulação de bloqueio para IP {ip} (Motivo: {reason})")
            return True

        ttl = ttl_seconds if ttl_seconds is not None else settings.block_ttl_seconds
        now_ts = time.time()
        expires_ts = now_ts + ttl

        self._blocks[ip] = {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(expires_ts, tz=timezone.utc).isoformat(),
            "expires_at_ts": expires_ts,
            "reason": reason
        }
        self._save()
        print(f"🚫 [Firewall BLOCKED] IP {ip} bloqueado por {ttl}s. Motivo: {reason}")
        return True

    def is_blocked(self, ip: str) -> bool:
        self.purge_expired()
        return ip in self._blocks

    def get_active_blocks(self) -> List[dict]:
        self.purge_expired()
        return [{"ip": ip, **data} for ip, data in self._blocks.items()]
