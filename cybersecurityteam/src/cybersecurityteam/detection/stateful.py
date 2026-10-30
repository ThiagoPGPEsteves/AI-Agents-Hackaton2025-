import time
from collections import deque
from typing import Dict, Optional, Tuple
from ..models import LogEntry, Detection, Severity

class StatefulAnomalyDetector:
    """
    Detector de anomalias com estado em janela deslizante.
    Identifica ataques de Força Bruta e Exfiltração de dados por volume.
    Implementa limite máximo de IPs rastreados (LRU) para evitar esgotamento de memória.
    """
    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window: int = 60,
        exfiltration_threshold: int = 15,
        exfiltration_window: int = 60,
        max_tracked_ips: int = 10000
    ):
        self.brute_threshold = brute_force_threshold
        self.brute_window = brute_force_window
        self.exfil_threshold = exfiltration_threshold
        self.exfil_window = exfiltration_window
        self.max_ips = max_tracked_ips

        # { ip: deque([timestamps]) }
        self._auth_failures: Dict[str, deque] = {}
        self._query_bursts: Dict[str, deque] = {}

    def _prune_and_add(self, storage: Dict[str, deque], key: str, window: int) -> int:
        now = time.time()
        # Controle de tamanho para evitar DoS em memória
        if len(storage) >= self.max_ips and key not in storage:
            # Remove o primeiro item mais antigo
            oldest_key = next(iter(storage))
            del storage[oldest_key]

        if key not in storage:
            storage[key] = deque()

        q = storage[key]
        q.append(now)

        # Remove eventos fora da janela
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()

        return len(q)

    def analyze(self, entry: LogEntry) -> Optional[Detection]:
        """Avalia um LogEntry e retorna Detection se cruzar limiares de volume/frequência."""
        ip = entry.source_ip

        # 1. Detecção de Força Bruta (Autenticação com status 401/403/falha)
        is_auth_failure = (
            entry.action_type == "AUTH_LOGIN" and entry.status_code in (401, 403)
        ) or "login failed" in entry.payload.lower() or "invalid password" in entry.payload.lower()

        if is_auth_failure:
            count = self._prune_and_add(self._auth_failures, ip, self.brute_window)
            if count >= self.brute_threshold:
                return Detection(
                    attack_type="brute_force",
                    matched_pattern=f"{count} falhas em {self.brute_window}s",
                    heuristic_severity=Severity.HIGH,
                    high_confidence=True,
                    details=f"Força bruta detectada para IP {ip}: {count} tentativas de login com falha."
                )

        # 2. Detecção de Exfiltração de Dados (Volume anômalo de consultas em janela curta)
        is_query = entry.action_type in ("QUERY", "SELECT") or entry.payload.upper().startswith("SELECT")
        if is_query:
            count = self._prune_and_add(self._query_bursts, ip, self.exfil_window)
            if count >= self.exfil_threshold:
                return Detection(
                    attack_type="exfiltration",
                    matched_pattern=f"{count} queries em {self.exfil_window}s",
                    heuristic_severity=Severity.HIGH,
                    high_confidence=False,
                    details=f"Volume anômalo de consultas para IP {ip}: {count} queries em {self.exfil_window}s."
                )

        return None
