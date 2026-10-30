import re
import urllib.parse
from typing import Optional
from ..models import Detection, Severity

# Padrões compilados para detecção de alta velocidade
SQLI_CRITICAL = re.compile(
    r'(?i)(;\s*drop\s+table|;\s*drop\s+database|xp_cmdshell|exec\s+master\.\.xp_cmdshell)',
    re.IGNORECASE
)

SQLI_HIGH = re.compile(
    r'(?i)(\bunion\s+(?:all\s+)?select\b|information_schema\b|\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+)',
    re.IGNORECASE
)

SQLI_MEDIUM = re.compile(
    r'(?i)(\bor\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|\band\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|--\s*$|/\*.*?\*/)',
    re.IGNORECASE
)

CMD_INJECTION = re.compile(
    r'(?i)(;\s*(?:id|whoami|cat\s+/etc|ls\s+-la|bash\s+-i|nc\s+-e|curl\s+https?|wget\s+https?)|\|\s*(?:bash|sh)|\$\([^\)]+\)|`[^`]+`)',
    re.IGNORECASE
)

PATH_TRAVERSAL = re.compile(
    r'(?i)(\.\./\.\./|etc/passwd|etc/shadow|windows/system32|boot\.ini)',
    re.IGNORECASE
)

def normalize_payload(payload: str) -> str:
    """Decodifica URL encodings e normaliza espaços para evitar técnicas comuns de evasão."""
    if not payload:
        return ""
    # Decodifica URL múltiplas vezes para neutralizar double encoding
    try:
        decoded = urllib.parse.unquote(payload)
        decoded = urllib.parse.unquote(decoded)
    except Exception:
        decoded = payload
    # Colapsa múltiplos espaços em branco
    return re.sub(r'\s+', ' ', decoded).strip()

def scan_signatures(payload: str) -> Optional[Detection]:
    """
    Analisa um payload contra assinaturas conhecidas de ataques.
    Retorna Detection se encontrar assinatura maliciosa ou None se limpo.
    """
    if not payload or len(payload) < 3:
        return None

    normalized = normalize_payload(payload)

    # 1. Command Injection (CRITICAL)
    match = CMD_INJECTION.search(normalized)
    if match:
        return Detection(
            attack_type="cmd_injection",
            matched_pattern=match.group(0),
            heuristic_severity=Severity.CRITICAL,
            high_confidence=True,
            details=f"Injeção de comandos do sistema operacional detectada: '{match.group(0)}'"
        )

    # 2. SQLi Crítico (DROP TABLE, xp_cmdshell)
    match = SQLI_CRITICAL.search(normalized)
    if match:
        return Detection(
            attack_type="sqli",
            matched_pattern=match.group(0),
            heuristic_severity=Severity.CRITICAL,
            high_confidence=True,
            details=f"Comando SQL altamente destrutivo detectado: '{match.group(0)}'"
        )

    # 3. Path Traversal / LFI (HIGH)
    match = PATH_TRAVERSAL.search(normalized)
    if match:
        return Detection(
            attack_type="lfi",
            matched_pattern=match.group(0),
            heuristic_severity=Severity.HIGH,
            high_confidence=True,
            details=f"Tentativa de acesso a arquivos restritos do sistema (LFI): '{match.group(0)}'"
        )

    # 4. SQLi de Alta Criticidade (UNION SELECT, exfiltração de schema)
    match = SQLI_HIGH.search(normalized)
    if match:
        return Detection(
            attack_type="sqli",
            matched_pattern=match.group(0),
            heuristic_severity=Severity.HIGH,
            high_confidence=True,
            details=f"Padrão clássico de injeção SQL/exfiltração detectado: '{match.group(0)}'"
        )

    # 5. SQLi Médio (Tautologia OR 1=1, comentários suspeitos)
    match = SQLI_MEDIUM.search(normalized)
    if match:
        return Detection(
            attack_type="sqli",
            matched_pattern=match.group(0),
            heuristic_severity=Severity.MEDIUM,
            high_confidence=False,
            details=f"Potencial bypass de autenticação ou comentário SQL detectado: '{match.group(0)}'"
        )

    return None
