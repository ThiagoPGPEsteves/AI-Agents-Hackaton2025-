from typing import Dict, Tuple

# Mapeamento determinístico padrão de categorias de ataque para MITRE ATT&CK e OWASP Top 10
ATTACK_MAPPING: Dict[str, Tuple[str, str, str]] = {
    "sqli": (
        "T1190",  # MITRE: Exploit Public-Facing Application
        "A03:2021-Injection",  # OWASP
        "Tentativa de injeção SQL para manipulação ou extração de dados do banco."
    ),
    "brute_force": (
        "T1110",  # MITRE: Brute Force
        "A07:2021-Identification and Authentication Failures",
        "Múltiplas tentativas sequenciais de autenticação sugerindo ataque de força bruta."
    ),
    "exfiltration": (
        "T1048",  # MITRE: Exfiltration Over Alternative Protocol
        "A01:2021-Broken Access Control",
        "Volume anômalo de consultas de leitura e dumps indicativo de exfiltração de dados."
    ),
    "lfi": (
        "T1083",  # MITRE: File and Directory Discovery
        "A01:2021-Broken Access Control",
        "Tentativa de travessia de diretórios (Path Traversal/LFI) para leitura de arquivos do sistema."
    ),
    "cmd_injection": (
        "T1059",  # MITRE: Command and Scripting Interpreter
        "A03:2021-Injection",
        "Tentativa de execução remota de comandos do sistema operacional no servidor."
    )
}

def get_attack_metadata(attack_type: str) -> Tuple[str, str, str]:
    """Retorna (mitre_technique, owasp_category, default_description) para o tipo de ataque."""
    return ATTACK_MAPPING.get(
        attack_type.lower(),
        ("T1059", "A03:2021-Injection", "Atividade cibernética suspeita não categorizada.")
    )
