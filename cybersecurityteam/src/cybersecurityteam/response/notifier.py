import requests
from ..config import settings
from ..models import Severity

class SecurityNotifier:
    """Disparador de alertas de segurança para múltiplos canais (Console, Slack, Discord)."""

    @staticmethod
    def notify(incident_id: str, ip: str, severity: Severity, attack_type: str, summary: str):
        # 1. Alerta colorido no console
        badge = {
            Severity.LOW: "🟢 [INFO]",
            Severity.MEDIUM: "🟡 [ALERTA]",
            Severity.HIGH: "🟠 [ALTO RISCO]",
            Severity.CRITICAL: "🔴 [CRÍTICO]"
        }.get(severity, "⚠️ [ALERTA]")

        print(f"\n{'='*70}")
        print(f"{badge} INCIDENTE DE SEGURANÇA: {attack_type.upper()}")
        print(f"ID: {incident_id} | Origem: {ip} | Severidade: {severity.value}")
        print(f"Resumo: {summary}")
        print(f"{'='*70}\n")

        # 2. Slack Webhook (se configurado)
        if settings.slack_webhook_url:
            try:
                payload = {
                    "text": f"*{badge} Incidente Detectado*\n*ID:* `{incident_id}`\n*IP:* `{ip}`\n*Severidade:* `{severity.value}`\n*Ataque:* `{attack_type}`\n*Detalhes:* {summary}"
                }
                requests.post(settings.slack_webhook_url, json=payload, timeout=5)
            except Exception as e:
                print(f"[Notifier Warning] Falha ao enviar alerta para Slack: {e}")

        # 3. Discord Webhook (se configurado)
        if settings.discord_webhook_url:
            try:
                payload = {
                    "embeds": [{
                        "title": f"{badge} Incidente: {attack_type.upper()}",
                        "description": summary,
                        "color": 15158332 if severity == Severity.CRITICAL else (15105570 if severity == Severity.HIGH else 3066993),
                        "fields": [
                            {"name": "ID", "value": incident_id, "inline": True},
                            {"name": "IP de Origem", "value": ip, "inline": True},
                            {"name": "Severidade", "value": severity.value, "inline": True}
                        ]
                    }]
                }
                requests.post(settings.discord_webhook_url, json=payload, timeout=5)
            except Exception as e:
                print(f"[Notifier Warning] Falha ao enviar alerta para Discord: {e}")
