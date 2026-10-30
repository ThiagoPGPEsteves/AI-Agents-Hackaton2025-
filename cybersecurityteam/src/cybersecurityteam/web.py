import os
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from .config import settings
from .models import LogEntry, Detection, Incident, Severity
from .detection.signatures import scan_signatures
from .flow import IncidentFlow
from .response.firewall import SimulatedFirewall
from .response.audit import AuditLogger

tempo_dir = settings.base_dir / "Tempo"

app = Flask(__name__, static_folder=str(tempo_dir), static_url_path="")
CORS(app)

firewall = SimulatedFirewall()
audit = AuditLogger()

@app.route("/")
def index():
    """Serve a interface gráfica do XenDefender."""
    if (tempo_dir / "index.html").exists():
        return send_from_directory(str(tempo_dir), "index.html")
    return jsonify({"message": "XenDefender API Online", "status": "active"})

@app.route("/analisar", methods=["POST"])
def analisar():
    """
    Endpoint consumido pelo frontend do XenDefender.
    Recebe texto/query, analisa assinaturas e aciona a CrewAI para triagem completa.
    """
    dados = request.get_json(force=True, silent=True) or {}
    texto = dados.get("texto", "").strip()

    if not texto:
        return jsonify({"mensagem": "Nenhum texto informado para análise."}), 400

    # 1. Varredura determinística preliminar
    detection = scan_signatures(texto)

    if not detection:
        # Se nenhuma assinatura estática foi violada
        return jsonify({
            "mensagem": "✅ Nenhuma ameaça detectada no texto/query analisada.",
            "status": "clean",
            "detalhes": {
                "severidade": "BAIXA",
                "tipo": "legitimo",
                "acao": "Nenhuma ação necessária."
            }
        })

    # 2. Cria um incidente sob demanda para a query
    dummy_entry = LogEntry(
        source_ip=request.remote_addr or "127.0.0.1",
        user="web_user",
        action_type="QUERY",
        payload=texto,
        status_code=200
    )

    incident = Incident(
        id=f"web-{abs(hash(texto)) % 1000000}",
        source_ip=dummy_entry.source_ip,
        attack_type=detection.attack_type,
        samples=[texto[:200]],
        heuristic_severity=detection.heuristic_severity,
        high_confidence=detection.high_confidence
    )

    # 3. Executa o IncidentFlow com a IncidentCrew (Gemini)
    try:
        flow = IncidentFlow(incident)
        result = flow.kickoff()
    except Exception as e:
        result = {
            "final_severity": detection.heuristic_severity.value,
            "actions_taken": ["audit_only"],
            "llm_status": f"fallback ({e})"
        }

    status_badge = "🔴 AMEAÇA CRÍTICA" if detection.heuristic_severity in (Severity.CRITICAL, Severity.HIGH) else "⚠️ SUSPEITA"

    return jsonify({
        "mensagem": f"{status_badge} DETECTADA! Ataque: {detection.attack_type.upper()}",
        "status": "threat_detected",
        "detalhes": {
            "tipo_ataque": detection.attack_type,
            "severidade": result.get("final_severity", detection.heuristic_severity.value),
            "padrao_detectado": detection.matched_pattern,
            "acoes_tomadas": result.get("actions_taken", []),
            "resumo": detection.details,
            "llm_status": result.get("llm_status", "ok")
        }
    })

@app.route("/api/status", methods=["GET"])
def get_status():
    """Retorna métricas em tempo real para o dashboard."""
    active_blocks = firewall.get_active_blocks()
    recent_audits = audit.get_recent_records(limit=10)
    return jsonify({
        "status": "online",
        "model": settings.model,
        "dry_run": settings.dry_run,
        "total_blocked_ips": len(active_blocks),
        "active_blocks": active_blocks,
        "recent_incidents": recent_audits
    })

def run_web(host: str = "127.0.0.1", port: int = 5000):
    print(f"\n🌐 [XenDefender Dashboard] Servidor iniciado em http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
