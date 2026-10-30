#!/usr/bin/env python
import sys
import time
import argparse
from pathlib import Path

from .config import settings
from .ingestion.tailer import LogTailer
from .ingestion.parsers import parse_log_line
from .detection.signatures import scan_signatures
from .detection.stateful import StatefulAnomalyDetector
from .detection.aggregator import IncidentAggregator
from .flow import IncidentFlow
from .response.firewall import SimulatedFirewall
from .response.audit import AuditLogger
from .simulator import LogSimulator
from .web import run_web

def monitor_loop():
    """
    Motor central de monitoramento em tempo real.
    Observa novos logs continuamente, executa pipeline determinístico e aciona
    a IncidentCrew para análise aprofundada de incidentes.
    """
    log_path = settings.base_dir / settings.log_file_path
    offset_file = settings.base_dir / settings.state_dir / "offset.json"
    
    print("\n" + "=" * 70)
    print("🛡️  XENDEFENDER — ORQUESTRADOR DE CIBERSEGURANÇA EM TEMPO REAL")
    print(f"Modo: {'DRY-RUN (Simulação)' if settings.dry_run else 'LIVE (Contenção Ativa)'}")
    print(f"Modelo IA: {settings.model}")
    print(f"Arquivo Monitorado: {log_path}")
    print("=" * 70 + "\n")

    # Garante que o arquivo de log e a pasta de estado existam
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.touch()

    tailer = LogTailer(file_path=str(log_path), offset_file=str(offset_file))
    stateful_detector = StatefulAnomalyDetector(
        brute_force_threshold=settings.brute_force_threshold,
        brute_force_window=settings.brute_force_window_seconds,
        exfiltration_threshold=settings.exfiltration_threshold,
        exfiltration_window=settings.exfiltration_window_seconds
    )
    aggregator = IncidentAggregator(cooldown_seconds=30)

    total_lines = 0
    total_detections = 0
    total_incidents = 0
    last_metric_time = time.time()

    try:
        for raw_line in tailer.follow(poll_interval=0.5):
            total_lines += 1
            entry = parse_log_line(raw_line)
            if not entry:
                continue

            # 1. Análise de Assinaturas (SQLi, Command Injection, LFI)
            detection = scan_signatures(entry.payload)

            # 2. Análise com Estado (Brute Force, Exfiltração)
            if not detection:
                detection = stateful_detector.analyze(entry)

            # 3. Agrupamento e Triagem se ameaça for detectada
            if detection:
                total_detections += 1
                incident, should_dispatch = aggregator.process(entry, detection)

                if should_dispatch:
                    total_incidents += 1
                    print(f"⚡ [Novo Incidente {incident.id}] Detectado {detection.attack_type.upper()} de {incident.source_ip} (Severidade: {incident.heuristic_severity.value})")
                    
                    # Aciona o IncidentFlow (roteamento condicional + CrewAI + Gemini)
                    try:
                        flow = IncidentFlow(incident)
                        flow.kickoff()
                    except Exception as e:
                        print(f"❌ [Erro no Fluxo] {e}")

            # Métricas periódicas a cada 15 segundos
            now = time.time()
            if now - last_metric_time >= 15:
                print(f"📊 [Status Monitor] Linhas processadas: {total_lines} | Detecções: {total_detections} | Incidentes tratados: {total_incidents}")
                last_metric_time = now

    except KeyboardInterrupt:
        print("\n🛑 [Monitor] Encerrado pelo operador.")

def show_status():
    """Exibe o estado atual da segurança, IPs bloqueados e histórico."""
    firewall = SimulatedFirewall()
    audit = AuditLogger()
    blocks = firewall.get_active_blocks()
    recent = audit.get_recent_records(limit=5)

    print("\n" + "=" * 60)
    print("📋 ESTADO DO ORQUESTRADOR XENDEFENDER")
    print(f"Modo: {'DRY-RUN' if settings.dry_run else 'LIVE'}")
    print(f"Total de IPs Bloqueados no Firewall: {len(blocks)}")
    for b in blocks:
        print(f"  - IP: {b['ip']} | Expira em: {b['expires_at']} | Motivo: {b['reason']}")
    print("\nÚltimos Incidentes Auditados:")
    for r in recent:
        print(f"  - [{r['timestamp'][:19]}] {r['final_severity']} | {r['source_ip']} | {r['threat_summary'][:60]}...")
    print("=" * 60 + "\n")

def run():
    """Entry point principal para crewai run e CLI."""
    parser = argparse.ArgumentParser(description="XenDefender Cybersecurity Orchestrator")
    parser.add_argument(
        "command",
        nargs="?",
        default="monitor",
        choices=["monitor", "simulate", "web", "status"],
        help="Comando a executar (monitor, simulate, web, status)"
    )
    args = parser.parse_args(sys.argv[1:] if len(sys.argv) > 1 else ["monitor"])

    if args.command == "monitor":
        monitor_loop()
    elif args.command == "simulate":
        LogSimulator().run(interval=1.2)
    elif args.command == "web":
        run_web()
    elif args.command == "status":
        show_status()

if __name__ == "__main__":
    run()
