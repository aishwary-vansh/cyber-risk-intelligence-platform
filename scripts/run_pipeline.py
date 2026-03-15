"""
Cyber Risk Intelligence & Adaptive Defense Platform
Main Pipeline Runner
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Ensure project root is always in Python path regardless of how script is called
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from src.ingestion.log_parser import LogParser
from src.detection.anomaly_detector import AnomalyDetector
from src.correlation.chain_builder import AttackChainBuilder
from src.scoring.risk_scorer import RiskScorer
from src.privacy.privacy_monitor import PrivacyMonitor
from src.advisor.defense_advisor import DefenseAdvisor


def run_pipeline(log_dir: str, output_path: str = "output/results.json"):
    logger.info("🛡️  Starting Cyber Risk Intelligence Pipeline")

    # Step 1: Ingest logs
    logger.info("📥 Step 1: Ingesting logs from {}", log_dir)
    parser = LogParser(log_dir=log_dir)
    events = parser.parse_all()
    logger.info("   → {} events loaded", len(events))

    # Step 2: Detect anomalies
    logger.info("🤖 Step 2: Running behavioural anomaly detection")
    detector = AnomalyDetector()
    anomalies = detector.detect(events)
    logger.info("   → {} anomalies detected", len(anomalies))

    # Step 3: Correlate attack chains
    logger.info("🔗 Step 3: Correlating attack chains")
    chain_builder = AttackChainBuilder()
    chains = chain_builder.build_chains(anomalies)
    logger.info("   → {} attack chains identified", len(chains))

    # Step 4: Score risks
    logger.info("📊 Step 4: Scoring dynamic cyber risks")
    scorer = RiskScorer()
    risk_scores = scorer.score(events, anomalies)
    logger.info("   → Risk scores computed for {} entities", len(risk_scores))

    # Step 5: Privacy monitoring
    logger.info("🔐 Step 5: Running privacy risk monitoring")
    privacy_monitor = PrivacyMonitor()
    privacy_alerts = privacy_monitor.analyze(events)
    logger.info("   → {} privacy risk signals detected", len(privacy_alerts))

    # Step 6: Defense recommendations
    logger.info("⚠️  Step 6: Generating adaptive defense recommendations")
    advisor = DefenseAdvisor()
    recommendations = advisor.recommend(risk_scores, chains, privacy_alerts)
    logger.info("   → {} recommendations generated", len(recommendations))

    # Compile results
    results = {
        "summary": {
            "total_events": len(events),
            "anomalies_detected": len(anomalies),
            "attack_chains": len(chains),
            "privacy_alerts": len(privacy_alerts),
            "recommendations": len(recommendations),
        },
        "risk_scores": risk_scores,
        "attack_chains": chains,
        "privacy_alerts": privacy_alerts,
        "recommendations": recommendations,
    }

    # Save output
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    logger.success("✅ Pipeline complete. Results saved to {}", output_path)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Risk Intelligence Pipeline")
    parser.add_argument("--log-dir", default="data/sample_logs/", help="Directory containing log files")
    parser.add_argument("--output", default="output/results.json", help="Output file path")
    args = parser.parse_args()

    run_pipeline(args.log_dir, args.output)