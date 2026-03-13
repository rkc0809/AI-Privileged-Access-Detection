import subprocess

def run_script(script, step):

    print(f"\n[{step}] Running {script}...\n")

    with open(f"../reports/{script}_output.txt", "w") as f:
        subprocess.run(
            ["python", script],
            stdout=f,
            stderr=f,
            text=True
        )

scripts = [
    "log_generator.py",
    "anomaly_detection.py",
    "alert_engine.py",
    "investigation_agent.py",
    "threat_intel_check.py",
    "attack_pattern_detector.py",
    "attack_campaign_detector.py",
    "risk_scoring_engine.py",
    "correlation_engine.py",
    "ai_soc_analyst.py",
    "report_generator.py"
]
print("\n========== SOC DETECTION PIPELINE ==========\n")

for i, s in enumerate(scripts, start=1):
    run_script(s, i)

print("\nPipeline complete. Check reports folder.\n")