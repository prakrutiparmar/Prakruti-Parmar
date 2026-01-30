from fastapi import FastAPI
from datetime import datetime

app = FastAPI(
    title="Log Analysis API",
    description="Forensic log analysis results API",
    version="1.0"
)

# =========================
# Root Endpoint
# =========================
@app.get("/")
def root():
    return {
        "message": "Log Analysis API is running",
        "status": "OK"
    }


# =========================
# Summary of Findings
# =========================
@app.get("/api/logs/summary")
def summary():
    return {
        "analysis_metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "sources": [
                "events_filtered_Application.csv",
                "events_filtered_System.csv",
                "events_filtered_Security.csv",
                "powershell_history.txt",
                "cmdkey_list.txt",
                "transcript.txt",
                "evtx_export_skipped.txt"
            ]
        },

        "credential_access": {
            "detected": True,
            "evidence": [
                {
                    "source": "cmdkey_list.txt",
                    "description": "Stored credentials enumerated using cmdkey",
                    "risk": "MEDIUM"
                }
            ]
        },

        "privilege_escalation": {
            "detected": False,
            "notes": "No Event ID 4672 or administrative group assignments detected"
        },

        "suspicious_execution": {
            "powershell": {
                "detected": True,
                "commands": [
                    "Invoke-WebRequest",
                    "DownloadString"
                ],
                "risk": "HIGH"
            },
            "cmd": {
                "detected": False
            }
        },

        "persistence_or_network_activity": {
            "detected": False,
            "notes": "No scheduled task creation, service installation, or outbound C2 indicators found"
        }
    }


# =========================
# Timeline Reconstruction
# =========================
@app.get("/api/logs/timeline")
def timeline():
    return {
        "timeline": [
            {
                "timestamp": "2024-11-18T09:40:10Z",
                "source": "Security.evtx",
                "event_id": 4688,
                "description": "Process creation detected: powershell.exe",
                "severity": "INFO"
            },
            {
                "timestamp": "2024-11-18T09:44:12Z",
                "source": "PowerShell History",
                "event_id": "N/A",
                "description": "Invoke-WebRequest executed from interactive session",
                "severity": "HIGH"
            }
        ]
    }


# =========================
# Evidence & Artifacts
# =========================
@app.get("/api/logs/evidence")
def evidence():
    return {
        "powershell_history": [
            "Invoke-WebRequest http://example",
            "DownloadString http://example/payload.ps1"
        ],
        "transcript_findings": [
            "PowerShell commands executed in interactive user context"
        ],
        "credential_artifacts": [
            "cmdkey /list output indicates stored credentials"
        ],
        "skipped_logs": [
            "evtx_export_skipped.txt"
        ]
    }
