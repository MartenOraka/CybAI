from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

app = FastAPI(title="CybAI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

LOG_FILE = Path("logs.csv")
REQUIRED_COLS = ["login_attempts", "failed_logins", "data_transfer_mb"]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_logs():
    if not LOG_FILE.exists():
        return None, {
            "status": "error",
            "message": "logs.csv not found",
            "timestamp": utc_now(),
        }

    try:
        logs = pd.read_csv(LOG_FILE, sep=None, engine="python")
    except Exception as e:
        return None, {
            "status": "error",
            "message": f"Failed to read logs.csv: {str(e)}",
            "timestamp": utc_now(),
        }

    logs.columns = (
        logs.columns.astype(str)
        .str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
    )

    missing = [col for col in REQUIRED_COLS if col not in logs.columns]
    if missing:
        return None, {
            "status": "error",
            "message": f"Missing columns in logs.csv: {missing}. Found columns: {logs.columns.tolist()}",
            "timestamp": utc_now(),
        }

    try:
        logs[REQUIRED_COLS] = logs[REQUIRED_COLS].apply(pd.to_numeric)
    except Exception as e:
        return None, {
            "status": "error",
            "message": f"Invalid numeric data in logs.csv: {str(e)}",
            "timestamp": utc_now(),
        }

    return logs, None


def calculate_risk_score(row):
    score = 0

    if row["login_attempts"] >= 100:
        score += 35
    elif row["login_attempts"] >= 70:
        score += 20

    if row["failed_logins"] >= 20:
        score += 35
    elif row["failed_logins"] >= 10:
        score += 20
    elif row["failed_logins"] >= 5:
        score += 10

    if row["data_transfer_mb"] >= 500:
        score += 30
    elif row["data_transfer_mb"] >= 250:
        score += 15

    return min(score, 100)


def classify_row(row):
    risk_score = calculate_risk_score(row)

    is_anomaly = (
        row["login_attempts"] >= 100
        or row["failed_logins"] >= 20
        or row["data_transfer_mb"] >= 500
        or risk_score >= 60
    )

    severity = "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "normal"

    return pd.Series({
        "risk_score": risk_score,
        "anomaly": -1 if is_anomaly else 1,
        "severity": severity
    })


def run_analysis():
    logs, error = load_logs()
    if error:
        return error

    derived = logs.apply(classify_row, axis=1)
    logs = pd.concat([logs, derived], axis=1)

    alerts_df = logs[logs["anomaly"] == -1].copy()

    alerts = []
    for _, row in alerts_df.iterrows():
        alerts.append({
            "login_attempts": int(row["login_attempts"]),
            "failed_logins": int(row["failed_logins"]),
            "data_transfer_mb": float(row["data_transfer_mb"]),
            "risk_score": int(row["risk_score"]),
            "severity": row["severity"],
            "message": "Possible brute-force or abnormal behaviour detected."
        })

    critical_risks = int((logs["severity"] == "critical").sum())
    high_risks = int((logs["severity"] == "high").sum())
    highest_risk_score = int(logs["risk_score"].max()) if len(logs) > 0 else 0

    return {
        "status": "ok",
        "timestamp": utc_now(),
        "total_rows": int(len(logs)),
        "anomaly_count": int(len(alerts_df)),
        "normal_count": int((logs["anomaly"] == 1).sum()),
        "critical_risks": critical_risks,
        "high_risks": high_risks,
        "highest_risk_score": highest_risk_score,
        "alerts": alerts,
        "rows": logs.to_dict(orient="records")
    }


@app.get("/")
def root():
    return {"message": "CybAI backend is running"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "cybai-backend"}


@app.get("/analysis")
def analysis():
    return run_analysis()


@app.get("/favicon.ico")
def favicon():
    return JSONResponse(content={}, status_code=204)


@app.get("/analytics")
def analytics():
    return JSONResponse(content={"status": "not_used"}, status_code=200)


@app.options("/{rest_of_path:path}")
def preflight_handler(rest_of_path: str):
    return JSONResponse({"ok": True})