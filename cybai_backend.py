from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sklearn.ensemble import IsolationForest
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
        logs = pd.read_csv(LOG_FILE, sep="\t")
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

    logs[REQUIRED_COLS] = logs[REQUIRED_COLS].apply(pd.to_numeric)
    return logs, None


def run_analysis():
    logs, error = load_logs()
    if error:
        return error

    model = IsolationForest(contamination=0.22, random_state=42)
    model.fit(logs[REQUIRED_COLS])
    logs["anomaly"] = model.predict(logs[REQUIRED_COLS])

    alerts_df = logs[logs["anomaly"] == -1].copy()

    alerts = []
    for _, row in alerts_df.iterrows():
        alerts.append({
            "login_attempts": int(row["login_attempts"]),
            "failed_logins": int(row["failed_logins"]),
            "data_transfer_mb": float(row["data_transfer_mb"]),
            "message": "Possible brute-force or abnormal behaviour detected."
        })

    return {
        "status": "ok",
        "timestamp": utc_now(),
        "total_rows": int(len(logs)),
        "anomaly_count": int(len(alerts_df)),
        "normal_count": int((logs["anomaly"] == 1).sum()),
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


@app.options("/{rest_of_path:path}")
def preflight_handler(rest_of_path: str):
    return JSONResponse({"ok": True})