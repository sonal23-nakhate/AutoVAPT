from fastapi import FastAPI
import psycopg2
import os
import socket
import time
from apscheduler.schedulers.background import BackgroundScheduler

app = FastAPI()
scheduler = BackgroundScheduler()

# Targets to check on our regular background intervals
AUTOMATED_TARGETS = ["scanme.nmap.org"]

def get_db_connection():
    return psycopg2.connect(
        host="postgres-db",
        database=os.getenv("POSTGRES_DB", "autovapt_db"),
        user=os.getenv("POSTGRES_USER", "myuser"),
        password=os.getenv("POSTGRES_PASSWORD", "mypassword")
    )

@app.on_event("startup")
def setup_platform():
    print("AutoVAPT initialization process started...", flush=True)
    
    # 1. Establish resilient connection link to the PostgreSQL cluster
    conn = None
    retries = 5
    while retries > 0:
        try:
            conn = get_db_connection()
            break
        except Exception as e:
            print(f"Waiting for database cluster to wake up... (Retries left: {retries})", flush=True)
            time.sleep(3)
            retries -= 1

    if not conn:
        print("CRITICAL: Database link unavailable. Skipping table initialization.", flush=True)
        return

    # 2. Verify table existence
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_findings (
                id SERIAL PRIMARY KEY,
                target TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score FLOAT NOT NULL
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("PostgreSQL logging tables verified and online!", flush=True)
    except Exception as e:
        print(f"Table verification query failed: {e}", flush=True)

    # 3. Initialize background scheduled interval assessments
    try:
        scheduler.add_job(trigger_periodic_scans, 'interval', minutes=2)
        scheduler.start()
        print("Background automation task engine started successfully.", flush=True)
    except Exception as e:
        print(f"Failed to start interval scheduler: {e}", flush=True)

@app.on_event("shutdown")
def shutdown_platform():
    if scheduler.running:
        scheduler.shutdown()

def perform_live_assessment(target: str):
    clean_target = target.replace("http://", "").replace("https://", "").split('/')[0].split(':')[0].strip()
    print(f"Executing network socket probe against: {clean_target}", flush=True)
    
    # 1. LIVE DNS LOOKUP RESOLUTION
    try:
        ip_address = socket.gethostbyname(clean_target)
    except socket.gaierror:
        return {
            "status": "Scan Failed",
            "details": f"Target host resolution failed. Domain '{clean_target}' does not exist on the internet."
        }

    # 2. RUN PORT SCAN AGAINST CORE ACTIVE PORTS
    ports_to_check = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}
    open_ports = []
    
    for port, service in ports_to_check.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(service)
        s.close()

    # 3. TRANSLATE OPEN ATTACK SURFACE INTO SECURITY LOGIC
    if not open_ports:
        vulnerability = "Filtered Attack Surface (No Public Administrative Ports Exposed)"
        severity = "Low"
        risk_score = 1.5
    else:
        if "FTP" in open_ports or "SSH" in open_ports:
            vulnerability = f"Critical Infrastructure Exposure: Management Port Active ({', '.join(open_ports)})"
            severity = "High"
            risk_score = 8.5
        else:
            vulnerability = f"Standard Active Production Web Operations Listening ({', '.join(open_ports)})"
            severity = "Medium"
            risk_score = 4.5

    # 4. COMMIT RESULTS SECURELY TO POSTGRES DATABASE
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO security_findings (target, vulnerability, severity, risk_score) VALUES (%s, %s, %s, %s);",
            (clean_target, vulnerability, severity, risk_score)
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return {
            "status": "Scan Completed",
            "target": clean_target,
            "discovered_issue": vulnerability,
            "calculated_severity": severity,
            "final_risk_score": risk_score
        }
    except Exception as e:
        return {"status": "Scan Failed", "details": f"Database write validation error: {str(e)}"}

def trigger_periodic_scans():
    for target in AUTOMATED_TARGETS:
        perform_live_assessment(target)

@app.get("/run-scan")
def run_scan(target: str):
    return perform_live_assessment(target)

@app.get("/findings")
def get_findings():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT target, vulnerability, severity, risk_score FROM security_findings ORDER BY id DESC;")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return [{"target": r[0], "vulnerability": r[1], "severity": r[2], "risk_score": r[3]} for r in rows]
    except Exception as e:
        return []