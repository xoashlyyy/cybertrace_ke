"""Generate SIMULATED security incidents. No real systems are touched.

Scenario: external attacker scans the app, brute-forces a staff account,
logs in, reaches the admin panel, bulk-reads the customers table and exfiltrates it.
Benign background noise is mixed in so the analyst has to correlate, not just read.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

ATTACKER_IP = "203.0.113.50"          # TEST-NET-3 documentation range
APP_SERVER = "10.0.1.10"
DB_SERVER = "10.0.2.20"
STAFF = ["jmwangi", "akamau", "nochieng", "wnjeri", "pkiprop"]
OFFICE_IPS = ["10.0.5.11", "10.0.5.12", "10.0.5.13", "10.0.5.14"]

# the ordered ground truth an analyst should reconstruct
TRUE_STAGES = ["reconnaissance", "credential_access", "initial_access",
               "privilege_escalation", "collection", "exfiltration"]
STAGE_OF = {
    "port_scan": "reconnaissance",
    "login_failed": "credential_access",
    "login_success": "initial_access",
    "admin_access": "privilege_escalation",
    "db_bulk_select": "collection",
    "large_outbound": "exfiltration",
}


def _ev(ts, source, etype, src_ip, user=None, dst_ip=None, detail="", severity=1, bytes_=0):
    return {"id": uuid.uuid4().hex[:8], "ts": ts.isoformat(), "source": source,
            "event_type": etype, "src_ip": src_ip, "dst_ip": dst_ip, "user": user,
            "detail": detail, "severity": severity, "bytes": bytes_}


def generate_incident(seed: int | None = None):
    rng = random.Random(seed)
    victim = rng.choice(STAFF)
    t0 = datetime(2026, 3, 14, 1, 0, tzinfo=timezone.utc) + timedelta(minutes=rng.randint(0, 120))
    events = []

    # --- attack ---
    t = t0
    for port in rng.sample([21, 22, 23, 80, 443, 3306, 5432, 8080], 6):
        t += timedelta(seconds=rng.randint(1, 4))
        events.append(_ev(t, "network", "port_scan", ATTACKER_IP, dst_ip=APP_SERVER,
                          detail=f"SYN probe to port {port}", severity=2))
    t += timedelta(minutes=3)
    for i in range(rng.randint(18, 40)):
        t += timedelta(seconds=rng.randint(1, 3))
        events.append(_ev(t, "auth", "login_failed", ATTACKER_IP, user=victim,
                          dst_ip=APP_SERVER, detail="Invalid password", severity=3))
    t += timedelta(seconds=5)
    events.append(_ev(t, "auth", "login_success", ATTACKER_IP, user=victim,
                      dst_ip=APP_SERVER, detail="Login OK after repeated failures", severity=4))
    t += timedelta(minutes=2)
    events.append(_ev(t, "app", "admin_access", APP_SERVER, user=victim,
                      detail="GET /admin/export (role normally not used by this user)", severity=4))
    t += timedelta(minutes=1)
    events.append(_ev(t, "db", "db_bulk_select", APP_SERVER, user=victim, dst_ip=DB_SERVER,
                      detail="SELECT * FROM customers (48,210 rows)", severity=5, bytes_=18_500_000))
    t += timedelta(minutes=2)
    events.append(_ev(t, "network", "large_outbound", APP_SERVER, user=victim, dst_ip=ATTACKER_IP,
                      detail="HTTPS upload 18.4 MB to external host", severity=5, bytes_=18_400_000))

    # --- benign noise across the same window ---
    for _ in range(rng.randint(60, 90)):
        ts = t0 - timedelta(minutes=30) + timedelta(seconds=rng.randint(0, 3 * 3600))
        kind = rng.choice(["login_success", "login_failed", "page_view", "db_query", "outbound"])
        user, ip = rng.choice(STAFF), rng.choice(OFFICE_IPS)
        if kind == "login_success":
            events.append(_ev(ts, "auth", kind, ip, user, APP_SERVER, "Normal login"))
        elif kind == "login_failed":
            events.append(_ev(ts, "auth", kind, ip, user, APP_SERVER, "Typo in password"))
        elif kind == "page_view":
            events.append(_ev(ts, "app", kind, ip, user, APP_SERVER, "GET /dashboard"))
        elif kind == "db_query":
            events.append(_ev(ts, "db", kind, APP_SERVER, user, DB_SERVER, "SELECT ... LIMIT 20", bytes_=rng.randint(500, 9000)))
        else:
            events.append(_ev(ts, "network", kind, APP_SERVER, user, "198.51.100.7",
                              "Update check", bytes_=rng.randint(1000, 50000)))
    events.sort(key=lambda e: e["ts"])
    truth = {"suspect_ip": ATTACKER_IP, "compromised_user": victim, "stages": TRUE_STAGES}
    return events, truth
