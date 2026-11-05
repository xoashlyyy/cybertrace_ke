import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from fastapi.testclient import TestClient

from app import correlate, scoring, simulator
from app.main import app

client = TestClient(app)


def test_simulator_is_deterministic_with_seed():
    a, ta = simulator.generate_incident(1)
    b, tb = simulator.generate_incident(1)
    assert [e["event_type"] for e in a] == [e["event_type"] for e in b]
    assert ta == tb


def test_correlation_recovers_ground_truth():
    events, truth = simulator.generate_incident(3)
    r = correlate.reconstruct(events)
    assert r["suspect_ip"] == truth["suspect_ip"]
    assert r["compromised_user"] == truth["compromised_user"]
    assert r["stages"] == truth["stages"]


def test_perfect_and_wrong_scores():
    _, truth = simulator.generate_incident(5)
    assert scoring.score_submission(truth, truth)["total"] == 100
    assert scoring.score_submission(truth, {"stages": []})["total"] == 0


def test_anomaly_flags_exfiltration_highly():
    events, _ = simulator.generate_incident(9)
    s = scoring.anomaly_scores(events)
    exfil = next(e for e in events if e["event_type"] == "large_outbound")
    assert s[exfil["id"]] > 0.7


def test_api_flow():
    r = client.post("/incidents", json={"seed": 11})
    assert r.status_code == 201
    iid = r.json()["id"]
    tl = client.get(f"/incidents/{iid}/timeline").json()
    assert tl["suspect_ip"] == simulator.ATTACKER_IP
    assert [t["stage"] for t in tl["timeline"]] == simulator.TRUE_STAGES
    assert client.get(f"/incidents/{iid}/attack-path").json()["edges"]
    body = {"suspect_ip": tl["suspect_ip"], "compromised_user": tl["compromised_user"],
            "stages": [t["stage"] for t in tl["timeline"]]}
    assert client.post(f"/incidents/{iid}/score", json=body).json()["total"] == 100
    assert client.get("/incidents/9999/events").status_code == 404
