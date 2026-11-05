"""Analyst scoring + ML anomaly flagging."""
import numpy as np
from sklearn.ensemble import IsolationForest


def score_submission(truth, sub):
    """100 points: suspect IP 40, compromised user 30, stage ordering 30."""
    ip_pts = 40 if sub.get("suspect_ip") == truth["suspect_ip"] else 0
    user_pts = 30 if sub.get("compromised_user") == truth["compromised_user"] else 0
    given, want = sub.get("stages", []), truth["stages"]
    right = sum(1 for i, s in enumerate(want) if i < len(given) and given[i] == s)
    order_pts = round(30 * right / len(want))
    return {"total": ip_pts + user_pts + order_pts,
            "breakdown": {"suspect_ip": ip_pts, "compromised_user": user_pts, "stage_order": order_pts},
            "correct": truth}


def _features(e):
    hour = int(e["ts"][11:13])
    return [hour, e["severity"], np.log1p(e["bytes"]), int(e["event_type"] == "login_failed")]


def anomaly_scores(events, contamination=0.08, seed=0):
    """Return {event_id: score in [0,1]} (1 = most anomalous)."""
    if len(events) < 10:
        return {e["id"]: 0.0 for e in events}
    X = np.array([_features(e) for e in events])
    model = IsolationForest(contamination=contamination, random_state=seed).fit(X)
    raw = -model.score_samples(X)
    norm = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    return {e["id"]: round(float(s), 3) for e, s in zip(events, norm)}
