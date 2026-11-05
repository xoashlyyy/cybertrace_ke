"""Correlate events from auth/app/db/network sources into one attack story."""
from collections import Counter
from .simulator import STAGE_OF

BRUTE_FORCE_THRESHOLD = 10


def find_suspect_ips(events):
    """IPs showing scanning or repeated auth failures, strongest evidence first.

    Evidence score = failed logins + 50 per port-scan event cluster, so an IP that
    both scans and brute-forces outranks one with a few ordinary typos.
    """
    failed = Counter(e["src_ip"] for e in events if e["event_type"] == "login_failed")
    scans = Counter(e["src_ip"] for e in events if e["event_type"] == "port_scan")
    score = {}
    for ip in set(failed) | set(scans):
        if failed[ip] >= BRUTE_FORCE_THRESHOLD or scans[ip] > 0:
            score[ip] = failed[ip] + (50 if scans[ip] else 0)
    return sorted(score, key=score.get, reverse=True)


def compromised_user(events, ip):
    for e in events:
        if e["event_type"] == "login_success" and e["src_ip"] == ip:
            return e["user"], e["ts"]
    return None, None


def reconstruct(events):
    """Return {suspect_ip, compromised_user, timeline, stages}."""
    suspects = find_suspect_ips(events)
    if not suspects:
        return {"suspect_ip": None, "compromised_user": None, "timeline": [], "stages": []}
    ip = suspects[0]
    user, t_login = compromised_user(events, ip)
    related = []
    for e in events:
        touches_ip = e["src_ip"] == ip or e["dst_ip"] == ip
        # pivot on the compromised account, but only for elevated-severity events;
        # routine activity by the same user would otherwise pollute the story
        user_after = (user and e["user"] == user and t_login and e["ts"] >= t_login
                      and e["severity"] >= 3)
        if touches_ip or user_after:
            related.append(e)
    related.sort(key=lambda e: e["ts"])

    timeline, seen = [], []
    for e in related:
        stage = STAGE_OF.get(e["event_type"])
        if stage is None:
            continue
        if timeline and timeline[-1]["stage"] == stage:
            timeline[-1]["count"] += 1
            timeline[-1]["last_ts"] = e["ts"]
            timeline[-1]["event_ids"].append(e["id"])
            continue
        timeline.append({"stage": stage, "first_ts": e["ts"], "last_ts": e["ts"], "count": 1,
                         "source": e["source"], "detail": e["detail"], "event_ids": [e["id"]]})
        if stage not in seen:
            seen.append(stage)
    return {"suspect_ip": ip, "compromised_user": user, "timeline": timeline, "stages": seen}


def attack_path(recon):
    """Graph nodes/edges for the dashboard's attack-path visual."""
    if not recon["suspect_ip"]:
        return {"nodes": [], "edges": []}
    nodes = [
        {"id": "attacker", "label": recon["suspect_ip"], "kind": "external"},
        {"id": "app", "label": "App server", "kind": "internal"},
        {"id": "account", "label": f"user: {recon['compromised_user']}", "kind": "identity"},
        {"id": "db", "label": "Customer DB", "kind": "internal"},
    ]
    edges = [
        {"from": "attacker", "to": "app", "label": "scan + brute force"},
        {"from": "app", "to": "account", "label": "login"},
        {"from": "account", "to": "db", "label": "bulk SELECT"},
        {"from": "app", "to": "attacker", "label": "exfiltration"},
    ]
    present = {t["stage"] for t in recon["timeline"]}
    if "collection" not in present:
        edges = [e for e in edges if e["to"] != "db"]
    if "exfiltration" not in present:
        edges = [e for e in edges if e["label"] != "exfiltration"]
    return {"nodes": nodes, "edges": edges}
