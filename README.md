# CyberTrace KE: Cybersecurity Incident Investigation Platform

A controlled lab that generates **simulated** security incidents, correlates authentication, application,
database and network events into an attack timeline, draws the attack path, flags anomalous events with
machine learning, and scores an analyst's findings against the known ground truth.

> **Safety note:** all data is simulated and uses documentation-reserved IP ranges (203.0.113.0/24,
> 198.51.100.0/24). The platform only *analyzes* events. It contains no scanning, exploitation or
> brute-force tooling and never touches real systems.

## The scenario

A simulated attacker scans the app server, brute-forces a staff account (18 to 40 failed logins), logs in,
reaches an admin export page, bulk-reads the customer table, and uploads ~18 MB to an external host.
60 to 90 benign events (normal logins, typos, page views) are mixed in, so the analyst has to correlate
rather than just read.

## Features

| Feature | How it works | Code |
|---|---|---|
| Incident simulator | Seeded and deterministic, so incidents are reproducible | `backend/app/simulator.py` |
| Cross-source correlation | Finds suspect IPs by evidence score, pivots on the compromised account, maps events to kill-chain stages | `backend/app/correlate.py` |
| Attack-path graph | Nodes and edges derived from the stages actually observed | `correlate.attack_path` |
| Anomaly detection | Isolation Forest over hour, severity, log(bytes), failed-login flag | `backend/app/scoring.py` |
| Analyst scoring | 100 points: suspect IP 40, compromised account 30, stage order 30 | `scoring.score_submission` |
| REST API | FastAPI with auto docs | `backend/app/main.py` |
| Dashboard | React: attack path, timeline, evidence table, scoring form | `frontend/src/` |

## Architecture

```
React dashboard  --/api-->  FastAPI  --> correlate.py  (timeline, attack path)
 (Vite, :5173)              (:8000)  --> scoring.py    (Isolation Forest, scoring)
                               |     --> simulator.py  (incident + hidden ground truth)
                               v
                          PostgreSQL (SQLite when run locally without DATABASE_URL)
```

The ground truth is stored server-side and only revealed in the response to a score submission, so the
exercise cannot be solved by reading the API.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/incidents` | Create a simulated incident. Body: `{"seed": 42}` (optional) |
| GET | `/incidents` | List incidents |
| GET | `/incidents/{id}/events?source=auth` | Events with anomaly score, optional filter |
| GET | `/incidents/{id}/timeline` | Correlated stages, suspect IP, compromised user |
| GET | `/incidents/{id}/attack-path` | Graph nodes and edges |
| POST | `/incidents/{id}/score` | Submit `suspect_ip`, `compromised_user`, ordered `stages` |

Interactive docs: http://localhost:8000/docs

## Quick start

### Option 1: Docker

```bash
docker compose up --build
# dashboard: http://localhost:5173    API docs: http://localhost:8000/docs
```

### Option 2: local

```bash
# terminal 1: backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# terminal 2: frontend (Node 20+)
cd frontend
npm install
npm run dev        # http://localhost:5173
```

## Tests

```bash
cd backend && python -m pytest -q
```

5 tests: simulator determinism, correlation recovers the ground truth, scoring (perfect and zero),
the exfiltration event gets a high anomaly score, and the full API flow including a 404 case.
The correlation was additionally checked against 20 different random seeds.

## Verified

- Backend run against a real PostgreSQL 16 database with `uvicorn`: every endpoint exercised, 107 events stored, 404 handling and CORS preflight confirmed.
- Dashboard driven in headless Chromium through the Vite dev proxy: create incident, 6-stage timeline, 4-node graph, evidence filter, and scoring (100/100 for the correct answer, 90/100 after swapping two stages). No JavaScript errors. Light and dark themes both checked.
- A graph bug found this way was fixed: arrowheads were hidden under the boxes and two labels overlapped.
- Docker was not available in the build environment, so `docker compose up` itself was not run (Dockerfiles pass hadolint, compose parses).

## Design decisions worth knowing

- **Evidence score for suspects** (failed logins plus a large bonus for scanning): a first version used a bare
  threshold and wrongly picked an office IP that happened to mistype a password several times.
- **Pivoting on the compromised user only for severity 3+ events:** otherwise the victim's own normal
  activity after the breach pollutes the attack story. Real tools solve this with session IDs; adding a
  `session_id` field to events is a good extension.
- **Unsupervised anomaly detection** is a triage aid, not a verdict. It ranks events; the analyst decides.
- **Ground truth never leaves the server** until the analyst submits findings.

## Limitations and next steps

- One scenario. Add more (phishing then lateral movement, SQL injection, insider data theft).
- Add MITRE ATT&CK technique IDs next to each stage.
- Import real log formats (syslog, nginx, auth.log) through a parser layer.
- Add authentication and per-analyst leaderboards.

## Be ready to explain (interview prep)

1. Walk me through how you decided which IP was the attacker.
2. Why does Isolation Forest suit this problem, and what are its false-positive risks?
3. What is the difference between a SIEM correlation rule and what this does?
4. How would you prevent a defender tool like this from being misused?
