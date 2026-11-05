from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import correlate, scoring, simulator
from .db import Base, EventRow, Incident, engine, get_db

Base.metadata.create_all(engine)
app = FastAPI(title="CyberTrace KE", version="1.0.0",
              description="Controlled cyber-incident investigation lab (simulated data only).")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])


class NewIncident(BaseModel):
    seed: int | None = None


class Submission(BaseModel):
    suspect_ip: str | None = None
    compromised_user: str | None = None
    stages: list[str] = []


def _incident(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


def _events(inc: Incident):
    return [r.data for r in sorted(inc.events, key=lambda r: r.ts)]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/incidents", status_code=201)
def create_incident(body: NewIncident, db: Session = Depends(get_db)):
    events, truth = simulator.generate_incident(body.seed)
    inc = Incident(seed=body.seed, truth=truth)
    inc.events = [EventRow(ts=e["ts"], source=e["source"], data=e) for e in events]
    db.add(inc)
    db.commit()
    return {"id": inc.id, "event_count": len(events)}


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    return [{"id": i.id, "event_count": len(i.events)} for i in db.query(Incident).all()]


@app.get("/incidents/{incident_id}/events")
def get_events(incident_id: int, source: str | None = None, db: Session = Depends(get_db)):
    events = _events(_incident(db, incident_id))
    scores = scoring.anomaly_scores(events)
    out = [dict(e, anomaly=scores[e["id"]]) for e in events]
    return [e for e in out if source is None or e["source"] == source]


@app.get("/incidents/{incident_id}/timeline")
def get_timeline(incident_id: int, db: Session = Depends(get_db)):
    r = correlate.reconstruct(_events(_incident(db, incident_id)))
    return {"suspect_ip": r["suspect_ip"], "compromised_user": r["compromised_user"],
            "timeline": r["timeline"]}


@app.get("/incidents/{incident_id}/attack-path")
def get_attack_path(incident_id: int, db: Session = Depends(get_db)):
    return correlate.attack_path(correlate.reconstruct(_events(_incident(db, incident_id))))


@app.post("/incidents/{incident_id}/score")
def score(incident_id: int, sub: Submission, db: Session = Depends(get_db)):
    inc = _incident(db, incident_id)
    return scoring.score_submission(inc.truth, sub.model_dump())
