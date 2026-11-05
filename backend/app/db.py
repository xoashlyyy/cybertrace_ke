import os

from sqlalchemy import JSON, Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cybertrace.db")
kwargs = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
if DATABASE_URL.endswith(":memory:"):
    kwargs["poolclass"] = StaticPool
engine = create_engine(DATABASE_URL, **kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    seed = Column(Integer)
    truth = Column(JSON)          # hidden from API consumers until scored
    events = relationship("EventRow", cascade="all, delete-orphan")


class EventRow(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    ts = Column(String, index=True)
    source = Column(String)
    data = Column(JSON)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
