import { useEffect, useState } from "react";
import { api } from "./api.js";

const STAGES = ["reconnaissance", "credential_access", "initial_access", "privilege_escalation", "collection", "exfiltration"];
const STAGE_NAME = (s) => s.replace("_", " ");
const SOURCE_COLOR = { auth: "#0E5A62", app: "#6B4C9A", db: "#B4580F", network: "#B4243B" };
const NODE_POS = { attacker: [100, 115], app: [350, 55], account: [350, 175], db: [590, 175] };
const HALF_W = 62, HALF_H = 20;

// point where the line from centre `a` toward centre `b` leaves a's box, so arrows stay visible
function edgePoint(a, b) {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const t = Math.min(dx ? HALF_W / Math.abs(dx) : Infinity, dy ? HALF_H / Math.abs(dy) : Infinity);
  return [a[0] + dx * t, a[1] + dy * t];
}

function AttackPath({ graph }) {
  if (!graph.nodes.length) return <p className="empty">No attack path found. Create or select an incident.</p>;
  return (
    <svg viewBox="0 0 700 235" role="img" aria-label="Attack path graph" className="graph">
      <defs>
        {[["arrow", "currentColor"], ["arrow-red", "var(--alert)"]].map(([id, fill]) => (
          <marker key={id} id={id} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" fill={fill} />
          </marker>
        ))}
      </defs>
      {graph.edges.map((e, i) => {
        const a = NODE_POS[e.from], b = NODE_POS[e.to];
        const dx = b[0] - a[0], dy = b[1] - a[1], len = Math.hypot(dx, dy);
        const flip = e.from > e.to ? -1 : 1;               // same normal for A->B and B->A, so paired edges separate
        const nx = (-dy / len) * flip, ny = (dx / len) * flip;
        // two edges join attacker and app (inbound attack, outbound exfiltration): draw them apart
        const side = e.label === "exfiltration" ? 1 : e.label === "scan + brute force" ? -1 : 0;
        const off = side * 9;
        const [sx, sy] = edgePoint(a, b), [ex, ey] = edgePoint(b, a);
        const lx = (sx + ex) / 2 + nx * side * 22;
        const ly = (sy + ey) / 2 + (side ? ny * side * 22 : -9);
        const exfil = e.label === "exfiltration";
        return (
          <g key={i}>
            <line x1={sx + nx * off} y1={sy + ny * off} x2={ex + nx * off} y2={ey + ny * off}
              stroke={exfil ? "var(--alert)" : "currentColor"} strokeWidth="2" markerEnd={exfil ? "url(#arrow-red)" : "url(#arrow)"}
              strokeDasharray={exfil ? "6 4" : "0"} />
            <text x={lx} y={ly} textAnchor="middle" fontSize="12" className="edge-label"
              fill={exfil ? "var(--alert)" : "currentColor"}>{e.label}</text>
          </g>
        );
      })}
      {graph.nodes.map((n) => {
        const [x, y] = NODE_POS[n.id];
        return (
          <g key={n.id}>
            <rect x={x - 62} y={y - 20} width="124" height="40" rx="4" className={`node ${n.kind}`} />
            <text x={x} y={y + 5} textAnchor="middle" fontSize="13" fontWeight="500" className={n.kind === "internal" ? "label-internal" : "label"}>{n.label}</text>
          </g>
        );
      })}
    </svg>
  );
}

function Timeline({ data }) {
  if (!data.timeline.length) return <p className="empty">No correlated activity yet.</p>;
  return (
    <ol className="timeline">
      {data.timeline.map((t, i) => (
        <li key={i}>
          <div className="stage">{STAGE_NAME(t.stage)}</div>
          <div className="time">{t.first_ts.slice(11, 19)} UTC{t.count > 1 ? `, ${t.count} events` : ""}</div>
          <div className="detail">{t.detail}</div>
          <span className="tag" style={{ background: SOURCE_COLOR[t.source] }}>{t.source}</span>
        </li>
      ))}
    </ol>
  );
}

function EventTable({ events, source, setSource }) {
  const sources = ["all", "auth", "app", "db", "network"];
  const top = [...events].sort((a, b) => b.anomaly - a.anomaly).slice(0, 25);
  return (
    <>
      <div className="filters" role="group" aria-label="Filter by source">
        {sources.map((s) => (
          <button key={s} className={source === s ? "chip on" : "chip"} onClick={() => setSource(s)}>{s}</button>
        ))}
      </div>
      <div className="scroll">
        <table>
          <thead><tr><th>Time</th><th>Source</th><th>Event</th><th>From</th><th>User</th><th>Anomaly</th></tr></thead>
          <tbody>
            {top.map((e) => (
              <tr key={e.id}>
                <td>{e.ts.slice(11, 19)}</td>
                <td><span className="tag" style={{ background: SOURCE_COLOR[e.source] }}>{e.source}</span></td>
                <td>{e.event_type}</td><td>{e.src_ip}</td><td>{e.user || "-"}</td>
                <td><div className="bar"><div style={{ width: `${e.anomaly * 100}%` }} /></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="note">Showing the 25 most anomalous events (Isolation Forest score).</p>
    </>
  );
}

function ScoreForm({ incidentId, defaults }) {
  const [ip, setIp] = useState("");
  const [user, setUser] = useState("");
  const [order, setOrder] = useState(STAGES.slice());
  const [result, setResult] = useState(null);
  const move = (i, d) => {
    const next = order.slice();
    [next[i], next[i + d]] = [next[i + d], next[i]];
    setOrder(next);
  };
  const submit = async () => setResult(await api.score(incidentId, { suspect_ip: ip, compromised_user: user, stages: order }));
  const fillFromTool = () => { setIp(defaults.suspect_ip || ""); setUser(defaults.compromised_user || ""); setOrder(defaults.timeline.map((t) => t.stage)); };
  return (
    <div className="score">
      <label>Suspect IP<input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 203.0.113.50" /></label>
      <label>Compromised account<input value={user} onChange={(e) => setUser(e.target.value)} placeholder="username" /></label>
      <fieldset>
        <legend>Order the attack stages</legend>
        {order.map((s, i) => (
          <div key={s} className="row">
            <span>{STAGE_NAME(s)}</span>
            <span>
              <button disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Move ${s} up`}>Up</button>
              <button disabled={i === order.length - 1} onClick={() => move(i, 1)} aria-label={`Move ${s} down`}>Down</button>
            </span>
          </div>
        ))}
      </fieldset>
      <div className="actions">
        <button className="primary" onClick={submit}>Submit findings</button>
        <button onClick={fillFromTool}>Use correlation result</button>
      </div>
      {result && (
        <div className="result">
          <strong>{result.total} / 100</strong>
          <span>IP {result.breakdown.suspect_ip}/40, account {result.breakdown.compromised_user}/30, order {result.breakdown.stage_order}/30</span>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [current, setCurrent] = useState(null);
  const [timeline, setTimeline] = useState({ timeline: [] });
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [events, setEvents] = useState([]);
  const [source, setSource] = useState("all");
  const [error, setError] = useState("");

  const refresh = () => api.list().then(setIncidents).catch((e) => setError(e.message));
  useEffect(() => { refresh(); }, []);

  useEffect(() => {
    if (!current) return;
    Promise.all([api.timeline(current), api.path(current), api.events(current)])
      .then(([t, g, e]) => { setTimeline(t); setGraph(g); setEvents(e); setError(""); })
      .catch((e) => setError(e.message));
  }, [current]);

  const create = async () => {
    try {
      const r = await api.create(Math.floor(Math.random() * 10000));
      await refresh();
      setCurrent(r.id);
    } catch (e) { setError(e.message); }
  };

  const shown = source === "all" ? events : events.filter((e) => e.source === source);

  return (
    <div className="app">
      <aside>
        <h1>CyberTrace KE</h1>
        <p className="lede">Investigate a simulated breach. Correlate four log sources into one attack story.</p>
        <button className="primary" onClick={create}>New simulated incident</button>
        <ul className="incidents">
          {incidents.map((i) => (
            <li key={i.id}>
              <button className={current === i.id ? "inc on" : "inc"} onClick={() => setCurrent(i.id)}>
                Incident {i.id}<small>{i.event_count} events</small>
              </button>
            </li>
          ))}
        </ul>
        {error && <p className="error" role="alert">{error}. Is the backend running on port 8000?</p>}
      </aside>
      <main>
        {!current ? (
          <p className="empty big">Create an incident to begin your investigation.</p>
        ) : (
          <>
            <section><h2>Attack path</h2><AttackPath graph={graph} /></section>
            <section className="two">
              <div><h2>Incident timeline</h2><Timeline data={timeline} /></div>
              <div><h2>Your findings</h2><ScoreForm key={current} incidentId={current} defaults={timeline} /></div>
            </section>
            <section><h2>Evidence</h2><EventTable events={shown} source={source} setSource={setSource} /></section>
          </>
        )}
      </main>
    </div>
  );
}
