const json = async (res) => {
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res.json();
};
const post = (url, body) =>
  fetch(`/api${url}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);
const get = (url) => fetch(`/api${url}`).then(json);

export const api = {
  create: (seed) => post("/incidents", { seed }),
  list: () => get("/incidents"),
  events: (id) => get(`/incidents/${id}/events`),
  timeline: (id) => get(`/incidents/${id}/timeline`),
  path: (id) => get(`/incidents/${id}/attack-path`),
  score: (id, body) => post(`/incidents/${id}/score`, body),
};
