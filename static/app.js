// No innerHTML anywhere: all content is inserted as text, so analysed text cannot inject markup.
const $ = id => document.getElementById(id);
let busy = false;
async function call(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: {"Content-Type": "application/json", "X-API-Key": $("key").value}});
  if (!r.ok) {
    const map = {401: "That API key was not accepted.", 403: "This key's role cannot do that.", 413: "Input is too large.",
                 422: "Check the input: it must be 1 to 20,000 characters.", 429: "Too many requests. Wait a minute and try again."};
    throw new Error(map[r.status] || "Something went wrong. Try again.");
  }
  return r.json();
}
function highlight(text, findings) {
  const cp = Array.from(text), pre = $("orig"); pre.textContent = "";
  let pos = 0;
  for (const f of findings) {
    pre.append(cp.slice(pos, f.start).join(""));
    const m = document.createElement("mark"); m.textContent = cp.slice(f.start, f.end).join("");
    m.title = f.category; pre.append(m); pos = f.end;
  }
  pre.append(cp.slice(pos).join(""));
  if (findings.length) { const s = document.createElement("div"); s.className = "small";
    s.textContent = "Found: " + [...new Set(findings.map(f => f.category))].join(", "); pre.append(s); }
}
$("go").onclick = async () => {
  if (busy) return; busy = true; $("msg").textContent = "";
  try {
    const text = $("text").value;
    const d = await call("/v1/inspect", {method: "POST", body: JSON.stringify({text, destination: $("dest").value})});
    $("result").hidden = false;
    const b = $("badge"); b.textContent = d.action.replace("_", " "); b.className = "badge " + d.action;
    $("reasons").textContent = d.reasons.join(". ") || "No sensitive content found.";
    highlight(text, d.findings);
    $("san").textContent = d.sanitized_text ?? "Nothing was sent.";
    $("ai").textContent = d.ai_response ?? "";
    $("meta").textContent = `Event ${d.event_id} · ${d.latency_ms} ms`;
    loadAudit();
  } catch (e) { $("msg").textContent = e.message; } finally { busy = false; }
};
async function loadAudit() {
  try {
    const [ev, m] = await Promise.all([call("/v1/events"), call("/v1/metrics")]);
    $("metrics").textContent = `${m.total} events, average ${m.avg_latency_ms} ms. ` +
      Object.entries(m.actions).map(([k, v]) => `${k}: ${v}`).join(", ");
    const tb = document.querySelector("#events tbody"); tb.textContent = "";
    for (const e of ev) {
      const tr = tb.insertRow();
      [e.timestamp.replace("T", " ").slice(0, 19), e.event_id.slice(0, 8), e.role, e.destination, e.categories.join(", ") || "none", e.action, e.latency_ms]
        .forEach(v => { tr.insertCell().textContent = v; });
    }
  } catch (e) { $("metrics").textContent = e.message; }
}
$("refresh").onclick = loadAudit;
