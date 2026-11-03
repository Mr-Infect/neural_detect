import { useEffect, useMemo, useState } from "react";

type Detection = {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  format: string;
  source_yaml: string | null;
  compiled_query: string | Record<string, unknown> | null;
  metadata: Record<string, unknown>;
  version: number;
};
type Approval = { id: string; status: string; expires_at: string };

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? "Request failed: " + response.status);
  }
  return response.json() as Promise<T>;
}

export function DetectionsPage() {
  const [rules, setRules] = useState<Detection[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [approval, setApproval] = useState<Approval | null>(null);
  const [loading, setLoading] = useState(true);

  const selected = useMemo(() => rules.find((rule) => rule.id === selectedId) ?? null, [rules, selectedId]);
  async function reload() {
    setLoading(true);
    try {
      const data = await request<Detection[]>("/api/v1/detections");
      setRules(data);
      if (!selectedId && data.length) setSelectedId(data[0].id);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load detections.");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { void reload(); }, []);

  async function importRule() {
    try {
      const created = await request<Detection>("/api/v1/detections", {
        method: "POST", body: JSON.stringify({ source_yaml: source }),
      });
      setSource("");
      setSelectedId(created.id);
      setResult("Imported " + created.title + " at version " + created.version + ".");
      await reload();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Import failed.");
    }
  }
  async function action(path: string, label: string, body?: unknown) {
    if (!selected) return;
    try {
      const value = await request<Record<string, unknown>>("/api/v1/detections/" + selected.id + "/" + path, {
        method: "POST", body: JSON.stringify(body ?? {}),
      });
      setResult(label + ": " + JSON.stringify(value, null, 2));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : label + " failed.");
    }
  }

  return <main className="detection-page">
    <header className="detection-header">
      <div>
        <p className="eyebrow">DETECTION AS CODE · PHASE 3</p>
        <h1>Detection library</h1>
        <p className="detection-subtitle">Versioned Sigma and Elastic rules, compiled and tested against telemetry.</p>
      </div>
      <a className="button secondary" href="/">Back to overview</a>
    </header>
    {error && <div className="error" role="alert"><b>Detection request failed</b><span>{error}</span></div>}
    <section className="detection-grid">
      <article className="panel rule-library">
        <div className="panel-head"><div><p className="eyebrow">RULES</p><h3>Detection library</h3></div><span className="source-count">{rules.length} RULES</span></div>
        {loading ? <p className="empty">Loading stored detections…</p> : !rules.length ? <p className="empty">No rules stored. Import a Sigma YAML rule to begin.</p> :
          <ul>{rules.map((rule) => <li key={rule.id}>
            <button className={selectedId === rule.id ? "rule-item selected" : "rule-item"} onClick={() => { setSelectedId(rule.id); setResult(""); setApproval(null); }}>
              <span className="rule-format">{rule.format.toUpperCase()}</span>
              <span className="rule-copy"><b>{rule.title}</b><small>{rule.rule_id} · v{rule.version}</small></span>
              <span className="severity">{String(rule.metadata.level ?? rule.metadata.severity ?? "medium").toUpperCase()}</span>
            </button>
          </li>)}</ul>}
      </article>
      <article className="panel rule-detail">
        {!selected ? <p className="empty">Select a detection to inspect its source and compiled form.</p> : <>
          <div className="panel-head"><div><p className="eyebrow">{selected.format.toUpperCase()} · VERSION {selected.version}</p><h2>{selected.title}</h2></div><span className="live-dot">STORED</span></div>
          <p className="rule-description">{selected.description}</p>
          <div className="attack-tags">{(Array.isArray(selected.metadata.tags) ? selected.metadata.tags as string[] : []).map((tag) => <span key={tag}>{tag}</span>)}</div>
          <div className="action-row">
            <button className="button" onClick={() => void action("validate", "Validation")}>Validate</button>
            <button className="button secondary" onClick={() => void action("compile", "Compilation")}>Compile</button>
            {selected.source_yaml && <button className="button secondary" onClick={() => { window.location.href = "/api/v1/detections/" + selected.id + "/export"; }}>Export Sigma</button>}
            <button className="button approval" onClick={async () => {
              try {
                const value = await request<Approval>("/api/v1/detections/" + selected.id + "/approvals", { method: "POST", body: JSON.stringify({ requested_by: "operator" }) });
                setApproval(value);
                setResult("Approval requested. Deployment stays disabled until a trusted reviewer approves request " + value.id + ".");
                setError("");
              } catch (reason) {
                setError(reason instanceof Error ? reason.message : "Approval request failed.");
              }
            }}>Request deployment approval</button>
          </div>
          {approval && <div className="approval-state">Approval {approval.id.slice(0, 8)} · {approval.status} · expires {new Date(approval.expires_at).toLocaleString()}</div>}
          <div className="code-panel"><div className="code-title">ORIGINAL SIGMA SOURCE</div><pre>{selected.source_yaml ?? "Native Elastic rule — no Sigma source."}</pre></div>
          <div className="code-panel"><div className="code-title">GENERATED QUERY</div><pre>{typeof selected.compiled_query === "string" ? selected.compiled_query : JSON.stringify(selected.compiled_query, null, 2)}</pre></div>
        </>}
        {result && <pre className="operation-result">{result}</pre>}
      </article>
    </section>
    <section className="panel import-panel">
      <div className="panel-head"><div><p className="eyebrow">IMPORT</p><h3>Add Sigma rule</h3></div><span className="source-count">YAML · VALIDATED · VERSIONED</span></div>
      <label htmlFor="sigma-source">Paste one Sigma YAML document</label>
      <textarea id="sigma-source" value={source} onChange={(event) => setSource(event.target.value)} placeholder={"title: Example detection\nid: 82e8fa6d-3c6d-4c11-a480-9f98d30ac6e0\nstatus: experimental\n..."} />
      <button className="button" disabled={!source.trim()} onClick={() => void importRule()}>Validate and import</button>
    </section>
    <footer>Detection as Code Engine · Deployment requires a separate reviewer approval.</footer>
  </main>;
}