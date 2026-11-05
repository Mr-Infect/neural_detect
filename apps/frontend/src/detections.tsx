import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "./api";

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
type ApprovalRow = {
  id: string; status: string; rule_version: number; current_version: number;
  requested_by: string; reviewer: string | null; decision_note: string | null; expires_at: string;
};
type TestCase = { name: string; expected_detection: boolean; detected: boolean; passed: boolean };
type TestResult = { passed: boolean; cases: TestCase[]; failures: string[] };

const FIXTURE_TEMPLATE = JSON.stringify({
  positive: [{ name: "should-alert", events: [{ process: { name: "example.exe" } }] }],
  negative: [{ name: "should-stay-quiet", events: [{ process: { name: "notepad.exe" } }] }],
}, null, 2);

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(url, {
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
  const [approvals, setApprovals] = useState<ApprovalRow[]>([]);
  const [fixtures, setFixtures] = useState(FIXTURE_TEMPLATE);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [note, setNote] = useState("");
  const [me, setMe] = useState("operator");
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
  useEffect(() => {
    void request<{ email: string }>("/api/v1/auth/me").then((user) => setMe(user.email)).catch(() => undefined);
  }, []);
  async function loadApprovals(id: string) {
    try { setApprovals(await request<ApprovalRow[]>("/api/v1/detections/" + id + "/approvals")); } catch { setApprovals([]); }
  }
  useEffect(() => {
    setTestResult(null); setFixtures(FIXTURE_TEMPLATE); setNote("");
    if (selectedId) void loadApprovals(selectedId); else setApprovals([]);
  }, [selectedId]);

  async function runTests() {
    if (!selected) return;
    let body: unknown;
    try { body = JSON.parse(fixtures); } catch { setError("Fixtures must be valid JSON."); return; }
    try {
      setTestResult(await request<TestResult>("/api/v1/detections/" + selected.id + "/test", { method: "POST", body: JSON.stringify(body) }));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Fixture test failed.");
    }
  }
  async function requestApproval() {
    if (!selected) return;
    try {
      await request<ApprovalRow>("/api/v1/detections/" + selected.id + "/approvals", { method: "POST", body: JSON.stringify({ requested_by: me }) });
      setResult("Approval requested. A different approver must review it before deployment.");
      setError("");
      await loadApprovals(selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Approval request failed.");
    }
  }
  async function review(approval: ApprovalRow, decision: "approved" | "rejected") {
    if (decision === "rejected" && !note.trim()) { setError("Enter a reason before rejecting."); return; }
    try {
      await request<Record<string, unknown>>("/api/v1/detections/approvals/" + approval.id + "/review", {
        method: "POST", body: JSON.stringify({ decision, note: note.trim() || null }),
      });
      setResult("Approval " + approval.id.slice(0, 8) + " " + decision + ".");
      setError(""); setNote("");
      if (selected) await loadApprovals(selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Review failed.");
    }
  }
  async function deploy(approval: ApprovalRow) {
    if (!selected) return;
    try {
      await request<Record<string, unknown>>("/api/v1/detections/" + selected.id + "/deploy?approval_id=" + approval.id, { method: "POST" });
      setResult("Deployed " + selected.title + " to Kibana. Open Security → Rules in Kibana to see it enabled.");
      setError("");
      await loadApprovals(selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Deployment failed.");
    }
  }

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
            <button className={selectedId === rule.id ? "rule-item selected" : "rule-item"} onClick={() => { setSelectedId(rule.id); setResult(""); }}>
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
            <button className="button approval" onClick={() => void requestApproval()}>Request deployment approval</button>
          </div>
          <div className="workflow-panel">
            <div className="code-title">1 · TEST WITH FIXTURES</div>
            <p className="workflow-hint">Events under "positive" must alert; events under "negative" must stay quiet. They run against a throwaway Elasticsearch index.</p>
            <textarea aria-label="Fixture JSON" value={fixtures} onChange={(event) => setFixtures(event.target.value)} />
            <button className="button" onClick={() => void runTests()}>Run fixture tests</button>
            {testResult && <div className={testResult.passed ? "test-result pass" : "test-result fail"} role="status">
              <b>{testResult.passed ? "ALL TESTS PASSED" : "TESTS FAILED"}</b>
              {testResult.cases.map((item) => <div className="test-case" key={item.name}>
                <span className={item.passed ? "ok" : "bad"}>{item.passed ? "PASS" : "FAIL"}</span>
                <span>{item.name}</span>
                <small>{item.expected_detection ? "should alert" : "should stay quiet"} · {item.detected ? "alerted" : "stayed quiet"}</small>
              </div>)}
            </div>}
          </div>
          <div className="workflow-panel">
            <div className="code-title">2 · APPROVE AND DEPLOY</div>
            <p className="workflow-hint">A different person must approve. Deploy only works with an approved request for the current version.</p>
            <input aria-label="Review note" className="note-input" placeholder="Reviewer note (required to reject)" value={note} onChange={(event) => setNote(event.target.value)} />
            {!approvals.length ? <p className="empty">No approval requests yet. Use “Request deployment approval” above.</p> :
              approvals.map((item) => <div className="approval-row" key={item.id}>
                <div className="approval-info">
                  <b className={"approval-status " + item.status}>{item.status.toUpperCase()}</b>
                  <small>{item.id.slice(0, 8)} · v{item.rule_version} · requested by {item.requested_by}{item.reviewer ? " · reviewed by " + item.reviewer : ""}</small>
                  <small>expires {new Date(item.expires_at).toLocaleString()}</small>
                </div>
                <div className="approval-actions">
                  {item.status === "pending" && <>
                    <button className="button" onClick={() => void review(item, "approved")}>Approve</button>
                    <button className="button secondary" onClick={() => void review(item, "rejected")}>Reject</button>
                  </>}
                  {item.status === "approved" && item.rule_version === item.current_version && <button className="button approval" onClick={() => void deploy(item)}>Deploy to Kibana</button>}
                  {item.status === "approved" && item.rule_version !== item.current_version && <small>Rule changed after approval</small>}
                </div>
              </div>)}
          </div>
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