import { useEffect, useState } from "react";
import { apiFetch } from "./api";

type Props={mode:"hunting"|"investigations"};
type Alert={id:string;title:string;severity:string;timestamp?:string;host?:string;status:string;incident_id?:string|null};
type RecordData={incident:Record<string,any>;investigations?:Record<string,any>[];notes?:Record<string,any>[];audit_history?:Record<string,any>[]};
const api=async(path:string,init?:RequestInit)=>{const r=await apiFetch(path,{...init,headers:{"Content-Type":"application/json",...(init?.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||"Request failed with HTTP "+r.status);return d};
export function SocAgentsPage({mode}:Props){
 const [tab,setTab]=useState(mode),[alerts,setAlerts]=useState<Alert[]>([]),[incidents,setIncidents]=useState<Record<string,any>[]>([]);
 const [selected,setSelected]=useState<RecordData|null>(null),[selectedId,setSelectedId]=useState("");
 const [request,setRequest]=useState("Find failed authentication events for user accounts in the last day");
 const [hours,setHours]=useState(24),[result,setResult]=useState<any>(null),[note,setNote]=useState("");
 const [busy,setBusy]=useState(false),[error,setError]=useState(""),[tenant,setTenant]=useState("default");
 const refresh=async()=>{try{const [a,i]=await Promise.all([api("/api/v1/alerts?tenant_id="+encodeURIComponent(tenant)),api("/api/v1/investigations?tenant_id="+encodeURIComponent(tenant))]);setAlerts(a.items||[]);setIncidents(i.items||[])}catch(e){setError(e instanceof Error?e.message:"Could not load SOC data.")}};
 useEffect(()=>{void refresh()},[tenant]);
 const openIncident=async(id:string)=>{setSelectedId(id);setError("");try{setSelected(await api("/api/v1/investigations/"+id+"?tenant_id="+encodeURIComponent(tenant)))}catch(e){setError(e instanceof Error?e.message:"Could not load incident.")}};
 const runHunt=async()=>{setBusy(true);setError("");setResult(null);try{setResult(await api("/api/v1/hunt/query",{method:"POST",body:JSON.stringify({tenant_id:tenant,request,time_range_hours:hours})}))}catch(e){setError(e instanceof Error?e.message:"Hunt could not be completed.")}finally{setBusy(false)}};
 const runInvestigation=async(id:string)=>{setBusy(true);setError("");try{const res=await api("/api/v1/alerts/"+encodeURIComponent(id)+"/investigate",{method:"POST",body:JSON.stringify({tenant_id:tenant,alert_id:id,time_range_hours:Math.max(hours,72)})});setResult(res);await refresh();if(res.incident_id)await openIncident(res.incident_id)}catch(e){setError(e instanceof Error?e.message:"Investigation could not be completed.")}finally{setBusy(false)}};
 const updateStatus=async(status:string)=>{if(!selectedId)return;setBusy(true);try{await api("/api/v1/investigations/"+selectedId+"/status",{method:"PATCH",body:JSON.stringify({tenant_id:tenant,status,actor:"analyst",note:null})});await refresh();await openIncident(selectedId)}catch(e){setError(e instanceof Error?e.message:"Status update failed.")}finally{setBusy(false)}};
 const addNote=async()=>{if(!selectedId||!note.trim())return;setBusy(true);try{await api("/api/v1/investigations/"+selectedId+"/notes",{method:"POST",body:JSON.stringify({tenant_id:tenant,author:"analyst",note})});setNote("");await openIncident(selectedId)}catch(e){setError(e instanceof Error?e.message:"Note could not be saved.")}finally{setBusy(false)}};
 return <main className="soc-page">
  <aside className="sidebar"><div className="brand"><b>N</b><span>NEURAL<br/>DETECT</span></div><p className="section-label">SECURITY OPERATIONS</p><nav aria-label="Main navigation"><a href="/">Overview</a><a href="#detections">Detections</a><a className={tab==="hunting"?"active":""} href="#hunting">Threat hunting</a><a className={tab==="investigations"?"active":""} href="#investigations">Investigations</a><a href="#detection-agent">AI Detection Engineer</a><a href="#models">AI Models</a><a href="#settings">Settings</a></nav><div className="side-foot">LOCAL-FIRST SECURITY <span>V0.6</span></div></aside>
  <section className="soc-main"><header className="soc-header"><div><p className="eyebrow">AI SOC AGENTS · PHASE 6</p><h1>{tab==="hunting"?"Threat hunting":"Investigations & incident triage"}</h1><p className="soc-subtitle">Read-only Elastic hunts with tenant filters, evidence references and analyst audit history.</p></div><label className="tenant-picker">TENANT<input value={tenant} maxLength={128} onChange={e=>setTenant(e.target.value||"default")}/></label></header>
  {error&&<div className="error soc-error" role="alert">{error}</div>}
  <div className="soc-tabs"><button className={tab==="hunting"?"selected":""} onClick={()=>setTab("hunting")}>Threat hunt</button><button className={tab==="investigations"?"selected":""} onClick={()=>setTab("investigations")}>Alert investigations</button><button className="button secondary" onClick={()=>void refresh()}>Refresh Elastic data</button></div>
  {tab==="hunting"?<div className="soc-grid">
   <article className="panel soc-form"><div className="panel-head"><div><p className="eyebrow">NATURAL LANGUAGE</p><h2>Build a bounded hunt</h2></div><span className="live-dot">READ ONLY</span></div>
    <label>Hunt request<textarea value={request} onChange={e=>setRequest(e.target.value)} maxLength={6000}/></label>
    <label>Time range<select value={hours} onChange={e=>setHours(Number(e.target.value))}><option value={1}>Past hour</option><option value={24}>Past 24 hours</option><option value={72}>Past 3 days</option><option value={168}>Past 7 days</option><option value={720}>Past 30 days</option></select></label>
    <p className="soc-guard">Generated queries are checked before execution. Results are limited to 100 rows and only the tenant/time-filtered telemetry index.</p><button className="button" disabled={busy||request.trim().length<8} onClick={()=>void runHunt()}>{busy?"Working…":"Generate and run hunt"}</button>
    {result&&<Result data={result}/>}
   </article>
   <article className="panel"><div className="panel-head"><div><p className="eyebrow">ELASTIC SECURITY</p><h2>Recent alerts</h2></div><span className="source-count">{alerts.length} LOADED</span></div>
    {!alerts.length?<p className="empty">No alerts returned from the Elastic Security alerts index.</p>:<div className="soc-alerts">{alerts.map(a=><div className="soc-alert" key={a.id||a.title}><div><b>{a.title}</b><small>{a.severity} · {a.host||"host unavailable"} · {a.timestamp||"time unavailable"}</small></div><span className={"incident-state "+a.status}>{a.status}</span>{a.id&&<button className="button secondary" disabled={busy} onClick={()=>void runInvestigation(a.id)}>Investigate</button>}</div>)}</div>}
   </article>
  </div>:<div className="soc-grid investigation-grid">
   <article className="panel"><div className="panel-head"><div><p className="eyebrow">INCIDENT QUEUE</p><h2>Tracked investigations</h2></div><span className="source-count">{incidents.length} INCIDENTS</span></div>
    {!incidents.length?<p className="empty">No investigations yet. Start from a recent alert in Threat hunt.</p>:<div className="soc-alerts">{incidents.map(i=><button className={"incident-row "+(selectedId===i.id?"picked":"")} key={i.id} onClick={()=>void openIncident(i.id)}><span className={"severity-dot "+i.severity}/><span><b>{i.title}</b><small>{i.severity} · {i.category} · {i.status}</small></span><time>{new Date(i.updated_at||i.created_at).toLocaleString()}</time></button>)}</div>}
   </article>
   <article className="panel"><div className="panel-head"><div><p className="eyebrow">EVIDENCE & AUDIT</p><h2>{selected?.incident?.title||"Select an incident"}</h2></div>{selected?.incident&&<span className={"incident-state "+selected.incident.status}>{selected.incident.status}</span>}</div>
    {selected?<><div className="action-row">{["open","in_progress","resolved","closed"].map(s=><button key={s} className="button secondary" disabled={busy||selected.incident.status===s} onClick={()=>void updateStatus(s)}>{s.replace("_"," ")}</button>)}</div>
     <div className="soc-tags">{(selected.incident.attack_techniques||[]).map((t:string)=><span key={t}>{t}</span>)}</div>
     {(selected.investigations||[]).map((inv:any)=><div className="code-panel" key={inv.id}><div className="code-title">INVESTIGATION · {inv.status} · {inv.model_name||"model unavailable"}</div><Result data={{report:inv.report,evidence:inv.event_references}}/></div>)}
     <label className="soc-note">Analyst note<textarea value={note} onChange={e=>setNote(e.target.value)} maxLength={8000} placeholder="Record an observation or handoff…"/></label><button className="button" disabled={busy||!note.trim()} onClick={()=>void addNote()}>Add note</button>
     <h3 className="soc-subhead">Notes</h3>{!(selected.notes||[]).length?<p className="empty">No analyst notes.</p>:(selected.notes||[]).map((n:any)=><p className="timeline-item" key={n.id}><b>{n.author}</b><small>{new Date(n.created_at).toLocaleString()}</small><span>{n.note}</span></p>)}
     <h3 className="soc-subhead">Audit history</h3>{(selected.audit_history||[]).map((a:any)=><p className="timeline-item" key={a.id}><b>{a.action}</b><small>{a.actor} · {new Date(a.created_at).toLocaleString()}</small><code>{JSON.stringify(a.details)}</code></p>)}
    </>:<p className="empty">Select an incident to review model findings, event references, analyst notes and status history.</p>}
   </article>
  </div>}
  <footer>Phase 6 · AI SOC agents <span>·</span> <a href="/docs">API reference</a></footer>
 </section>
 </main>
}
function Result({data}:{data:any}){return <div className="soc-result"><div className="result-meta"><span>{data.status||data.provider||"REPORT"}</span><span>{data.result_count!==undefined?data.result_count+" EVENTS":data.model||""}</span></div>{data.query&&<pre>{data.query}</pre>}<pre>{JSON.stringify(data.report||data,null,2)}</pre>{data.evidence&&<details><summary>Evidence references · {data.evidence.length}</summary><pre>{JSON.stringify(data.evidence,null,2)}</pre></details>}</div>}
