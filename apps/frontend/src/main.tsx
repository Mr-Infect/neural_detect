import { useEffect, useState, type ReactNode } from "react";
import { apiFetch } from "./api";
import { LoginPage, PlatformNav } from "./auth-ui";
import { AdministrationPage, AutomationPage } from "./phase9-pages";
import { createRoot } from "react-dom/client";
import "./style.css";
import { DetectionsPage } from "./detections";
import { AIModelsPage } from "./ai-models";
import { DetectionAgentPage } from "./detection-agent";
import { SocAgentsPage } from "./ai-soc";
import { IntelligencePage } from "./intelligence";
import { AISecurityPage } from "./ai-security";

type Summary={data_available:boolean;total_events:number;events_by_category:{name:string;count:number}[];authentication_failures:number;suspicious_processes:number;network_events:number;recent_alerts:Record<string,unknown>[]};
type Health={status:string;authenticated:boolean;cluster:{status:string}|null;indices:number};
type Source={id:string;name:string;kind:string;dataset:string;enabled:boolean};
const pageFromHash=()=>{const h=window.location.hash;return h==="#detections"?"detections":h==="#models"?"models":h==="#detection-agent"?"detection-agent":h==="#hunting"?"hunting":h==="#investigations"?"investigations":h==="#intelligence"?"intelligence":h==="#ai-security"?"ai-security":h==="#automation"?"automation":h==="#administration"?"administration":"overview"};
async function json<T>(path:string):Promise<T>{const r=await apiFetch(path);if(!r.ok)throw new Error(path+" returned HTTP "+r.status);return r.json() as Promise<T>}
function App(){
 const [page,setPage]=useState(pageFromHash),[data,setData]=useState<{summary:Summary;health:Health;sources:Source[]}|null>(null),[error,setError]=useState("");
 const [authReady,setAuthReady]=useState(false),[principal,setPrincipal]=useState<any>(null);
 useEffect(()=>{const token=localStorage.getItem("nd_access_token");if(!token){setAuthReady(true);return}apiFetch("/api/v1/auth/me").then(async r=>{if(!r.ok)throw new Error("expired");setPrincipal(await r.json())}).catch(()=>localStorage.removeItem("nd_access_token")).finally(()=>setAuthReady(true))},[]);
 useEffect(()=>{const f=()=>setPage(pageFromHash());window.addEventListener("hashchange",f);return()=>window.removeEventListener("hashchange",f)},[]);
 useEffect(()=>{if(!principal)return;Promise.all([json<Summary>("/api/v1/dashboard/summary?tenant_id="+encodeURIComponent(principal.tenant_id)),json<Health>("/api/v1/telemetry/health"),json<Source[]>("/api/v1/telemetry/sources")]).then(([summary,health,sources])=>setData({summary,health,sources})).catch(e=>setError(e instanceof Error?e.message:"Dashboard unavailable."))},[principal]);
 if(!authReady)return <div className="auth-loading">Checking your session...</div>;
 if(!principal)return <LoginPage onLogin={setPrincipal}/>;
 const frame=(content:ReactNode)=><><PlatformNav principal={principal} onLogout={()=>{localStorage.removeItem("nd_access_token");setPrincipal(null)}}/>{content}</>;
 if(page==="automation")return frame(<AutomationPage principal={principal}/>);
 if(page==="administration")return frame(<AdministrationPage principal={principal}/>);
 if(page==="detections")return frame(<DetectionsPage/>);
 if(page==="models")return frame(<AIModelsPage/>);
 if(page==="detection-agent")return frame(<DetectionAgentPage/>);
 if(page==="hunting")return frame(<SocAgentsPage mode="hunting"/>);
 if(page==="investigations")return frame(<SocAgentsPage mode="investigations"/>);
 if(page==="intelligence")return frame(<IntelligencePage/>);
 if(page==="ai-security")return frame(<AISecurityPage/>);
 const s=data?.summary;
 return frame(<main className="layout"><aside className="sidebar"><div className="brand"><b>N</b><span>NEURAL<br/>DETECT</span></div><p className="section-label">SECURITY OPERATIONS</p><nav aria-label="Main navigation"><a className="active" href="/">Overview</a><a href="#detections">Detections</a><a href="#hunting">Threat hunting</a><a href="#investigations">Investigations</a><a href="#intelligence">Threat intelligence</a><a href="#ai-security">AI security assurance</a><a href="#detection-agent">AI Detection Engineer</a><a href="#models">AI Models</a><a href="#settings">Settings</a></nav><div className="side-foot">LOCAL-FIRST SECURITY <span>V1.0.0 RC1</span></div></aside>
 <section className="main"><header><div><p className="eyebrow">TELEMETRY · ELASTIC STACK</p><h1>Security overview</h1></div><div className={"health-pill "+(data?.health.status==="ok"?"good":"waiting")}><i/>{error?"DATA UNAVAILABLE":data?.health.cluster?.status?.toUpperCase()??"CONNECTING"}</div></header>
 {error&&<div className="error" role="alert">{error}</div>}{data&&!s?.data_available&&<div className="notice"><span className="pulse"/>Elasticsearch is connected. No telemetry events are indexed yet.</div>}
 <section className="hero"><div><p className="eyebrow">LIVE TELEMETRY</p><h2>See what’s happening<br/>across your environment.</h2><p>Event counts, detections, and source status come from Elasticsearch.</p></div><div className="signal" aria-hidden="true"><span/><span/><span/><b>ND</b></div></section>
 <section className="metrics"><article className="metric"><p className="eyebrow">TOTAL EVENTS</p><strong>{s?.total_events??"—"}</strong><span>Indexed in NEURAL DETECT</span></article><article className="metric"><p className="eyebrow">AUTH FAILURES</p><strong>{s?.authentication_failures??"—"}</strong><span>Authentication outcome: failure</span></article><article className="metric"><p className="eyebrow">SUSPICIOUS PROCESSES</p><strong>{s?.suspicious_processes??"—"}</strong><span>Process indicators</span></article><article className="metric"><p className="eyebrow">NETWORK EVENTS</p><strong>{s?.network_events??"—"}</strong><span>Network telemetry</span></article></section>
 <section className="lower"><article className="panel"><div className="panel-head"><div><p className="eyebrow">EVENT DISTRIBUTION</p><h3>Events by category</h3></div><span className="live-dot">ELASTIC DATA</span></div>{!s?.events_by_category.length?<p className="empty">No categorized events to display.</p>:<div className="bars">{s.events_by_category.map(x=><div className="bar-row" key={x.name}><span>{x.name}</span><div className="track"><i style={{width:String(Math.max(3,x.count/Math.max(1,...s.events_by_category.map(y=>y.count))*100))+"%"}}/></div><b>{x.count}</b></div>)}</div>}</article>
 <article className="panel sources"><div className="panel-head"><div><p className="eyebrow">COLLECTORS</p><h3>Telemetry sources</h3></div><span className="source-count">{data?.sources.length??0} REGISTERED</span></div>{!data?.sources.length?<p className="empty">No sources registered.</p>:<ul>{data.sources.map(x=><li key={x.id}><span className={"source-indicator "+(x.enabled?"on":"")}/><div><b>{x.name}</b><small>{x.kind} · {x.dataset}</small></div><em>{x.enabled?"CONFIGURED":"DISABLED"}</em></li>)}</ul>}<div className="index-line"><span>Elasticsearch indices</span><b>{data?.health.indices??0}</b></div></article></section>
 <section className="panel alert-panel"><div className="panel-head"><div><p className="eyebrow">ELASTIC SECURITY</p><h3>Recent alerts</h3></div><a href="#investigations" className="live-dot">OPEN INCIDENTS →</a></div>{!s?.recent_alerts.length?<p className="empty">No Elastic Security alerts found.</p>:<div className="alert-list">{s.recent_alerts.map((a,i)=><div className="alert-row" key={String(a["kibana.alert.uuid"]??i)}><span className="alert-mark">!</span><b>{String(a["kibana.alert.rule.name"]??"Untitled rule")}</b><span>{String(a["kibana.alert.severity"]??"severity unavailable")}</span><time>{String(a["@timestamp"]??"")}</time></div>)}</div>}</section>
 <footer>Phase 10 · Release candidate <span>·</span><a href="/docs">API reference</a></footer></section></main>);
}
createRoot(document.getElementById("root")!).render(<App/>);
