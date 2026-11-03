import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "./api";

type Provider = { provider: string; status: string; cloud: boolean; model: string; available_models?: number };
type Evaluation = { id:string; provider:string; model:string; model_version:string|null; output_kind:string; latency_ms:number; prompt_tokens:number|null; completion_tokens:number|null; output_valid:boolean; error_code:string|null; created_at:string };
type Result = { provider:string; model:string; model_version:string|null; latency_ms:number; usage:{prompt_tokens:number|null;completion_tokens:number|null}; cost_usd:number|null; redacted_categories:string[]; output:Record<string,unknown> };
const kinds=["detection","threat_intelligence","investigation","hunting_query"] as const;

export function AIModelsPage(){
  const [providers,setProviders]=useState<Provider[]>([]);
  const [evaluations,setEvaluations]=useState<Evaluation[]>([]);
  const [provider,setProvider]=useState("ollama");
  const [outputKind,setOutputKind]=useState<(typeof kinds)[number]>("investigation");
  const [prompt,setPrompt]=useState("");
  const [cloudConsent,setCloudConsent]=useState(false);
  const [rawTelemetry,setRawTelemetry]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [result,setResult]=useState<Result|null>(null);
  const [loading,setLoading]=useState(true);
  const refresh=useCallback(async()=>{
    setLoading(true);
    try{
      const [p,e]=await Promise.all([apiFetch("/api/v1/ai/models/providers"),apiFetch("/api/v1/ai/models/evaluations")]);
      if(!p.ok||!e.ok) throw new Error("Model gateway status is unavailable.");
      setProviders(await p.json());setEvaluations(await e.json());
    }catch(reason){setError(reason instanceof Error?reason.message:"Could not load model gateway.");}
    finally{setLoading(false);}
  },[]);
  useEffect(()=>{void refresh();},[refresh]);
  const submit=async()=>{
    setBusy(true);setError("");setResult(null);
    try{
      const response=await apiFetch("/api/v1/ai/models/infer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tenant_id:"default",prompt,output_kind:outputKind,provider,cloud_consent:cloudConsent,contains_raw_telemetry:rawTelemetry})});
      const body=await response.json();
      if(!response.ok) throw new Error(typeof body.detail==="string"?body.detail:body.detail?.message??"Inference failed.");
      setResult(body as Result);await refresh();
    }catch(reason){setError(reason instanceof Error?reason.message:"Inference failed.");}
    finally{setBusy(false);}
  };
  const chosen=providers.find(item=>item.provider===provider);
  return <main className="ai-page">
    <header className="ai-header"><div><p className="eyebrow">MODEL GATEWAY · PHASE 4</p><h1>Hybrid AI models</h1><p className="ai-subtitle">Local and hosted inference behind one privacy-aware interface.</p></div><a className="button secondary" href="/">Back to overview</a></header>
    {error&&<div className="error ai-error" role="alert"><b>Gateway response</b><span>{error}</span></div>}
    <section className="ai-provider-grid" aria-label="Provider status">
      {providers.map(item=><article className="panel provider-card" key={item.provider}><div className="provider-card-top"><span className="provider-icon">{item.cloud?"C":"L"}</span><span className={"provider-status "+(item.status==="ok"||item.status==="configured"?"good":"muted")}>{item.status.replaceAll("_"," ").toUpperCase()}</span></div><h2>{item.provider.replaceAll("_"," ")}</h2><p>{item.model}</p><small>{item.cloud?"Hosted · explicit consent required":"Local inference"}{item.available_models!==undefined?` · ${item.available_models} models discovered`:""}</small></article>)}
      {!providers.length&&!loading&&<article className="panel provider-card"><p className="empty">No provider status returned.</p></article>}
    </section>
    <section className="ai-workspace">
      <article className="panel ai-form"><div className="panel-head"><div><p className="eyebrow">STRUCTURED INFERENCE</p><h2>Try a model</h2></div><span className="source-count">SCHEMA VALIDATED</span></div>
        <div className="ai-select-row"><label>Provider<select value={provider} onChange={event=>setProvider(event.target.value)}>{providers.map(item=><option key={item.provider} value={item.provider}>{item.provider.replaceAll("_"," ")}</option>)}</select></label><label>Output type<select value={outputKind} onChange={event=>setOutputKind(event.target.value as (typeof kinds)[number])}>{kinds.map(item=><option key={item} value={item}>{item.replaceAll("_"," ")}</option>)}</select></label></div>
        <label className="ai-prompt-label">Prompt<textarea value={prompt} onChange={event=>setPrompt(event.target.value)} maxLength={20000} placeholder="Describe the security task. Sensitive values are redacted before the provider call." /></label>
        <div className="privacy-controls"><label><input type="checkbox" checked={cloudConsent} onChange={event=>setCloudConsent(event.target.checked)} disabled={!chosen?.cloud}/> I explicitly consent to hosted inference for this request</label><label><input type="checkbox" checked={rawTelemetry} onChange={event=>setRawTelemetry(event.target.checked)}/> This prompt contains raw security telemetry</label></div>
        <p className="privacy-note">Secrets, email addresses, phone numbers, and IP addresses are redacted before inference. Hosted inference also requires a server-side global enable and tenant policy. Raw telemetry remains blocked unless separately allowed for that tenant.</p>
        <button className="button" disabled={busy||!prompt.trim()||!chosen||chosen.status!=="ok"} onClick={()=>void submit()}>{busy?"Running inference…":"Run structured inference"}</button>
        {result&&<div className="ai-result"><div className="result-meta"><b>{result.provider} · {result.model}</b><span>{result.latency_ms} ms</span></div>{result.redacted_categories.length>0&&<p className="redaction-note">Redacted: {result.redacted_categories.join(", ")}</p>}<pre>{JSON.stringify(result.output,null,2)}</pre></div>}
      </article>
      <article className="panel ai-history"><div className="panel-head"><div><p className="eyebrow">MODEL EVALUATIONS</p><h2>Recent requests</h2></div><button className="button secondary" onClick={()=>void refresh()}>{loading?"Refreshing…":"Refresh"}</button></div>
        {!evaluations.length?<p className="empty">No inference evaluations stored yet.</p>:<div className="eval-list">{evaluations.map(item=><div className="eval-row" key={item.id}><span className={"eval-dot "+(item.output_valid?"pass":"fail")}/><div className="eval-main"><b>{item.provider} · {item.model}</b><small>{item.output_kind.replaceAll("_"," ")} · {new Date(item.created_at).toLocaleString()}</small></div><span className="eval-latency">{item.latency_ms} ms</span><span className={"eval-valid "+(item.output_valid?"pass":"fail")}>{item.output_valid?"VALID":"ERROR"}</span></div>)}</div>}
      </article>
    </section>
    <footer>Phase 4 · Provider-neutral inference with tenant-scoped privacy controls <span>·</span> Evaluation records omit prompts and model responses.</footer>
  </main>;
}

