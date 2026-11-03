import { useEffect, useState, type FormEvent } from "react";
import { apiFetch } from "./api";

async function api<T>(path:string,init?:RequestInit):Promise<T>{
 const headers=new Headers(init?.headers||{});
 if(init?.body&&!headers.has("Content-Type"))headers.set("Content-Type","application/json");
 const response=await apiFetch(path,{...init,headers});
 const body=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(body.detail||"Request failed: "+response.status);
 return body as T;
}
type Approval={id:string;tenant_id:string;action_type:string;risk_level:string;title:string;description:string;payload:Record<string,unknown>;status:string;requested_by:string;reviewer?:string|null;rejection_reason?:string|null;created_at:string;expires_at:string;executed_at?:string|null};
type User={id:string;email:string;role:string;tenant_id:string;is_active:boolean};
type Tenant={id:string;slug:string;name:string;is_active:boolean};
const actionTypes=["detection_deploy","ip_block","account_disable","endpoint_isolation","incident_close"];

export function AutomationPage({principal}:{principal:{email:string;role:string;tenant_id:string}}){
 const [items,setItems]=useState<Approval[]>([]),[configured,setConfigured]=useState(false),[action,setAction]=useState(actionTypes[0]),[title,setTitle]=useState(""),[description,setDescription]=useState(""),[payload,setPayload]=useState("{}"),[error,setError]=useState(""),[busy,setBusy]=useState(false);
 const refresh=()=>Promise.all([
  api<Approval[]>("/api/v1/automation/approvals?tenant_id="+encodeURIComponent(principal.tenant_id)),
  api<{soar_configured:boolean}>("/api/v1/automation/summary?tenant_id="+encodeURIComponent(principal.tenant_id))
 ]).then(([rows,summary])=>{setItems(rows);setConfigured(summary.soar_configured)}).catch(e=>setError(e instanceof Error?e.message:"Automation data unavailable."));
 useEffect(()=>{void refresh()},[principal.tenant_id]);
 async function create(e:FormEvent){e.preventDefault();setBusy(true);setError("");try{
  let parsed:Record<string,unknown>;try{parsed=JSON.parse(payload)}catch{throw new Error("Payload must be valid JSON.")}
  await api("/api/v1/automation/approvals",{method:"POST",body:JSON.stringify({tenant_id:principal.tenant_id,action_type:action,title,description,payload:parsed})});
  setTitle("");await refresh();
 }catch(e){setError(e instanceof Error?e.message:"Could not request approval.")}finally{setBusy(false)}}
 async function review(id:string,decision:"approved"|"rejected"){let rejection_reason:string|undefined;if(decision==="rejected"){rejection_reason=window.prompt("Reason for rejecting this request?")||"";if(!rejection_reason.trim())return}
  setError("");try{await api("/api/v1/automation/approvals/"+id+"/review",{method:"POST",body:JSON.stringify({decision,rejection_reason})});await refresh()}catch(e){setError(e instanceof Error?e.message:"Review failed.")}}
 async function execute(id:string){setError("");try{await api("/api/v1/automation/approvals/"+id+"/execute",{method:"POST"});await refresh()}catch(e){setError(e instanceof Error?e.message:"Dispatch failed.")}}
 return <main className="phase9-page"><header><div><p className="eyebrow">HUMAN REVIEW / APPROVED RESPONSE</p><h1>Automation and approvals</h1><p className="muted">High impact actions need a different human reviewer and are recorded in the audit log.</p></div><span className={"status-chip "+(configured?"good":"warn")}>{configured?"SOAR CONNECTED":"SOAR NOT CONFIGURED"}</span></header>
  {error&&<div className="error" role="alert">{error}</div>}
  <div className="phase9-grid"><section className="panel"><p className="eyebrow">NEW REQUEST</p><h2>Request an action</h2><form className="phase9-form" onSubmit={create}>
   <label>Action type<select value={action} onChange={e=>setAction(e.target.value)}>{actionTypes.map(x=><option key={x}>{x}</option>)}</select></label>
   <label>Title<input required minLength={4} maxLength={240} value={title} onChange={e=>setTitle(e.target.value)}/></label>
   <label>Details<textarea maxLength={4000} value={description} onChange={e=>setDescription(e.target.value)}/></label>
   <label>Action payload (JSON)<textarea value={payload} onChange={e=>setPayload(e.target.value)}/></label>
   <button className="button primary" disabled={busy}>{busy?"Submitting...":"Submit for approval"}</button></form></section>
   <section className="panel"><div className="panel-head"><div><p className="eyebrow">WORKFLOW</p><h2>Review and execution history</h2></div><button className="button secondary" onClick={()=>void refresh()}>Refresh</button></div>
    {!items.length?<p className="empty">No approval requests for this tenant.</p>:<div className="approval-list">{items.map(item=><article className="approval-card" key={item.id}>
     <div className="approval-heading"><span className={"status-chip "+item.status}>{item.status}</span><span>{item.risk_level}</span></div><h3>{item.title}</h3>
     <p>{item.action_type.replaceAll("_"," ")} / requested by {item.requested_by}</p>{item.description&&<p>{item.description}</p>}
     <pre>{JSON.stringify(item.payload,null,2)}</pre><small>Expires {new Date(item.expires_at).toLocaleString()}{item.reviewer?" / reviewed by "+item.reviewer:""}</small>
     {item.status==="pending"&&(principal.role==="admin"||principal.role==="approver")&&item.requested_by.toLowerCase()!==principal.email.toLowerCase()&&<div className="approval-actions"><button onClick={()=>void review(item.id,"approved")}>Approve</button><button className="danger" onClick={()=>void review(item.id,"rejected")}>Reject</button></div>}
     {item.status==="approved"&&principal.role==="admin"&&<button className="button secondary" disabled={!configured} onClick={()=>void execute(item.id)}>{configured?"Dispatch approved action":"Configure SOAR to dispatch"}</button>}
    </article>)}</div>}
   </section></div>
 </main>;
}

export function AdministrationPage({principal}:{principal:{email:string;tenant_id:string}}){
 const [users,setUsers]=useState<User[]>([]),[tenants,setTenants]=useState<Tenant[]>([]),[roles,setRoles]=useState<any[]>([]),[integrations,setIntegrations]=useState<any[]>([]),[audit,setAudit]=useState<any[]>([]),[error,setError]=useState("");
 const [email,setEmail]=useState(""),[password,setPassword]=useState(""),[role,setRole]=useState("analyst"),[tenant,setTenant]=useState(principal.tenant_id),[busy,setBusy]=useState(false);
 const [tenantName,setTenantName]=useState(""),[tenantSlug,setTenantSlug]=useState(""),[tenantBusy,setTenantBusy]=useState(false);
 const refresh=()=>Promise.all([
  api<User[]>("/api/v1/auth/users?tenant_id="+encodeURIComponent(principal.tenant_id)),
  api<Tenant[]>("/api/v1/auth/tenants"),api<any[]>("/api/v1/auth/roles"),
  api<any[]>("/api/v1/auth/integrations"),
  api<any[]>("/api/v1/auth/audit?tenant_id="+encodeURIComponent(principal.tenant_id))
 ]).then(([u,t,r,i,a])=>{setUsers(u);setTenants(t);setRoles(r);setIntegrations(i);setAudit(a)}).catch(e=>setError(e instanceof Error?e.message:"Administration data unavailable."));
 useEffect(()=>{void refresh()},[principal.tenant_id]);
 async function addUser(e:FormEvent){e.preventDefault();setBusy(true);setError("");try{
  await api("/api/v1/auth/users",{method:"POST",body:JSON.stringify({email,password,role,tenant_id:tenant})});
  setEmail("");setPassword("");await refresh();
 }catch(e){setError(e instanceof Error?e.message:"Could not create user.")}finally{setBusy(false)}}
 async function addTenant(e:FormEvent){e.preventDefault();setTenantBusy(true);setError("");try{
  await api("/api/v1/auth/tenants",{method:"POST",body:JSON.stringify({name:tenantName,slug:tenantSlug})});
  setTenantName("");setTenantSlug("");await refresh();
 }catch(e){setError(e instanceof Error?e.message:"Could not create tenant.")}finally{setTenantBusy(false)}}
 async function updateUser(user:User,changes:Record<string,unknown>){setError("");try{
  await api("/api/v1/auth/users/"+user.id,{method:"PATCH",body:JSON.stringify(changes)});await refresh();
 }catch(e){setError(e instanceof Error?e.message:"Could not update user.")}}
 return <main className="phase9-page"><header><div><p className="eyebrow">IDENTITY / POLICY / AUDIT</p><h1>Administration</h1><p className="muted">Role and tenant changes are enforced through OPA and written to the audit stream.</p></div><span className="status-chip good">OPA ENFORCING</span></header>
  {error&&<div className="error" role="alert">{error}</div>}
  <section className="panel"><div className="panel-head"><div><p className="eyebrow">IDENTITY</p><h2>Users</h2></div></div>
   <form className="user-create" onSubmit={addUser}><input aria-label="Email" placeholder="analyst@example.org" type="email" required value={email} onChange={e=>setEmail(e.target.value)}/><input aria-label="Temporary password" placeholder="Temporary password (20+ chars)" type="password" minLength={20} required value={password} onChange={e=>setPassword(e.target.value)}/><select aria-label="Role" value={role} onChange={e=>setRole(e.target.value)}>{roles.map(x=><option key={x.name} value={x.name}>{x.name}</option>)}</select><select aria-label="Tenant" value={tenant} onChange={e=>setTenant(e.target.value)}>{tenants.map(x=><option key={x.slug} value={x.slug}>{x.name} / {x.slug}</option>)}</select><button disabled={busy}>Create user</button></form>
   <div className="admin-table"><div className="admin-row admin-head"><b>Email</b><b>Role</b><b>Tenant</b><b>Status</b></div>{users.map(x=><div className="admin-row" key={x.id}><span>{x.email}</span><select value={x.role} disabled={x.email===principal.email} onChange={e=>void updateUser(x,{role:e.target.value})}>{roles.map(r=><option key={r.name}>{r.name}</option>)}</select><span>{x.tenant_id}</span><button disabled={x.email===principal.email} onClick={()=>void updateUser(x,{is_active:!x.is_active})}>{x.is_active?"Active":"Disabled"}</button></div>)}</div>
  </section>
  <section className="panel"><p className="eyebrow">TENANT BOUNDARIES</p><h2>Tenants</h2>
   <form className="user-create tenant-create" onSubmit={addTenant}><input required minLength={2} placeholder="Tenant name" value={tenantName} onChange={e=>setTenantName(e.target.value)}/><input required minLength={2} pattern="[a-z0-9]+(-[a-z0-9]+)*" placeholder="tenant-slug" value={tenantSlug} onChange={e=>setTenantSlug(e.target.value)}/><button disabled={tenantBusy}>{tenantBusy?"Creating...":"Create tenant"}</button></form>
   <div className="tenant-list">{tenants.map(t=><div key={t.id}><b>{t.name}</b><code>{t.slug}</code><span>{t.is_active?"ACTIVE":"DISABLED"}</span></div>)}</div>
  </section>
  <div className="phase9-grid admin-lower"><section className="panel"><p className="eyebrow">ACCESS CONTROL</p><h2>Roles</h2>{roles.map(x=><div className="role-row" key={x.name}><b>{x.name}</b><span>{x.description}</span></div>)}</section>
   <section className="panel"><p className="eyebrow">CONNECTED SERVICES</p><h2>Integrations and model providers</h2>{integrations.map(x=><div className="integration-row" key={x.name}><b>{x.name}</b><span>{x.kind}</span><em>{x.status}</em></div>)}</section></div>
  <section className="panel"><p className="eyebrow">AUDIT HISTORY</p><h2>Audit log</h2>{!audit.length?<p className="empty">No events recorded yet.</p>:<div className="audit-list">{audit.slice(0,60).map(x=><div key={x.id}><time>{new Date(x.created_at).toLocaleString()}</time><b>{x.action}</b><span>{x.actor}</span><small>{x.resource_type} / {x.resource_id||"-"}</small></div>)}</div>}</section>
 </main>;
}
