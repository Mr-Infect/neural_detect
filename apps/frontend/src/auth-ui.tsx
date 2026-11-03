import { useState, type FormEvent } from "react";

type Principal = { id:string; email:string; role:string; tenant_id:string };
type Props = { principal:Principal; onLogout:()=>void };

export function LoginPage({onLogin}:{onLogin:(user:Principal)=>void}) {
 const [email,setEmail]=useState("admin@neural-detect.local"),[password,setPassword]=useState(""),[error,setError]=useState(""),[busy,setBusy]=useState(false);
 async function submit(event:FormEvent){event.preventDefault();setBusy(true);setError("");try{
  const response=await fetch("/api/v1/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});
  const data=await response.json();if(!response.ok)throw new Error(data.detail||"Sign in failed.");
  localStorage.setItem("nd_access_token",data.access_token);onLogin(data.user);
 }catch(e){setError(e instanceof Error?e.message:"Sign in failed.");}finally{setBusy(false)}}
 return <main className="auth-page"><form className="auth-card" onSubmit={submit}><div className="brand"><b>N</b><span>NEURAL<br/>DETECT</span></div>
  <p className="eyebrow">IDENTITY / ROLE BASED ACCESS</p><h1>Sign in to NEURAL DETECT</h1><p className="muted">Every API request is checked against your tenant and role.</p>
  {error&&<div role="alert" className="error">{error}</div>}
  <label>Email<input type="email" autoComplete="username" required value={email} onChange={e=>setEmail(e.target.value)}/></label>
  <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={e=>setPassword(e.target.value)}/></label>
  <button className="button primary" disabled={busy}>{busy?"Signing in...":"Sign in"}</button>
  <small>Bootstrap login: admin@neural-detect.local. The password is in your ignored local .env file.</small>
 </form></main>;
}
const links=[["Overview","overview"],["Detections","detections"],["Threat hunting","hunting"],["Investigations","investigations"],["Threat intelligence","intelligence"],["AI security","ai-security"],["AI Detection Engineer","detection-agent"],["AI Models","models"],["Automation","automation"],["Administration","administration"]];
export function PlatformNav({principal,onLogout}:Props){
 return <div className="platform-nav"><a className="platform-brand" href="#overview">NEURAL DETECT <span>v1.0.0-rc.1</span></a>
  <nav>{links.map(([label,hash])=><a key={hash} href={"#"+hash}>{label}</a>)}</nav>
  <div className="platform-user"><span>{principal.email}<small>{principal.role} / {principal.tenant_id}</small></span><button onClick={onLogout}>Sign out</button></div>
 </div>;
}
