"use client";
import { useEffect, useState } from "react";

import { ArrowRight, Shield, Lock, Search } from "lucide-react";

type Row={case_id:string;request_id:string|null;status:number|null;upstream_status:string|null;uri:string;outcome:string;passed:boolean};
type Control={waf_request_id:string;waf_rules:string[];burst_total:number;burst_rejected:number;burst_admitted:number;recovery:boolean;backend_private:boolean;tls:string[]};
type Summary={run_id:string;generated_at:string;benign:{passed:number;total:number;ok:boolean};rows:Row[];controls?:Control;full_suite_ok:boolean};
type Page="overview"|"controls"|"evidence"|"demo";
const info={
  controls:["Edge controls","Follow a request through the network edge, from the TLS handshake to a policy decision."],
  evidence:["Request evidence","Find a case and compare its response ID with the corresponding entry in the proxy log."],
  demo:["Evaluator guide","Walk through the running application and its evidence in five to seven minutes."]
};
function useRun(){
  const [data,setData]=useState<Summary|null>(null);
  const [error,setError]=useState(false);
  useEffect(()=>{
    const controller=new AbortController();
    async function refresh(){
      try{
        const response=await fetch("/alerts.json",{cache:"no-store",signal:controller.signal});
        if(!response.ok)throw Error();
        const value=await response.json();
        if(!value.run_id||!Array.isArray(value.rows)||!value.benign)throw Error();
        if(!controller.signal.aborted){setData(value);setError(false)}
      }catch{if(!controller.signal.aborted)setError(true)}
    }
    refresh(); const timer=setInterval(refresh,5000);
    return ()=>{controller.abort();clearInterval(timer)};
  },[]);
  return {data,error};
}
function Stats({data}:{data:Summary}){
  const c=data.controls;
  return <div className="stats">{[
    ["Benign requests passed",data.benign.passed+"/"+data.benign.total],
    ["Policy check",c?"403":"—"],
    ["Burst requests limited",c?c.burst_rejected+"/"+c.burst_total:"—"]
  ].map(([label,value])=><div key={label}><small>{label}</small><strong>{value}</strong></div>)}</div>
}
function Controls({data}:{data:Summary}){
  const c=data.controls;
  return <><div className="path"><span>HTTPS client</span><b>→</b><span>nginx + ModSecurity</span><b>→</b><span>Private Juice Shop</span></div>
  {c?<div className="panels"><article><Lock/><h2>TLS termination</h2><p>The edge negotiated TLS {c.tls.join(" and ")}. The backend runs on an internal Docker network.</p></article>
  <article><Shield/><h2>Inbound policy block</h2><p>The media-type probe returned 403. CRS rules {c.waf_rules.join(", ")} were recorded before upstream processing.</p><code>{c.waf_request_id}</code></article>
  <article><h2>Login rate limit</h2><p>Of {c.burst_total} credential-free probes, {c.burst_rejected} were rejected at nginx and {c.burst_admitted} reached the application. Recovery check: {c.recovery?"passed":"failed"}.</p></article></div>:<p>This run contains no edge-control measurements.</p>}
  <section><small>Recorded Windows run · 20261121-105637</small><h2>Attack categories</h2><p>The team’s Windows report recorded one inbound 403 for each category. These counts belong to that earlier run.</p><div className="history">{["SQL injection","Cross-site scripting","Path traversal","Command injection","Scanner user agent"].map(x=><div key={x}>{x}<strong>1 block</strong></div>)}</div><p>Recorded login burst: 20 of 25 attempts returned 429; five reached the app. See report/REPORT.md for the mappings and source evidence.</p></section></>
}
function Evidence({data}:{data:Summary}){
  const [query,setQuery]=useState("");
  const rows=data.rows.filter(r=>[r.request_id,r.case_id,r.status,r.uri,r.outcome].join(" ").toLowerCase().includes(query.toLowerCase()));
  return <><Stats data={data}/><div className="search"><Search size={19}/><input value={query} onChange={e=>setQuery(e.target.value)} aria-label="Filter request evidence" placeholder="Filter by case, route, status or request ID"/></div>
  <div className="scroll"><table><thead><tr>{["Case","Route","HTTP","Upstream","Request ID"].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{rows.map(r=><tr key={r.case_id}><td>{r.case_id}</td><td>{r.uri}</td><td>{r.status??"timeout"}</td><td>{r.upstream_status||"—"}</td><td><code>{r.request_id??"unavailable"}</code></td></tr>)}</tbody></table></div>
  <p aria-live="polite">{rows.length} of {data.rows.length} requests shown.</p></>
}
function Guide(){return <div className="guide">{[
  ["1 minute","Open the storefront","Visit https://localhost:8443 through the SSH tunnel. Browse and search for a product. Show the loopback port and the private backend on the Controls page."],
  ["2 minutes","Walk through the controls","Show the TLS versions, the WAF rule IDs, and the request ID for the harmless policy check. Explain how nginx admits early login attempts and rejects excess requests."],
  ["2 minutes","Trace a shopper request","Open Evidence and search for ben-20. Show the HTTP response, upstream status, and full request ID. Use that ID to locate the same event in logs/nginx/access.log."],
  ["1 minute","Repeat one check","From the project directory run bash scripts/verify-waf.sh. It prints a fresh 403 request ID and verifies its audit rules. The UI shows the latest published run; bash scripts/run_demo.sh publishes another complete defensive run."]
].map(([duration,title,body])=><article key={title}><small>{duration}</small><div><h2>{title}</h2><p>{body}</p></div></article>)}</div>}
export function Observatory({page}:{page:Page}){
  const {data,error}=useRun();
  return <main>{page==="overview"?<div className="hero"><div className="heroinner"><span className="eyebrow">PS6 / Secure Networks</span><h1>Shield Wall</h1><p>Protecting a public-facing storefront at the network edge.</p><a className="button" href="/controls/">Explore edge controls <ArrowRight size={17}/></a></div></div>:
    <div className="pagehead"><div className="wrap"><span className="eyebrow">Shield Wall / {page}</span><h1>{info[page][0]}</h1><p>{info[page][1]}</p></div></div>}
  <div className="wrap content">{error&&<p role="alert">{data?"Refresh failed. Showing the last loaded run.":"Run evidence is unavailable. Publish a run from the VM."}</p>}
  {page==="demo"?<Guide/>:<>{data?<><div className="stamp"><i/>Latest published run <code>{data.run_id}</code><time>{new Date(data.generated_at).toLocaleString()}</time></div>
  {page==="overview"?<><h2 className="title">Verification overview</h2><Stats data={data}/><div className="cards"><a href="/controls/"><Shield/><h2>Control decisions</h2><p>TLS, policy enforcement and login throttling.</p><ArrowRight/></a><a href="/evidence/"><Search/><h2>Request ledger</h2><p>Trace each shopper request to the application.</p><ArrowRight/></a></div></>:page==="controls"?<Controls data={data}/>:<Evidence data={data}/>}</>:!error&&<p>Loading run evidence…</p>}</>}
  </div></main>
}
