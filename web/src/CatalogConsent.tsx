import {createEffect,createSignal,onCleanup,Show} from 'solid-js';
import {api} from './api';
import {orgPath} from './utils';
type Approval={authorization_id:string;consent_url:string|null;state:string;status:string;expires_at:string};
export default function CatalogConsent(props:{org:string;approved:()=>void}) {
  const [request,setRequest]=createSignal<Approval>(),[code,setCode]=createSignal(''),[busy,setBusy]=createSignal(false),[error,setError]=createSignal('');
  let generation=0,key=crypto.randomUUID();
  createEffect(()=>{props.org;generation++;key=crypto.randomUUID();setRequest();setCode('');setBusy(false);setError('');});
  onCleanup(()=>{generation++;setCode('');});
  async function act(complete:boolean) {
    if(busy())return;
    const current=generation,org=props.org;
    setBusy(true);setError('');
    try {
      const value=await api<Approval>(orgPath(org,complete?`catalog-authorizations/${request()!.authorization_id}/complete`:'catalog-authorizations'),'POST',complete?{code:code().trim(),state:request()!.state}:{idempotency_key:key});
      if(current!==generation)return;
      if(value.status==='completed'){setCode('');props.approved();}else setRequest(value);
    }catch(error){if(current===generation)setError(error instanceof Error?error.message:'Approval could not be saved. Try again.');}
    finally{if(current===generation)setBusy(false);}
  }
  return <section class="panel panel-body" aria-label="Honeycomb approval">
    <h2>Connect your applications</h2><p>Approve access to your Honeycomb application list. Choose the same account and organization as this Ting workspace.</p>
    <Show when={request()} fallback={<button class="button primary" disabled={busy()} onClick={()=>void act(false)}>{busy()?'Preparing approval…':'Review Honeycomb access'}</button>}>
      <p><a class="text-link" href={request()!.consent_url||undefined} target="_blank" rel="noopener noreferrer">Open approval in IAM ↗</a></p>
      <label>Approval code from IAM<input type="password" autocomplete="off" spellcheck={false} value={code()} onInput={event=>setCode(event.currentTarget.value)} placeholder="Paste the single-use code" disabled={busy()}/></label>
      <p class="muted">Expires {new Date(request()!.expires_at).toLocaleTimeString()}.</p>
      <button class="button primary" disabled={busy()||!code().trim()} onClick={()=>void act(true)}>{busy()?'Saving approval…':'Save approval'}</button>
      <button class="button" disabled={busy()} onClick={()=>{setRequest();setCode('');setError('');key=crypto.randomUUID();}}>Start again</button>
    </Show>
    <Show when={error()}><p role="alert">{error()}</p></Show>
  </section>;
}
