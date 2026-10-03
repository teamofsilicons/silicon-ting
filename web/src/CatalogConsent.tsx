import {createEffect,createSignal,onCleanup,Show} from 'solid-js';
import {api, ApiError} from './api';
import {orgPath} from './utils';
import {openIamPopup} from './iam-popup';
export default function CatalogConsent(props:{org:string;approved:()=>void}) {
  const [busy,setBusy]=createSignal(false),[error,setError]=createSignal('');
  let generation=0,key=crypto.randomUUID();
  createEffect(()=>{props.org;generation++;key=crypto.randomUUID();setBusy(false);setError('');});
  onCleanup(()=>{generation++;});
  async function start() {
    if(busy())return;
    const current=generation,org=props.org;
    setBusy(true);setError('');
    try {
      await openIamPopup(async nonce => {
        const value=await api<{redirect_url:string}>(orgPath(org,'catalog-authorizations'),'POST',{idempotency_key:key,popup_nonce:nonce});
        if(current!==generation)throw new Error('Your workspace changed. Start approval in the current workspace.');
        return value.redirect_url;
      });
      if(current===generation)props.approved();
    }catch(error){if(current===generation){if(error instanceof ApiError && error.code==='catalog_approval_declined')key=crypto.randomUUID();setError(error instanceof Error?error.message:'Approval could not be saved. Try again.');}}
    finally{if(current===generation)setBusy(false);}
  }
  return <section class="panel panel-body" aria-label="Honeycomb approval">
    <h2>Connect your applications</h2><p>Approve access to your Honeycomb application list. Choose the same account and organization as this Ting workspace.</p>
    <button class="button primary" disabled={busy()} onClick={()=>void start()}>{busy()?'Waiting for your approval…':'Review Honeycomb access'}</button>
    <p class="muted">IAM opens in a secure popup and returns here automatically. Your Ting session stays active.</p>
    <Show when={error()}><p role="alert">{error()}</p><button class="button" disabled={busy()} onClick={()=>{key=crypto.randomUUID();setError('');}}>Start a new approval</button></Show>
  </section>;
}
