import { randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { hostedAppPreviewHostname, HostedAppPreviewAccessError } from './preview-access';

function origin(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.origin !== raw.replace(/\/$/, '')) {
    throw new HostedAppPreviewAccessError('invalid preview origin');
  }
  return url.origin;
}

export function hostedAppPreviewViewerUrl(runtimeId: string, previewOrigin: string): string {
  hostedAppPreviewHostname(runtimeId, previewOrigin);
  return `${origin(previewOrigin)}/viewer/${runtimeId}`;
}

/** Trusted shell: all untrusted app code lives on the distinct per-app origin.
 * The parent must authorize its browser challenge through the authenticated
 * lifecycle API; no API credential or transferable grant lives in this URL. */
export function sendHostedAppPreviewViewer(req: Request, res: Response, runtimeId: string, previewOrigin: string, parentOrigin: string): Response {
  const parent = origin(parentOrigin);
  const viewer = origin(previewOrigin);
  const channel = req.query.channel;
  if (typeof channel !== 'string' || !/^[a-f0-9]{32}$/.test(channel)) {
    return res.status(400).type('text/plain').send('Open this preview from LibreChat.');
  }
  const app = new URL(viewer);app.hostname = hostedAppPreviewHostname(runtimeId, viewer);
  const nonce = randomBytes(16).toString('base64url');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Origin-Agent-Cluster', '?1');
  res.setHeader('Content-Security-Policy', `default-src 'none'; frame-src ${app.origin}; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; frame-ancestors ${parent}; base-uri 'none'; form-action 'none'`);
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  return res.status(200).type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>App preview</title>
<style nonce="${nonce}">html,body,iframe{margin:0;width:100%;height:100%;border:0}body{overflow:hidden}</style></head><body>
<iframe title="App preview" sandbox="allow-scripts allow-forms allow-same-origin" referrerpolicy="no-referrer"></iframe>
<script nonce="${nonce}">
const parentOrigin=${JSON.stringify(parent)},appOrigin=${JSON.stringify(app.origin)},channel=${JSON.stringify(channel)},runtimeId=${JSON.stringify(runtimeId)};
const frame=document.querySelector('iframe');
let challengeForwarded=false,authorized=false;
window.addEventListener('message',event=>{
 const value=event.data;if(!value||typeof value!=='object')return;
 if(!challengeForwarded&&!authorized&&event.source===frame.contentWindow&&event.origin===appOrigin&&value.type==='codeapi.preview.challenge'&&typeof value.challenge==='string'&&value.challenge.length<=1024){
  challengeForwarded=true;
  window.parent.postMessage({type:value.type,channel,runtimeId,challenge:value.challenge},parentOrigin);return;
 }
 if(!challengeForwarded||authorized||event.source!==window.parent||event.origin!==parentOrigin||value.type!=='codeapi.preview.authorize'||value.channel!==channel||typeof value.authorizationUrl!=='string'||value.authorizationUrl.length>2048)return;
 try{const url=new URL(value.authorizationUrl);if(url.origin!==appOrigin||url.pathname!=='/__codeapi/authorize')return;authorized=true;frame.src=url.href;}catch{}
});
frame.src=appOrigin+'/__codeapi/challenge';
</script></body></html>`);
}
