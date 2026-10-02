import { normalizeCampaign } from './campaign.js';

const API_PATH = /^window\.([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,4})$/;
/** Static evidence proposes tests; it does not authorize backend writes or guess disposable records. */
export function campaignPlan(issues) {
  const items = [];
  const seen = new Set();
  for (const issue of issues) {
    const context = issue.properties?.context;
    const capabilities = [...new Set((context?.effects || []).filter(e => e.arguments.length).map(e => e.capability))];
    if (!capabilities.length && !['XSS_SINK_JS_CHECK', 'DOCUMENT_PIPELINE_JS_CHECK'].includes(issue.id)) continue;
    if (!['IPC_CHANNEL_MAP_GLOBAL_CHECK', 'FILE_HANDLER_JS_CHECK', 'RENDERER_INPUT_JS_CHECK', 'PROTOCOL_HANDLER_JS_CHECK', 'DOWNLOAD_JS_CHECK', 'XSS_SINK_JS_CHECK', 'DOCUMENT_PIPELINE_JS_CHECK'].includes(issue.id)) continue;
    const api = issue.properties?.exposedAPIs?.find(api => API_PATH.test(api.api));
    const key = `${issue.id}:${issue.properties?.channel || issue.file + ':' + issue.location?.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const fields = (context?.arguments || []).filter(arg => arg.operations.length).map(arg => arg.name);
    const cases = ['text', 'html', 'event-handler', 'script-tag', 'svg-handler'];
    if (capabilities.includes('network')) cases.push('external-image', 'external-script');
    if (capabilities.includes('windows')) cases.push('nav-loopback', 'nav-redirect');
    if (capabilities.includes('html') || issue.id === 'XSS_SINK_JS_CHECK') cases.push('cookie-canary', 'localstorage-canary');
    if (api) cases.push('api-normal', 'api-null', 'api-number', 'api-object', 'api-traversal', 'api-absolute', 'api-file-url');
    const pathField = fields.find(name => /^argument\d+\./.test(name));
    const match = pathField?.match(/^argument(\d+)\.(.+)$/);
    const apiDraft = api ? { path: api.api.replace(/^window\./, ''), args: null,
      mutationIndex: match ? Number(match[1]) - 1 : null, ...(match ? { mutationPath: match[2].split('.') } : {}) } : undefined;
    items.push({ id: `test-${items.length + 1}`, finding: { id: issue.id, file: issue.file, line: issue.location?.line, channel: issue.properties?.channel },
      capabilities, inputs: fields, ready: false,
      required: ['disposable test record/workspace', 'actual POST/PUT/PATCH save route', 'eligible content fields', 'saved-content view URL', ...(api ? ['benign API arguments and mutation location'] : [])],
      assertions: ['correlate delivery and effect to this exact case', 'record explicit rejection separately from no signal', 'verify original saved content after restoration'],
      profile: { version: 1, capture: { method: null, route: null }, fields: null, view: null, cases,
        closeOnDone: false, restoreOnDone: true, ...(apiDraft ? { api: apiDraft } : {}) },
    });
  }
  return { version: 1, kind: 'campaign-plan', executable: false, items,
    instructions: 'Review each finding, fill its profile with an actual disposable workflow, then save that profile alone and run --campaign. The plan itself cannot be executed.' };
}

/** Turn one reviewed draft into an executable profile only after its workflow contract is supplied. */
export function campaignFromPlan(plan, id, contract) {
  const item = plan?.kind === 'campaign-plan' && plan.items?.find(item => item.id === id);
  if (!item) throw new Error('Unknown campaign plan item');
  const profile = { ...item.profile, ...contract, api: item.profile.api ? { ...item.profile.api, ...contract.api } : contract.api };
  if (contract.request) delete profile.capture;
  return normalizeCampaign(profile);
}
