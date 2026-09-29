import fs from 'node:fs';
import { createRequire } from 'node:module';
import { apiRoute } from './analyze.js';

const require = createRequire(import.meta.url);
const { CASES } = require('./campaign.cjs');
const { DOCX_CASES } = require('./docx.cjs');
const METHODS = new Set(['POST', 'PUT', 'PATCH']);

/** Explicit test account/workflow contract. A profile authorizes these exact writes once, not per payload. */
export function normalizeCampaign(input) {
  if (!input || input.version !== 1 || (!(input.request || input.capture) && !input.docxImport) || (input.request && input.capture))
    throw new Error('Campaign profile needs version 1 and a request, capture route or docxImport contract');
  const source = input.request || input.capture;
  const method = String(source?.method || '').toUpperCase();
  const validField = field => typeof field === 'string' && /^[\w$.[\]-]{1,120}$/.test(field);
  const fields = input.fields === undefined ? [input.field] : input.fields;
  const validFields = fields === 'auto' || (Array.isArray(fields) && fields.length >= 1 && fields.length <= 8 &&
    new Set(fields).size === fields.length && fields.every(validField));
  if (source && (!METHODS.has(method) || !validFields || (input.field !== undefined && input.fields !== undefined)))
    throw new Error('Campaign needs a POST/PUT/PATCH method and 1–8 exact fields, or fields: "auto"');
  const cases = source ? input.cases || CASES.filter(c => !c.startsWith('api-') && !c.startsWith('nav-')) : [];
  if ((source && (!Array.isArray(cases) || cases.length < 1 || cases.length > CASES.length || new Set(cases).size !== cases.length || cases.some(c => !CASES.includes(c)))) ||
    (!source && (input.cases !== undefined || input.field !== undefined || input.fields !== undefined)))
    throw new Error(`Campaign cases must be unique selections from: ${CASES.join(', ')}`);
  if (cases.some(c => c.startsWith('api-'))) {
    const api = input.api;
    if (!api || typeof api.path !== 'string' || !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,4}$/.test(api.path) ||
      !Array.isArray(api.args) || api.args.length < 1 || api.args.length > 4 ||
      !Number.isInteger(api.mutationIndex) || api.mutationIndex < 0 || api.mutationIndex >= api.args.length ||
      JSON.stringify(api.args).length > 512) throw new Error('API cases require api.path, up to four JSON arguments, and a mutationIndex');
  }
  const waitMs = input.waitMs === undefined ? 1800 : input.waitMs;
  if (!Number.isInteger(waitMs) || waitMs < 500 || waitMs > 10000) throw new Error('Campaign waitMs must be 500–10000');
  const view = input.view;
  if (!view || (view !== 'reload' && (typeof view !== 'string' || !/^(https?:|file:|app:)/i.test(view))))
    throw new Error('Campaign needs a view URL or "reload" to exercise the saved content');
  if (cases.some(c => c.startsWith('nav-')) && view === 'reload')
    throw new Error('Navigation cases need an explicit view URL so the app can return after a navigation');
  if (input.closeOnDone !== undefined && typeof input.closeOnDone !== 'boolean') throw new Error('closeOnDone must be a boolean');
  if (input.restoreOnDone !== undefined && typeof input.restoreOnDone !== 'boolean') throw new Error('restoreOnDone must be a boolean');
  if (input.windowUrl !== undefined && (typeof input.windowUrl !== 'string' || !/^(https?:|file:|app:)/i.test(input.windowUrl)))
    throw new Error('windowUrl must be a window URL prefix');
  const parseUrl = url => {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('Campaign request URL must be HTTP(S) without embedded credentials');
    return parsed;
  };
  let docxImport;
  if (input.docxImport) {
    const contract = input.docxImport;
    const docxCases = contract.cases || DOCX_CASES;
    if (!['POST', 'PUT'].includes(String(contract.method).toUpperCase()) || !validField(contract.field) ||
      !Array.isArray(docxCases) || !docxCases.length || docxCases.length > DOCX_CASES.length ||
      new Set(docxCases).size !== docxCases.length || docxCases.some(name => !DOCX_CASES.includes(name)))
      throw new Error(`docxImport needs POST/PUT, a multipart field and unique cases from: ${DOCX_CASES.join(', ')}`);
    const url = parseUrl(contract.url);
    const headers = contract.headers || {};
    if (typeof headers !== 'object' || Array.isArray(headers) || Object.entries(headers).some(([key, value]) =>
      !/^[\w-]+$/.test(key) || /^(content-type|content-length|host)$/i.test(key) || typeof value !== 'string' || /[\r\n]/.test(value)))
      throw new Error('Invalid docxImport headers; multipart content type is set by fetch');
    docxImport = { method: String(contract.method).toUpperCase(), url: url.href, field: contract.field, headers, cases: docxCases };
  }
  const docxRoute = docxImport && `${docxImport.method} ${apiRoute(docxImport.url)}`;
  const common = { version: 1, field: fields === 'auto' ? undefined : fields[0], fields, cases, waitMs, view, api: input.api,
    closeOnDone: input.closeOnDone !== false, restoreOnDone: input.restoreOnDone !== false, windowUrl: input.windowUrl, docxImport, docxRoute };
  if (!source) return { ...common, mode: 'docx', route: docxRoute };
  if (input.request) {
    const url = parseUrl(source.url);
    if (typeof source.body !== 'string' || source.body.length > 100000 ||
      !source.body.trim() || (source.headers && (typeof source.headers !== 'object' || Array.isArray(source.headers))))
      throw new Error('Campaign request needs a body string (up to 100 KB) and optional headers object');
    const headers = source.headers || {};
    if (Object.entries(headers).some(([key, value]) => !/^[\w-]+$/.test(key) || typeof value !== 'string' || /[\r\n]/.test(value)))
      throw new Error('Invalid campaign request headers');
    return { ...common, mode: 'request', route: `${method} ${apiRoute(source.url)}`, request: { method, url: url.href, body: source.body, headers } };
  }
  if (typeof source.route !== 'string' || !/^https?:\/\//i.test(source.route)) throw new Error('Capture campaign needs an exact route URL');
  parseUrl(source.route.replaceAll('{id}', '1'));
  return { ...common, mode: 'capture', route: `${method} ${source.route}` };
}

export function loadCampaign(file) {
  return normalizeCampaign(JSON.parse(fs.readFileSync(file, 'utf8')));
}

export function campaignMatch(profile, record) {
  return profile?.mode === 'capture' && record?.replay !== undefined &&
    (!record.status || record.status < 400) &&
    `${String(record.method).toUpperCase()} ${apiRoute(record.url)}` === profile.route &&
    record.fields?.some(field => (profile.fields === 'auto' || (profile.fields || [profile.field]).includes(field.name)) && typeof field.html === 'boolean');
}
