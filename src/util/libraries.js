// Front-end libraries recognized inside any script, including bundles that concatenate several of them (vendor.js,
// app.min.js): by the license banners they keep, or by a version string only that library has. Used for the dependency
// inventory, so the libraries a server-hosted front end loads get the same advisory and support checks as npm packages.

// Banners: "<name> v1.2.3" in a comment. Each entry is [npm package, pattern with the version as its first group].
const BANNERS = [
  ['angular', /\bAngularJS v(1\.\d+\.\d+(?:-[\w.]+)?)/],
  ['@angular/core', /@license Angular v(\d+\.\d+\.\d+(?:-[\w.]+)?)/],
  ['jquery', /\bjQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+(?:-[\w.]+)?)/],
  ['jquery-ui', /\bjQuery UI - v(\d+\.\d+\.\d+)/],
  ['jquery-migrate', /\bjQuery Migrate - v(\d+\.\d+\.\d+)/],
  ['bootstrap', /\bBootstrap v(\d+\.\d+\.\d+(?:-[\w.]+)?)/],
  ['dompurify', /\bDOMPurify (\d+\.\d+\.\d+)/],
  // lodash's banner credits Underscore.js too
  ['underscore', /^(?![\s\S]*Lodash)[\s\S]*?\bUnderscore\.js (\d+\.\d+\.\d+)/],
  ['moment', /moment\.js\s*(?:\/\/!)?\s*version\s*:\s*(\d+\.\d+\.\d+)/],
  ['moment-timezone', /moment-timezone\.js\s*(?:\/\/!)?\s*version\s*:\s*(\d+\.\d+\.\d+)/],
  ['handlebars', /\bhandlebars v(\d+\.\d+\.\d+)/i],
  ['knockout', /\bKnockout JavaScript library v(\d+\.\d+\.\d+)/],
  ['tinymce', /\bTinyMCE version (\d+\.\d+\.\d+)|Tiny Technologies[\s\S]*?Version: (\d+\.\d+\.\d+)/],
  ['froala-editor', /\bfroala_editor v(\d+\.\d+\.\d+)/i],
  ['summernote', /\bSummernote v(\d+\.\d+\.\d+)/],
  ['quill', /\bQuill Editor v(\d+\.\d+\.\d+)/],
  ['textangular', /\btextAngular v(\d+\.\d+\.\d+)/i],
  ['angular-ui-bootstrap', /\bangular-ui-bootstrap\b[\s\S]{0,200}?Version: (\d+\.\d+\.\d+)/],
  ['angular-ui-router', /\bState-based routing for AngularJS[\s\S]{0,800}?@version v(\d+\.\d+\.\d+)/],
  ['vue', /\bVue\.js v(\d+\.\d+\.\d+(?:-[\w.]+)?)/],
  ['select2', /\bSelect2 (\d+\.\d+\.\d+)/],
  ['chart.js', /\bChart\.js v(\d+\.\d+\.\d+)/],
  ['popper.js', /\bPopper\.js v(1\.\d+\.\d+)/],
  ['@popperjs/core', /@popperjs\/core v(\d+\.\d+\.\d+)/],
  ['marked', /\bmarked v(\d+\.\d+\.\d+)/],
  ['showdown', /\bshowdown v ?(\d+\.\d+\.\d+)/],
  ['datatables.net', /\bDataTables (\d+\.\d+\.\d+)/],
  ['socket.io-client', /\bSocket\.IO v(\d+\.\d+\.\d+)/],
  ['axios', /\baxios v(\d+\.\d+\.\d+)/],
  ['modernizr', /\bmodernizr (\d+\.\d+\.\d+)/i],
  ['sweetalert2', /\bsweetalert2 v(\d+\.\d+\.\d+)/i],
  ['hammerjs', /\bHammer\.JS - v(\d+\.\d+\.\d+)/],
  ['highlight.js', /\bHighlight\.js v(\d+\.\d+\.\d+)/],
  ['pdfjs-dist', /\bpdfjsVersion = ['"](\d+\.\d+\.\d+)/],
  ['mammoth', /\bmammoth v(\d+\.\d+\.\d+)/i],
];

// Version strings that survive minification, for libraries whose banner is often stripped
const SIGNATURES = [
  ['angular', /full:\s*["'](1\.\d+\.\d+(?:-[\w.]+)?)["'],\s*major:\s*1,\s*minor:\s*\d+,\s*dot:\s*\d+,\s*codeName/],
  ['lodash', /["'](\d+\.\d+\.\d+)["'][\s\S]{0,300}?Unsupported core-js use/],
  ['dompurify', /\.version\s*=\s*["'](\d+\.\d+\.\d+)["']\s*[,;]\s*\w+\.removed\s*=/],
  ['ckeditor4', /\{timestamp:\s*["'][^"']*["'],\s*version:\s*["'](4\.\d+\.\d+)/],
  ['jquery', /\bjquery:\s*["'](\d+\.\d+\.\d+)["']\s*,\s*constructor:/],
  ['moment', /\.version\s*=\s*["'](2\.\d+\.\d+)["'][\s\S]{0,80}?\.fn\s*=[\s\S]{0,200}?\.min\s*=/],
  ['textangular', /textAngularVersion[\s\S]{0,200}?["']v(\d+\.\d+\.\d+)["']/],
  // AngularJS error links carry the version, in every build and in webpack bundles (errors.angularjs.org/1.8.2/)
  ['angular', /errors\.angularjs\.org\/(1\.\d+\.\d+(?:-[\w.]+)?)\//],
  // jQuery's constructor, right after its version: f="3.5.1",E=function(e,t){return new E.fn.init(e,t)}
  ['jquery', /["'](\d+\.\d+\.\d+)["'][\s\S]{0,200}?=\s*function\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*(?:\/\/[^\n]*\s*)*return\s+new\s+\w+\.fn\.init\b/],
  // TinyMCE keeps its version as two fields: majorVersion:"5",minorVersion:"10.2"
  ['tinymce', /majorVersion\s*:\s*["'](\d+)["']\s*,\s*minorVersion\s*:\s*["'](\d+\.\d+)["']/, (m) => `${m[1]}.${m[2]}`],
  ['ckeditor5', /CKEDITOR_VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']/],
  ['jquery-ui', /\.widget\(\s*["']ui\.\w+["']\s*,\s*(?:[\w.$]+\s*,\s*)?\{\s*version\s*:\s*["'](\d+\.\d+\.\d+)["']/],
  // Bootstrap's plugins: Modal.VERSION = '3.4.1' next to its defaults (3.x), or a VERSION getter (4.x, 5.x) in code using .bs. events
  ['bootstrap', /\.VERSION\s*=\s*["'](3\.\d+\.\d+)["']\s*[,;]\s*\w+\.(?:TRANSITION_DURATION|DEFAULTS)\b/],
  ['bootstrap', /(?:key\s*:\s*["']VERSION["']\s*,\s*get\s*:\s*function\s*\(\)\s*\{|get VERSION\s*\(\)\s*\{)\s*return\s*["']?(?:\w+\s*\})?["']?(\d+\.\d+\.\d+)["'][\s\S]*?\.bs\./],
  ['underscore', /exports\._\s*=\s*\w+\)?\s*[,;]\s*\w+\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']/],
  // pdf.js, its version in the document-loading call (getDocument) and the build constants, which minification keeps
  ['pdfjs-dist', /\bdocId\s*:\s*[\w$]+\s*,\s*apiVersion\s*:\s*["'](\d+\.\d+\.\d+)["']/],
  ['pdfjs-dist', /\bpdfjsVersion\s*=\s*["'](\d+\.\d+\.\d+)["']/],
];

// the package of a React banner: " * react-is.production.min.js" → react-is; react-jsx-runtime is part of react
function reactPackage(comment) {
  const file = comment.match(/\b([a-z][\w-]*)\.(?:production|development|profiling)(?:\.min)?\.js\b/);
  if (!file) return 'react';
  return /^react(?:-jsx-runtime|-jsx-dev-runtime)?$/.test(file[1]) ? 'react' : file[1];
}

const COMMENTS = /\/\*[\s\S]*?\*\/|\/\/[^\n]*(?:\n\s*\/\/[^\n]*)*/g;

/**
 * Libraries found in a script's text: [{ name, version }], each package version once.
 */
// The third-party library a file is a copy or chunk of: node_modules/<name>/…, or a bundler chunk named after a known
// library (tabulator-CmBzg3cD.js, mermaid.core-C91UIso6.js, jquery.module-R5Nq7kwZ.js, vendor/leaflet.min.js). `names` are the
// package and library names known for the app (its inventory and the libraries detected in its files).
// third-party components often bundled into Electron renderers, named in chunk file names whether or not the inventory
// lists them (a bundle has no package.json of its own)
export const COMMON_LIBRARIES = ['ckeditor5', 'ckeditor4', 'mermaid', 'mathlive', 'tabulator-tables', 'leaflet', 'maplibre-gl', 'jquery', 'jquery-ui',
  'codemirror', 'monaco-editor', 'katex', 'mathjax', 'excalidraw', 'tldraw', 'pdfjs-dist', 'highlight.js', 'prismjs', 'marked', 'markdown-it', 'dompurify',
  'lodash', 'moment', 'd3', 'echarts', 'chart.js', 'three', 'fullcalendar', 'tinymce', 'quill', 'prosemirror-view', 'xterm', 'react-dom', 'vue', 'cytoscape',
  'plantuml-encoder', 'vis-network', 'elkjs', 'dagre', 'abcjs', 'flowchart.js', 'mind-elixir', 'html2canvas', 'jspdf', 'xlsx', 'mammoth', 'turndown'];
const CHUNK_SUFFIXES = /(?:[.-](?:min|module|core|esm|bundle|umd|prod|production|dist|browser|global))+$/i;
export function libraryOfFile(file, names) {
  const value = String(file || '').replace(/\\/g, '/');
  const modules = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(value);
  if (modules) return modules[1];
  // a hash that names a build, not a word: it has a digit or a capital letter (maplibre-gl keeps its name)
  const base = value.split('/').pop().replace(/\.[cm]?js$/i, '').replace(/[-.](?=[A-Za-z0-9_-]{8,20}$)(?=[^-.]*[0-9A-Z])[A-Za-z0-9_-]{8,20}$/, '').replace(CHUNK_SUFFIXES, '').toLowerCase();
  if (base.length < 4 || /^(index|main|app|vendor|chunk|common|runtime|polyfills?)$/.test(base)) return undefined;
  const squash = s => s.replace(/^@[^/]+\//, '').replace(/[-_.]/g, '');
  for (const name of names) {
    const n = String(name).toLowerCase();
    const short = n.replace(/^@[^/]+\//, '');
    if (short.length < 4) continue;
    if (base === short || squash(base) === squash(short) || base.startsWith(`${short}-`) || short.startsWith(`${base}-`)) return name;
  }
  return undefined;
}

export function detectLibraries(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const found = new Map();
  const add = (name, version) => { if (version && !found.has(`${name}@${version}`)) found.set(`${name}@${version}`, { name, version }); };
  for (const [comment] of text.matchAll(COMMENTS)) {
    if (!/\d+\.\d+\.\d+/.test(comment)) continue;
    for (const [name, pattern] of BANNERS) {
      const match = comment.match(pattern);
      if (match) add(name, match.slice(1).find(Boolean));
    }
    // React's banners name the file they head: react-is, scheduler and react-dom carry their own versions
    const react = comment.match(/@license React v(\d+\.\d+\.\d+)/);
    if (react) add(reactPackage(comment), react[1]);
  }
  for (const [name, pattern, version = (m) => m[1]] of SIGNATURES) {
    const match = text.match(pattern);
    if (match) add(name, version(match));
  }
  // pdf.js before 4.2.67 runs a crafted font's code (CVE-2024-4367) unless the app turns isEvalSupported off
  for (const library of found.values())
    if (library.name === 'pdfjs-dist' && /\bisEvalSupported\s*[:=]\s*(?:!1|false)\b/.test(text))
      library.note = 'isEvalSupported is turned off in this file, which mitigates CVE-2024-4367 if it applies to every document the app opens; verify';
  return [...found.values()];
}
