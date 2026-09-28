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
  ['react', /@license React v(\d+\.\d+\.\d+)/],
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
];

const COMMENTS = /\/\*[\s\S]*?\*\/|\/\/[^\n]*(?:\n\s*\/\/[^\n]*)*/g;

/**
 * Libraries found in a script's text: [{ name, version }], each package version once.
 */
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
  }
  for (const [name, pattern] of SIGNATURES) {
    const match = text.match(pattern);
    if (match) add(name, match[1]);
  }
  return [...found.values()];
}
