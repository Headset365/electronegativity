// What each finding means in practice, and who could take advantage of it. Shown with every finding in the HTML report
// (and in JSON output), so readers don't have to follow the reference link to judge it.
//
// Routes:
//   content    - content another person can put in front of the user (a shared document, a message, a link, a page the
//                app loads) can exploit it directly
//   escalation - not exploitable on its own, but decides how far injected content gets (from the page to Node.js, the
//                file system or the OS): it raises the impact of any "content" issue
//   network    - needs a position on the network path (Wi-Fi, proxy, a compromised server or CDN)
//   local      - needs access to the user's device: to its files, to start the app, or to the keyboard
//   dependency - known vulnerabilities in outdated software; how they are exploited depends on each advisory
//   server     - another user of the same service, through its server API (authorization gaps, data it hands out)
//   thirdparty - a third-party service the app sends data to (analytics, CDNs, trackers)
//   info       - inventory and coverage, nothing to fix by itself
export const ROUTES = {
  content: 'Shared content',
  escalation: 'Raises impact',
  network: 'Network',
  server: 'Other users (server)',
  thirdparty: 'Third parties',
  local: 'Local access',
  dependency: 'Known vulnerabilities',
  info: 'Information',
};

// keyed by check id without its _JS_CHECK / _HTML_CHECK / _JSON_CHECK / _GLOBAL_CHECK suffix
const CONSEQUENCES = {
  AFFINITY: ['escalation', 'Windows sharing a renderer process are not isolated from each other: script injected into one of them can affect the others.'],
  ALLOWPOPUPS: ['content', 'The content shown in this <webview> can open new windows, e.g. for phishing or to get around navigation limits.'],
  ANGULAR_BIND_HTML_UNSAFE: ['content', 'The bound value is rendered as raw HTML with no escaping: markup stored by another user runs as script in this view (XSS).'],
  ANGULAR_RESOURCE_URL_LIST: ['content', 'AngularJS may load templates from untrusted locations; a template served from there runs with the app\'s privileges.'],
  ANGULAR_SCE_DISABLED: ['content', 'AngularJS escaping is off for the whole app: any bound value containing markup is rendered as HTML (XSS).'],
  ANGULAR_TRUST_HTML: ['content', 'Data is marked as safe HTML or compiled as an AngularJS template: markup or {{ }} expressions in stored content run as code (XSS, template injection).'],
  AUXCLICK: ['content', 'Middle-clicking a link in page content can open windows the app does not control.'],
  AVAILABLE_SECURITY_FIXES: ['dependency', 'The Electron version in use lacks published security fixes; some of them are exploitable by web content (see the advisories).'],
  BLINK_FEATURES: ['escalation', 'Experimental Chromium features are enabled, widening what page content can do.'],
  CERTIFICATE_ERROR_EVENT: ['network', 'Invalid TLS certificates are accepted: someone on the network can impersonate the server and inject content.'],
  CERTIFICATE_PINNING: ['network', 'Without certificate pinning, a certificate from any trusted authority (e.g. a corporate TLS proxy) can intercept the app\'s traffic.'],
  CERTIFICATE_VERIFY_PROC: ['network', 'Certificate verification is overridden: someone on the network can impersonate the server if the check is too lenient.'],
  COMMAND_INJECTION: ['content', 'Data from a page or an IPC message reaches a shell command: content that gets a message to it can run programs on the user\'s machine.'],
  CONTEXT_BRIDGE_EXPOSURE: ['escalation', 'The preload exposes powerful APIs (e.g. raw ipcRenderer) to the page: any script injected into the page (XSS) can use them.'],
  CONTEXT_ISOLATION: ['escalation', 'Page script shares its JavaScript world with the preload: an XSS in this window can tamper with the preload and reach its privileged APIs, often up to Node.js.'],
  CSP: ['escalation', 'Without a Content Security Policy, injected markup can run inline script. A strict CSP is what turns an HTML injection into a harmless one.'],
  CUSTOM_ARGUMENTS: ['escalation', 'Chromium switches that weaken security (e.g. disabling web security or certificate checks) apply to all content the app shows.'],
  DANGEROUS_FUNCTIONS: ['content', 'Code is built from data and run (executeJavaScript, eval, new Function): if the data can come from content, it runs as code.'],
  DEPENDENCY_INVENTORY: ['info', 'The packages the app ships, checked for published advisories.'],
  DEPENDENCY_VULNERABILITIES: ['dependency', 'A package the app ships has published security advisories; check whether the affected feature is reachable from content.'],
  DEVTOOLS: ['local', 'DevTools can be opened in the shipped app: someone at the keyboard can inspect and run code in the app\'s context. Other users\' content cannot use this.'],
  DOWNLOAD: ['content', 'Downloads triggered by page content are saved without asking, or opened automatically: a malicious file can be planted or run.'],
  ELECTRON_VERSION: ['info', 'The Electron version the findings are based on.'],
  END_OF_LIFE_LIBRARY: ['dependency', 'This library no longer receives security fixes: known and future flaws (e.g. sanitizer bypasses) will not be patched.'],
  EXPERIMENTAL_FEATURES: ['escalation', 'Experimental web platform features are enabled, widening what page content can do.'],
  EXPOSED_API: ['info', 'What the preload exposes to pages: everything an XSS in those pages could call.'],
  FILE_HANDLER: ['content', 'Deep links, file associations and command lines handed to the app are attacker-controlled: a link in a shared document or email can trigger this code.'],
  FILE_PROTOCOL: ['escalation', 'Pages with file:// access can read local files if script is ever injected into them.'],
  FUSES: ['local', 'Build hardening left at insecure defaults. It matters to someone who can start or modify the app on the device (e.g. RunAsNode turns it into a Node.js interpreter), not to other users\' content.'],
  PACKAGED_FUSES: ['local', 'Build hardening read from the shipped executable. It matters to someone who can start or modify the app on the device (e.g. RunAsNode turns it into a Node.js interpreter), not to other users\' content.'],
  HTTP_RESOURCES: ['network', 'Content loaded over plain http can be modified by anyone on the network path (Wi-Fi, proxy).'],
  HTTP_RESOURCES_WITH_NODE_INTEGRATION: ['network', 'Plain http content is loaded into a window with Node.js: someone on the network path gets code execution on the machine.'],
  IFRAME_SANDBOX: ['content', 'Embedded frames without a sandbox can run script and navigate the app window; with Node.js integration they can reach Node.js.'],
  INSECURE_CONTENT: ['network', 'Pages served over https may load scripts over http, which the network path can modify.'],
  IPC_SENDER_VALIDATION: ['escalation', 'The IPC handler does not check which page sent the message: script injected into any window, or a foreign page the window navigated to, can call it with the app\'s privileges.'],
  LIMIT_NAVIGATION: ['content', 'Windows can be navigated to any site (e.g. by a link in shared content); that site then runs inside the app window, with its preload and IPC access.'],
  NAVIGATE_ON_DRAG_DROP: ['content', 'Dropping a link or file on the window navigates it there.'],
  NODE_INTEGRATION: ['escalation', 'Page script has full Node.js access: any XSS in this window is code execution on the user\'s machine.'],
  NODE_INTEGRATION_ATTACH_EVENT: ['escalation', 'Node.js integration can be enabled for embedded content: any XSS there is code execution on the user\'s machine.'],
  NODE_TLS_REJECT_UNAUTHORIZED: ['network', 'TLS certificate checks are off for Node.js requests: someone on the network can impersonate the servers the app talks to.'],
  OPEN_EXTERNAL: ['content', 'A URL is handed to the operating system: if page content controls it, a crafted link (file:, smb:, a custom protocol) in shared content can launch programs or leak credentials.'],
  OPEN_PATH: ['content', 'A path is opened with its default program: if page content or an IPC message controls it, it can run an executable or script on the machine.'],
  SHOWITEMINFOLDER: ['content', 'A path is revealed in the file manager; low impact unless page content controls it.'],
  PERMISSION_REQUEST_HANDLER: ['content', 'Without a permission handler, any page (including one reached through a link in shared content) gets camera, microphone, notifications and other permissions automatically.'],
  PLAINTEXT_SECRETS: ['local', 'Secrets are stored unencrypted: other programs or users on the device can read them.'],
  PLUGINS: ['escalation', 'Browser plugins are enabled, adding attack surface for page content.'],
  PRELOAD: ['info', 'A preload script runs with extra privileges in each page: review what it exposes.'],
  PROTOCOL_HANDLER: ['content', 'A custom protocol serves files: crafted URLs in content may read files outside the app (path traversal).'],
  PROTOCOL_PRIVILEGES: ['escalation', 'A custom scheme is privileged (e.g. bypasses the CSP): content served from it is more powerful.'],
  REMOTE_MODULE: ['escalation', 'The remote module gives page script access to main-process objects.'],
  RICH_TEXT_EDITOR: ['content', 'HTML is loaded into a rich-text editor: document content stored by another user is rendered there. It is safe only if the editor and the server filter it.'],
  SANDBOX: ['escalation', 'The renderer is not sandboxed: page content exploiting a Chromium bug escapes to the operating system more easily.'],
  SANITIZER_CONFIG: ['content', 'The HTML sanitizer or editor filter is configured to let script-bearing markup through: stored content can run script (XSS).'],
  SECUREKEYBOARDENTRY: ['local', 'Keystrokes typed into the app (e.g. passwords) can be read by other programs on macOS.'],
  SECURITY_WARNINGS_DISABLED: ['info', 'Electron\'s own security warnings are hidden from developers.'],
  UNSUPPORTED_VERSION: ['dependency', 'This Electron version no longer receives security fixes, including for flaws exploitable by web content.'],
  UNTRUSTED_LOAD_URL: ['content', 'A URL from page content, IPC or a deep link is loaded into an app window: an attacker-chosen site runs inside the app.'],
  UPDATE_SECURITY: ['network', 'Updates fetched without TLS or signature checks can be replaced in transit: code execution for someone on the network path.'],
  WEBGL: ['escalation', 'WebGL adds renderer attack surface; low impact on its own.'],
  WEBSQL: ['escalation', 'WebSQL adds renderer attack surface; low impact on its own.'],
  WEBVIEW: ['escalation', 'A <webview> embeds other content; misconfigured, that content runs with Node.js or preload access.'],
  WEBVIEW_TAG: ['escalation', 'The <webview> tag is enabled: script injected into the page can create webviews with its own settings.'],
  WEB_SECURITY: ['escalation', 'The same-origin policy is off: script in the page can read data from any site and local files.'],
  WINDOW_OPEN_HANDLER: ['content', 'window.open() and target=_blank links in page content open app windows the app does not vet (phishing, getting around navigation limits).'],
  WINDOW_SUMMARY: ['info', 'Each window\'s effective security settings.'],
  WRITE_SHORTCUT: ['local', 'Windows shortcut (.lnk) files are created or changed; only a concern if their target or path comes from page content or IPC.'],
  XSS_SINK: ['content', 'Dynamic data is inserted as HTML: if it can hold content stored by another user, their markup runs as script in this window (XSS).'],

  TRAFFIC_CLEARTEXT_HTTP: ['network', 'The app sent requests over unencrypted http: anyone on the network path (Wi-Fi, proxy) can read and change them, including the responses the app acts on.'],
  TRAFFIC_SECRET_IN_URL: ['network', 'A secret travels in a URL: URLs are kept in proxy and server logs, browser history and Referer headers, where others can read them.'],
  TRAFFIC_AUTH_TO_THIRD_PARTY: ['thirdparty', 'The app\'s own credentials (a cookie, token or key) are sent to another company\'s server, which can then act as the user.'],
  TRAFFIC_USER_INPUT_TO_THIRD_PARTY: ['thirdparty', 'Something the user typed into the app is passed on to a third party: a privacy leak, and a problem if it is personal or confidential data.'],
  TRAFFIC_STATE_CHANGE_NO_AUTH: ['server', 'A request that changes data carries no visible credentials: if the server does not authenticate it some other way, anyone can make it.'],
  TRAFFIC_IDOR_CANDIDATE: ['server', 'An object is addressed by a guessable number: if the server does not check who owns it, another user can read or change it by changing the number (IDOR).'],
  TRAFFIC_REFLECTED_INPUT: ['content', 'A request value comes back in the response: if it is not encoded for where it lands, a crafted link or request injects markup (reflected XSS).'],
  TRAFFIC_BASIC_AUTH: ['network', 'The user\'s password travels, only base64-encoded, with every request: anything that sees one request can reuse it.'],
  TRAFFIC_SECRET_IN_RESPONSE: ['server', 'The server hands a secret to the client: anyone who can make the same request (or read the app\'s cache) gets it.'],
  TRAFFIC_INSECURE_COOKIE: ['escalation', 'Without HttpOnly, script injected into the page can read the session cookie; without Secure, it can be sent over unencrypted http.'],
  TRAFFIC_WS_CLEARTEXT: ['network', 'The WebSocket is unencrypted: anyone on the network path can read and inject messages.'],
  TRAFFIC_WS_SECRET_IN_URL: ['network', 'A secret travels in the WebSocket URL, which ends up in logs.'],
  TRAFFIC_WS_HTML_MESSAGE: ['content', 'The server pushes HTML to the app over a WebSocket, often content another user wrote: rendered as HTML without sanitizing, it runs as script (XSS).'],
  TRAFFIC_WS_SECRET_IN_MESSAGE: ['server', 'A secret is sent in WebSocket messages, where it can be logged or read by whoever receives them.'],
  TRAFFIC: ['info', 'Traffic observed from the app.'],
  RUNTIME_SECRET_IN_CONSOLE: ['local', 'A secret is written to the console: console output is kept in log files and crash reports that other programs and support staff can read.'],
  RUNTIME_UNCAUGHT_EXCEPTION: ['info', 'An error nothing handled: it can leave the app in an odd state, and its stack trace may reveal internals. Check whether content can trigger it.'],
  RUNTIME_CSP_VIOLATION: ['content', 'The Content Security Policy blocked something the page tried to load or run: the policy worked, but find the cause, as injected content is one.'],
  RUNTIME_CERTIFICATE_ERROR: ['network', 'A certificate error happened during the session: check that the app refused the connection.'],
  RUNTIME_CONTEXT_ISOLATION: ['escalation', 'A page ran without context isolation: an XSS in it can reach the preload\'s privileged APIs.'],
  RUNTIME_COVERAGE: ['info', 'IPC channels the session did not exercise.'],
  RUNTIME_CSP: ['escalation', 'A page ran without an effective Content Security Policy: injected markup there can run script.'],
  RUNTIME_DOM_INJECTION: ['content', 'Script-bearing HTML (event handlers, javascript: links) was inserted into a page at runtime: find where it came from; if it came from stored content, it is XSS.'],
  RUNTIME_ENTRY_COVERAGE: ['info', 'Ways content enters the app that the session did not try.'],
  RUNTIME_HTML_ENDPOINT: ['content', 'This endpoint stores HTML sent by the client, which other users\' clients will render: test on the server that it sanitizes or rejects markup, whatever the client sends.'],
  RUNTIME_INSECURE_LOAD: ['network', 'Content was loaded over plain http: the network path can modify it.'],
  RUNTIME_IPC: ['info', 'IPC channels pages used during the session, and from which origins.'],
  RUNTIME_MARKER_SINK: ['content', 'Markup planted as another user\'s content was written into the page as HTML by this code: stored content reaches an HTML sink, which is XSS unless the markup is sanitized first.'],
  RUNTIME_MARKER_SENT: ['info', 'The fields the planted marker was sent in, for checking where it comes back.'],
  RUNTIME_MARKER_OPEN_EXTERNAL: ['content', 'A link in content reached shell.openExternal: whoever writes the content chooses what the operating system opens.'],
  RUNTIME_MARKER_OPEN_PATH: ['content', 'A path from content reached shell.openPath: whoever writes the content chooses which file is opened with its default program.'],
  RUNTIME_MARKER_NAVIGATION: ['content', 'Whether a link in content can navigate an app window (the page then runs with the window\'s preload and IPC access), or was blocked.'],
  RUNTIME_MARKER_NEW_WINDOW: ['content', 'Whether a link in content can open a new app window, or was refused.'],
  RUNTIME_MARKER_IPC: ['escalation', 'Content from other users reaches this IPC channel: its handler must check the sender and validate the value.'],
  RUNTIME_MARKER_COMMAND: ['content', 'Content reached a command line the app runs: whoever writes the content controls part of the command.'],
  RUNTIME_MARKER: ['content', 'Where planted marker content appeared, and whether it came back as live HTML (stored content reaching another user\'s view) or as text.'],
  RUNTIME_NAVIGATION: ['content', 'A window went to another origin during the session: that origin\'s content ran inside the app window, with its preload and IPC access.'],
  RUNTIME_NEW_WINDOW: ['content', 'Page content opened a new app window during the session: check what setWindowOpenHandler allows.'],
  RUNTIME_NODE_INTEGRATION: ['escalation', 'A page ran with Node.js access: any XSS in it is code execution on the machine.'],
  RUNTIME_OPEN_EXTERNAL: ['content', 'The app handed a URL to the operating system during the session: check whether content can choose it.'],
  RUNTIME_OPEN_PATH: ['content', 'The app opened a file with its default program during the session: check whether content can choose it.'],
  RUNTIME_PERMISSION: ['content', 'A permission was granted to a page during the session, without the user being asked if the app has no handler.'],
  RUNTIME_PERMISSION_CHECK: ['content', 'A permission check was allowed for a page automatically: the app has no permission check handler.'],
  RUNTIME_SANDBOX: ['escalation', 'A page ran without the renderer sandbox.'],
  RUNTIME_WEBVIEW: ['escalation', 'A <webview> was attached during the session: check its settings.'],
  RUNTIME_WEB_SECURITY: ['escalation', 'A page ran with web security disabled: script in it can read data from any site.'],
  RUNTIME_WINDOW_COVERAGE: ['info', 'Windows defined in the code that the session never opened.'],
  RUNTIME_WINDOW_SUMMARY: ['info', 'A window observed at runtime and its settings.'],
};

// How to confirm or rule out a finding, keyed like CONSEQUENCES. "Automatic" ones are checked by a watch session with a
// marker (electronegativity --app <install folder>), which prompts for the steps and links the result to the finding.
const MARKER_HTML = 'Automatic: in a watch session (electronegativity --app <install folder>), save content carrying the HTML marker the tool prints, in the fields this code shows, then view it. If the markup reaches this code, the finding is confirmed at this location.';
const MARKER_LINK = 'Automatic: in a watch session, put the link https://example.invalid/<marker> the tool prints into shared content and click it (also Ctrl+click and middle-click). The report shows whether the app navigated, opened a window, handed it to the OS, or blocked it.';
const SETTINGS = 'Automatic: a watch session reports the settings each window really ran with.';
const HOW_TO_VALIDATE = {
  XSS_SINK: MARKER_HTML, ANGULAR_TRUST_HTML: MARKER_HTML, RICH_TEXT_EDITOR: MARKER_HTML, SANITIZER_CONFIG: MARKER_HTML, ANGULAR_BIND_HTML_UNSAFE: MARKER_HTML,
  DANGEROUS_FUNCTIONS: MARKER_HTML, RUNTIME_DOM_INJECTION: MARKER_HTML,
  OPEN_EXTERNAL: 'Automatic: in a watch session, put the link https://example.invalid/<marker> in shared content and click it, then a file:/// link the tool suggests. The report shows whether content reaches openExternal and whether non-web schemes get through.',
  OPEN_PATH: 'Automatic: in a watch session, attach and open the <marker>.txt file the tool writes (or any file whose name carries the marker). The report shows whether a path from content reaches shell.openPath.',
  SHOWITEMINFOLDER: 'Automatic: as for OPEN_PATH, open a file whose name carries the marker during a watch session.',
  LIMIT_NAVIGATION: MARKER_LINK, WINDOW_OPEN_HANDLER: MARKER_LINK, AUXCLICK: MARKER_LINK, UNTRUSTED_LOAD_URL: MARKER_LINK, RUNTIME_NAVIGATION: 'Check where the window went: if the origin is not your app or its sign-in provider, find what sent it there. ' + MARKER_LINK,
  RUNTIME_NEW_WINDOW: MARKER_LINK,
  COMMAND_INJECTION: 'Automatic where a feature passes content on to a command: use the marker there during a watch session; the report says whether it reached a command line.',
  IPC_SENDER_VALIDATION: 'Manual: read the handler and check that it verifies event.senderFrame (its URL or origin) before acting. A watch session lists the origins that used each channel, and whether content carrying the marker reached it.',
  CONTEXT_ISOLATION: SETTINGS, NODE_INTEGRATION: SETTINGS, SANDBOX: SETTINGS, WEB_SECURITY: SETTINGS,
  CSP: 'Automatic: a watch session records the Content Security Policy each page actually got.',
  PERMISSION_REQUEST_HANDLER: 'Automatic: a watch session records the permissions pages were granted.',
  FILE_HANDLER: 'Partly automatic: during a watch session, open a deep link or file association carrying the marker; the report lists the entry points used.',
  RUNTIME_HTML_ENDPOINT: 'Semi-automatic: during a watch session the tool asks you to send this endpoint the marker, then view the content as the second user. Whether the server itself strips markup is best checked with your proxy too.',
  DEVTOOLS: 'Manual, local access only: check that DevTools cannot be opened in the shipped build (the call is behind a development flag). Content from other users cannot use it.',
  WRITE_SHORTCUT: 'Manual: check that the shortcut\'s target and path are fixed values, not taken from IPC or page content. If so, dismiss it: it needs local access.',
  FUSES: 'Manual, local access only: set the fuses in the build (@electron/fuses). Content from other users cannot use them.',
  TRAFFIC_IDOR_CANDIDATE: 'Manual, on a test server: sign in as a second test account and repeat the request with the first account\'s id (replay it from your proxy). The tool never requests other ids.',
  TRAFFIC_STATE_CHANGE_NO_AUTH: 'Manual: replay the request from your proxy without cookies or tokens; it should be refused (401/403).',
  TRAFFIC_REFLECTED_INPUT: 'Manual: replay the request with markup in the parameter (e.g. <b>x</b>) and check whether it comes back unencoded.',
  TRAFFIC_WS_HTML_MESSAGE: MARKER_HTML,
  TRAFFIC_SECRET_IN_RESPONSE: 'Manual: check whether the client needs this value at all, and whether it is scoped to the signed-in user.',
  PACKAGED_FUSES: 'Manual, local access only: set the fuses in the build (@electron/fuses). Content from other users cannot use them.',
};

const baseId = (id) => String(id || '').replace(/_(JS|HTML|JSON|GLOBAL)_CHECK$/, '').replace(/_LOCK_CHECK$/, '');

/** How to confirm or rule out a finding with this check id, or undefined. */
export function validationHint(id) {
  return HOW_TO_VALIDATE[id] || HOW_TO_VALIDATE[baseId(id)];
}

/**
 * { route, label, text } for a finding's check id, or undefined. Upgrade checks (breaking changes between Electron
 * versions) are information.
 */
export function consequenceOf(id) {
  const entry = CONSEQUENCES[id] || CONSEQUENCES[baseId(id)];
  if (entry) return { route: entry[0], label: ROUTES[entry[0]], text: entry[1] };
  if (/_(REMOVAL|DEPRECATION|DEFAULT_CHANGE)$/.test(String(id))) return { route: 'info', label: ROUTES.info, text: 'A breaking change to handle when upgrading Electron.' };
  return undefined;
}
