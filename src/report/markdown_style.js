// House style of the client findings: titles, opening paragraphs, the note on the limits of testing, and the factual
// evidence sentence for each check. Australian English, impersonal voice ("Testing identified that…").

// finding titles: problem statements (earlier reports used the names on the left; --rerender maps them)
export const TITLES = {
  'Renderer Isolation Weakened': 'Insufficient Renderer Process Isolation',
  'Chromium Security Features Disabled': 'Browser Security Controls Disabled',
  'Privileged APIs Exposed to Untrusted Content': 'Privileged Functionality Exposed to Web Content',
  'IPC Handlers Trust Renderer Input': 'Insufficient Validation of Inter-Process Messages',
  'Unsafe Hand-off of URLs and Files to the Operating System': 'Unvalidated URLs and Files Passed to the Operating System',
  'Code or Command Execution from Untrusted Data': 'Command or Code Execution from Variable Input',
  'Microsoft Word Integration': 'Insecure Microsoft Word Integration',
  'Deep Link, Protocol and File Association Handling': 'Insecure Handling of Deep Links and File Associations',
  'Insufficient Navigation and Window Controls': 'Insufficient Navigation and New Window Restrictions',
  'Missing Permission Handlers': 'Permissive Browser Permission Handling',
  'Cross-Site Scripting Exposure in Content Rendering': 'Cross-Site Scripting in Content Rendering',
  'Missing or Weak Content Security Policy': 'Missing or Insufficient Content Security Policy',
  'Document Parsing Risks': 'Insecure Processing of Untrusted Documents',
  'Insecure Electron Fuse Configuration': 'Insecure Electron Fuse Configuration',
  'Application Code Not Protected Against Inspection or Tampering': 'Application Code Not Protected Against Tampering or Disclosure',
  'Executable Signing and Exploit Mitigations (hardening)': 'Missing Code Signing or Exploit Mitigations',
  'Insecure Update Mechanism': 'Insecure Software Update Mechanism',
  'Development and Debugging Features in Production': 'Debugging Features Enabled in Production',
  'Hard-coded Secrets in the Application Package': 'Hard-coded Secrets in the Application Package',
  'Sensitive Data Stored Insecurely': 'Sensitive Data Stored Without Adequate Protection',
  'Certificate Pinning Not Implemented (hardening)': 'Certificate Pinning Not Implemented',
  'Insecure Transport and Certificate Validation': 'Insecure Network Transport and Certificate Validation',
  'Sensitive Data Exposed in Network Traffic': 'Sensitive Data Exposed in Network Traffic',
  'Local Services Accessible Without Adequate Access Control': 'Local Services Accessible Without Adequate Access Control',
  'SQL Injection in Local Database Queries': 'SQL Injection in Local Database Queries',
  'Application Destinations Controlled by Web Content': 'Application Destinations Controlled by Web Content',
  'Known Malicious Package': 'Known Malicious Software Package',
  'Other Security Observations': 'Additional Security Observations',
};
const T = TITLES;

// the opening paragraph of each finding ({app}: the application's name)
export const LEADS = {
  [T['Renderer Isolation Weakened']]: 'Testing identified that one or more windows in {app} run web content with reduced isolation from the operating system and from the application’s privileged code.',
  [T['Chromium Security Features Disabled']]: 'Testing identified that {app} disables or weakens security protections built into the Chromium browser engine on which Electron applications are based.',
  [T['Privileged APIs Exposed to Untrusted Content']]: 'Testing identified that {app} exposes privileged functionality, or a shared session, to web content that should not have access to it.',
  [T['IPC Handlers Trust Renderer Input']]: 'Testing identified that inter-process communication (IPC) handlers in the {app} main process act on messages from the user interface without sufficient validation. The main process has full access to the operating system, so its handlers form the boundary between web content and the user’s computer.',
  [T['Unsafe Hand-off of URLs and Files to the Operating System']]: 'Testing identified that {app} passes URLs or file paths to the operating system to open without sufficient validation.',
  [T['Code or Command Execution from Untrusted Data']]: 'Testing identified that {app} runs operating system commands, or evaluates code, built from variable input.',
  [T['Microsoft Word Integration']]: 'Testing identified weaknesses in how {app} opens documents in Microsoft Word.',
  [T['Deep Link, Protocol and File Association Handling']]: 'Testing identified that {app} acts on input received through deep links, custom protocols or file associations without sufficient validation. This input can come from any web page, email or file a user opens.',
  [T['Insufficient Navigation and Window Controls']]: 'Testing identified that windows in {app} are not sufficiently restricted from navigating to, or opening, content outside the application.',
  [T['Missing Permission Handlers']]: 'Testing identified that {app} grants browser permissions to web content without checking which page is asking or which permission is requested.',
  [T['Cross-Site Scripting Exposure in Content Rendering']]: 'Testing identified that {app} renders dynamic content as HTML in a way that could allow cross-site scripting (XSS). In an Electron application, script injected into a window can have access beyond the page itself, depending on the window’s configuration.',
  [T['Missing or Weak Content Security Policy']]: 'Testing identified that the pages of {app} are not protected by an effective Content Security Policy (CSP), the browser mechanism that limits the scripts and other resources a page can load and run.',
  [T['Document Parsing Risks']]: 'Testing identified that {app} processes documents from external sources in a way that exposes it to malicious files.',
  [T['Insecure Electron Fuse Configuration']]: 'Testing identified that the Electron fuses of {app}, security settings fixed in the executable when the application is packaged, leave hardening features disabled.',
  [T['Application Code Not Protected Against Inspection or Tampering']]: 'Testing identified that the code of {app} is not protected against inspection or modification after it is installed.',
  [T['Executable Signing and Exploit Mitigations (hardening)']]: 'Testing identified that distributed files of {app} lack a publisher signature or operating system exploit mitigations.',
  [T['Insecure Update Mechanism']]: 'Testing identified weaknesses in how {app} obtains and verifies software updates.',
  [T['Application Destinations Controlled by Web Content']]: 'Testing identified that {app} lets content in an application window choose the addresses its privileged windows load and the servers that receive the user’s credentials.',
  [T['SQL Injection in Local Database Queries']]: 'Testing identified that {app} builds database queries by inserting values into the statement text instead of passing them as parameters.',
  [T['Local Services Accessible Without Adequate Access Control']]: 'Testing identified that {app} runs a local network service whose access controls are weaker than its data requires: authentication is skipped in the desktop build, or other web origins are allowed to read its responses.',
  [T['Development and Debugging Features in Production']]: 'Testing identified that the production build of {app} retains development or debugging features.',
  [T['Hard-coded Secrets in the Application Package']]: 'Testing identified values resembling credentials embedded in the distributed files of {app}.',
  [T['Sensitive Data Stored Insecurely']]: 'Testing identified that {app} stores data on the device without adequate protection.',
  [T['Certificate Pinning Not Implemented (hardening)']]: 'Testing identified that {app} does not pin the certificates or public keys of the services it connects to. Certificates are validated against the certificate authorities the operating system trusts; pinning is an additional safeguard whose need depends on the threat model.',
  [T['Insecure Transport and Certificate Validation']]: 'Testing identified that {app} communicates over unencrypted connections or does not properly validate server certificates.',
  [T['Sensitive Data Exposed in Network Traffic']]: 'Testing identified that the network traffic of {app} exposes sensitive data or sends it to unintended recipients.',
  [T['Known Malicious Package']]: 'Testing identified a software package version known to be malicious among the dependencies of {app}.',
  [T['Other Security Observations']]: 'Testing identified the following additional security observations in {app}.',
};

// the limits of testing, stated once per finding
export const NOTES = {
  [T['Renderer Isolation Weakened']]: 'The impact described requires an attacker to first run script in an affected window, for example through a separate cross-site scripting flaw or a compromised remote resource.',
  [T['Chromium Security Features Disabled']]: 'The impact depends on the content loaded in the affected windows. The settings themselves were confirmed in the application’s configuration.',
  [T['Privileged APIs Exposed to Untrusted Content']]: 'Exploitation requires script controlled by an attacker to run in a page that has access to the exposed functionality.',
  [T['IPC Handlers Trust Renderer Input']]: 'Exploitation requires an attacker to first run script in an application window, or to load their own content in one.',
  [T['Unsafe Hand-off of URLs and Files to the Operating System']]: 'Exploitation requires an attacker to control the URL or path passed to the operating system, for example through a link in content shown by the application, and in most cases a user to click it.',
  [T['Code or Command Execution from Untrusted Data']]: 'Exploitation requires an attacker to control the input that reaches the affected function.',
  [T['Microsoft Word Integration']]: 'The impact depends on how documents reach the application and on the Microsoft Office policies applied to users’ devices.',
  [T['Deep Link, Protocol and File Association Handling']]: 'Exploitation requires a user to open a crafted link or file, for example from a web page or an email.',
  [T['Insufficient Navigation and Window Controls']]: 'The impact depends on the privileges of the affected windows, and is greatest where they have Node.js integration or a privileged preload script.',
  [T['Missing Permission Handlers']]: 'Exploitation requires content controlled by an attacker to be loaded in an application window.',
  [T['Cross-Site Scripting Exposure in Content Rendering']]: 'Exploitation requires an attacker to be able to supply the content that is rendered, for example by saving it for another user to view.',
  [T['Missing or Weak Content Security Policy']]: 'A Content Security Policy is an additional layer of defence. Its absence does not create an injection flaw, but it increases the impact of one.',
  [T['Document Parsing Risks']]: 'Exploitation requires a crafted document to reach the affected processing and, for parser flaws, a vulnerability in the parser itself.',
  [T['Insecure Electron Fuse Configuration']]: 'These settings matter to someone who can run or modify the application on the device. They do not provide remote access on their own.',
  [T['Application Code Not Protected Against Inspection or Tampering']]: 'These weaknesses matter to someone who can obtain or modify the installed application. They do not provide remote access on their own.',
  [T['Executable Signing and Exploit Mitigations (hardening)']]: 'This is a hardening observation. It does not indicate that the distributed files have been modified.',
  [T['Insecure Update Mechanism']]: 'Exploitation requires an attacker to be able to intercept or substitute the update traffic.',
  [T['SQL Injection in Local Database Queries']]: 'Exploitation requires the attacker to influence a value used in a query, for example by running script in an application window that can send the message that triggers it. The impact depends on what the database holds beyond the records the interface already shows the user.',
  [T['Application Destinations Controlled by Web Content']]: 'Exploitation requires an attacker to run script in an application window that can send the message, for example through a cross-site scripting flaw, or to have their own content loaded in such a window.',
  [T['Local Services Accessible Without Adequate Access Control']]: 'Exploitation requires the attacker to reach the service: through a web page the user opens, a browser extension, another program on the same computer or, where the port is bound to every interface, the local network.',
  [T['Development and Debugging Features in Production']]: 'These features are generally available only to someone already using the application on the device.',
  [T['Hard-coded Secrets in the Application Package']]: 'The impact depends on whether the value is a live credential and on the access it grants, which should be confirmed with its owner.',
  [T['Sensitive Data Stored Insecurely']]: 'Exploitation requires access to the user’s profile on the device, or to a backup of it.',
  [T['Certificate Pinning Not Implemented (hardening)']]: 'This is a hardening observation. Certificates are still validated, and interception requires a certificate trusted by the device.',
  [T['Insecure Transport and Certificate Validation']]: 'Exploitation requires an attacker to be positioned on the network path between the application and its servers.',
  [T['Sensitive Data Exposed in Network Traffic']]: 'The impact depends on the sensitivity of the data and on who can access the logs or destinations concerned.',
  [T['Known Malicious Package']]: 'The presence of the package does not confirm that it ran. The build and installation history should be reviewed to determine the extent of any exposure.',
  [T['Other Security Observations']]: 'The impact depends on whether an attacker can reach the affected functionality.',
};

const lower = (text) => String(text || '').replace(/^[A-Z](?![A-Z])/, c => c.toLowerCase());
// the factual part a scanner description adds after its generic text: "(…)" at the end, or what follows ": "
function detailOf(description) {
  const text = String(description || '').trim();
  const bracket = text.match(/\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$/);
  if (bracket) return bracket[1].trim();
  const colon = text.indexOf(': ');
  return colon > 0 ? text.slice(colon + 2).replace(/\.$/, '').trim() : '';
}
const code = (value) => `\`${String(value).replace(/`/g, '')}\``;
const channel = (i) => i.properties?.channel ? ` for the ${code(i.properties.channel)} channel` : '';
const source = (i) => {
  const from = /(?:the value|data) comes? from (.+?)(?: and is not validated)?$/.exec(detailOf(i.description)) || /receives data from (.+)$/.exec(detailOf(i.description));
  return from ? from[1] : '';
};
const shell = (api) => (i) => source(i) ? `the value passed to ${code(api)} comes from ${source(i)} and is not validated` : `a value is passed to ${code(api)} without validation`;

// the evidence sentence for a static check: what the code or configuration shows ("This shows that …")
const STATIC = {
  NODE_INTEGRATION: () => 'Node.js integration is enabled for the window',
  NODE_INTEGRATION_ATTACH_EVENT: () => 'Node.js integration is enabled for an embedded web view',
  HTTP_RESOURCES_WITH_NODE_INTEGRATION: (i) => { const urls = (i.properties?.urls || []).slice(0, 3).map(code).join(', ');
    return i.properties?.loopbackOnly
      ? `Node.js integration is enabled in windows that load the application’s own local server over HTTP${urls ? ` (${urls})` : ''}; the content does not cross the network, but any other program on the computer that can bind the same port could serve it instead`
      : `Node.js integration is enabled while resources are loaded over unencrypted HTTP${urls ? ` (${urls})` : ''}`; },
  CONTEXT_ISOLATION: () => 'context isolation is disabled for the window',
  SANDBOX: () => 'the renderer sandbox is not enabled for the window',
  PRELOAD: () => 'a preload script runs in a window without context isolation, so page script shares its environment',
  REMOTE_MODULE: () => 'the remote module is enabled',
  AFFINITY: () => 'process affinity is set for the window',
  WEB_SECURITY: () => 'web security, which enforces the same-origin policy, is disabled for the window',
  INSECURE_CONTENT: () => 'content loaded over unencrypted HTTP is allowed to run on HTTPS pages',
  CUSTOM_ARGUMENTS: (i) => /ignore-certificate-errors/.test(i.description) ? 'the `--ignore-certificate-errors` command-line switch is applied, which disables certificate validation for the whole application'
    : detailOf(i.description) ? `the command-line switch ${code(detailOf(i.description))} is applied` : 'a security-relevant command-line switch is applied',
  EXPERIMENTAL_FEATURES: () => 'experimental Chromium features are enabled',
  BLINK_FEATURES: () => 'additional Blink rendering engine features are enabled',
  WEBGL: () => 'WebGL is explicitly enabled',
  WEBSQL: () => 'WebSQL is explicitly enabled',
  PLUGINS: () => 'browser plugins are enabled',
  NAVIGATE_ON_DRAG_DROP: () => 'dropping a file or link onto the window navigates to it',
  SECURITY_WARNINGS_DISABLED: () => 'Electron security warnings are disabled',
  SECUREKEYBOARDENTRY: () => 'password fields are used without Secure Keyboard Entry being enabled on macOS',
  CONTEXT_BRIDGE_EXPOSURE: (i) => { const what = /exposes (\S+)/.exec(detailOf(i.description)); return what ? `the preload script exposes ${code(what[1])} to page script through the context bridge` : 'the preload script exposes privileged Electron or Node.js functionality to page script through the context bridge'; },
  WINDOW_SESSION: (i) => { const d = detailOf(i.description); return d ? `windows that display different content share a session (${d.replace(/\s*\([^)]*\)/, '')})` : 'windows that display different content share a session'; },
  IPC_SENDER_VALIDATION: (i) => `the handler${channel(i)} does not validate the sender of the message before acting on it`,
  IPC_HANDLER: (i) => { const kind = i.properties?.issue;
    if (kind === 'credential') return `the handler${channel(i)} returns a credential${i.properties?.credential ? ` (${code(i.properties.credential)})` : ''} to the page that sends the message`;
    if (kind === 'window-target') return `the handler${channel(i)} acts on a window chosen by the page through its identifier, so one window can control another`;
    if (kind === 'write-then-open') return `the handler${channel(i)} writes a file at a path built from the values the page sends, then opens it with its default program`;
    const op = /uses (\w+) with arguments/.exec(i.description || ''); const what = { processes: 'to start a process', shell: 'to Electron’s `shell` module', files: 'to file system operations', fs: 'to file system operations', network: 'to network requests' }[op && op[1]] || 'to a sensitive operation'; return `the handler${channel(i)} passes values received from the user interface ${what} without validating them`; },
  IPC_RPC_PROCEDURE: (i) => { const p = i.properties || {}; const what = (p.capabilities || []).join(', ') || 'performs a privileged operation';
    return `the ${code(p.procedure || 'listed')} procedure, which any page that reaches the inter-process channel can call, ${what}${p.takesInput ? ' using input supplied by the page' : ''}`; },
  AUTH_MODE_BYPASS: (i) => { const routes = (i.properties?.routes || []).slice(0, 4); return `authentication of the local service is skipped in one mode of the application${routes.length ? `, for routes such as ${routes.map(code).join(', ')}` : ''}`; },
  NODE_TLS_REJECT_UNAUTHORIZED_SCRIPT: (i) => `the launcher script ${code(i.properties?.script || 'shipped with the application')} disables certificate validation for the application’s Node.js connections`,
  CUSTOM_ARGUMENTS_SCRIPT: (i) => `the launcher script ${code(i.properties?.script || 'shipped with the application')} ${String(i.properties?.setting || 'weakens a security setting').replace(/^starts the app/, 'starts the application').replace(/^runs the executable/, 'runs the executable')}`,
  SQL_INJECTION: (i) => { const p = i.properties || {}; const values = (p.values || []).slice(0, 3).map(code).join(', ');
    if (p.secondOrder) return `a database query is built by inserting ${values || 'values'} into its text (${code(p.statement || 'statement')}); ${(p.values || []).length > 1 ? 'these values were' : 'the value was'} read by an earlier query whose rows were chosen by ${p.chosenBy || 'the caller'} (second-order)`;
    return `a database query is built by inserting ${values || 'values'} into its text (${code(p.statement || 'statement')})${p.source ? `, with values from ${p.source}` : ''}`; },
  RELATIVE_EXECUTABLE_PATH: (i) => `a program or script is started from ${code(i.properties?.path || 'a relative path')}, a path resolved against the folder the application was started from`,
  IPC_STATE_DESTINATION: (i) => { const p = i.properties || {}; const files = list => list.slice(0, 3).map(code).join(', ');
    const uses = [p.loads?.length && `windows load that address in ${files(p.loads)}`, p.credentialed?.length && `requests carrying the user’s access token are sent to it from ${files(p.credentialed)}`].filter(Boolean);
    return `the ${code(p.channel || 'listed')} message lets the page set the address application windows load${p.credentialed?.length ? ' and the server that receives the user’s access token' : ''}${p.setter ? ` (through ${code(p.setter)})` : ''}${uses.length ? `; ${uses.join(', and ')}` : ''}`; },
  IPC_FILE_ACCESS: () => 'a file path chosen by the user interface, a navigation or a deep link reaches the file system without validation',
  IPC_CHANNEL_MAP: (i) => `no reviewed user interface code sends the ${code(i.properties?.channel || 'listed')} channel that the main process handles`,
  OPEN_EXTERNAL: shell('shell.openExternal()'),
  OPEN_PATH: shell('shell.openPath()'),
  SHOWITEMINFOLDER: shell('shell.showItemInFolder()'),
  WRITE_SHORTCUT: shell('shell.writeShortcutLink()'),
  DOWNLOAD: () => 'downloads are saved without validating their destination',
  COMMAND_INJECTION: (i) => { const m = /(\w+) receives data from (.+)$/.exec(detailOf(i.description)); return m ? `${code(`${m[1]}()`)} runs a command built from data received from ${m[2]}` : 'a process is started with a command built from variable input'; },
  DANGEROUS_FUNCTIONS: () => 'a string built from variable input is evaluated as code',
  DYNAMIC_MODULE: () => 'a module is loaded from a path built from variable input',
  WORD_LAUNCH: () => 'Microsoft Word is started with a command line or document path built from variable values',
  FILE_HANDLER: () => 'input received through a custom protocol or file association is used without validation',
  INSTALLER_FILE_HANDLER: () => 'the installer registers a custom protocol or file association whose input reaches the application',
  PROTOCOL_HANDLER: (i) => /containment/.test(i.description || '') ? 'a custom protocol handler serves files using a path taken from the request, without checking that the path stays within the intended folder' : 'a custom protocol handler uses request data without validation',
  PROTOCOL_PRIVILEGES: () => 'a custom protocol is registered with elevated privileges',
  FILE_PROTOCOL: () => 'local content is loaded over `file:` URLs, which have additional privileges in Electron',
  UNTRUSTED_LOAD_URL: () => 'an application window loads a URL taken from external input',
  LIMIT_NAVIGATION: (i) => i.properties?.hostOnly ? 'the navigation allowlist compares host names only, so an allowed host is also accepted over unencrypted `http:`, where its page loads with the window’s privileges'
    : /never calls event\.preventDefault/.test(i.description || '') ? 'the `will-navigate` handler never blocks a navigation, so windows can navigate to any destination'
      : /Missing will-navigate/i.test(i.description || '') ? 'no `will-navigate` handler restricts where windows can navigate' : 'navigation is not restricted to the application’s own pages',
  NAVIGATION_REDIRECT: () => 'server redirects are not restricted, as no handler blocks redirects to other destinations',
  WINDOW_OPEN_HANDLER: (i) => /every URL is allowed/.test(i.description || '') ? 'the `setWindowOpenHandler()` handler allows every URL to open a new window' : 'new windows are allowed without restriction',
  AUXCLICK: () => 'middle-clicking a link can open it in a new window',
  ALLOWPOPUPS: () => 'a `<webview>` tag allows popups',
  WEBVIEW_TAG: () => 'the `<webview>` tag is enabled',
  WEBVIEW: () => 'the `<webview>` tag is enabled without a `will-attach-webview` handler to check embedded content before it is created',
  IFRAME_SANDBOX: (i) => i.properties?.sameOrigin ? 'an iframe created in code displays generated HTML (`srcdoc`) without the `sandbox` attribute, so its content runs in the application’s own origin' : 'an iframe displays content without the `sandbox` attribute',
  PERMISSION_REQUEST_HANDLER: (i) => /grants every permission/.test(i.description || '') ? 'the permission request handler grants every permission to every origin'
    : /Missing/.test(i.description || '') ? 'no permission request handler is set, so permission requests are granted by default' : 'the permission request handler does not restrict which permissions are granted',
  XSS_SINK: (i) => { const m = /^(\w+(?:\.\w+)?) with (.+)$/.exec(detailOf(i.description)); return m ? `${code(m[1])} is assigned ${m[2].replace(/^a /, 'a ')}, so the content is inserted as HTML` : 'dynamic content is inserted into the page as HTML'; },
  HTML_TEMPLATE: (i) => { const values = (i.properties?.values || []).map(v => String(v).replace(/ \((?:attribute value|element text)\)$/, '')); const shown = [...new Set(values)].slice(0, 4).map(code).join(', ');
    return shown ? `HTML is built by inserting ${shown} into a markup template without escaping` : 'HTML is built by inserting values into a markup template without escaping'; },
  RICH_TEXT_EDITOR: () => 'HTML is loaded into a rich-text editor without being sanitised on the server',
  SANITIZER_CONFIG: () => 'an HTML sanitiser or editor is configured to allow script-bearing markup',
  ANGULAR_SCE_DISABLED: () => 'AngularJS Strict Contextual Escaping is disabled for the whole application',
  ANGULAR_RESOURCE_URL_LIST: () => 'the AngularJS resource URL allow list permits templates from untrusted locations',
  ANGULAR_TRUST_HTML: () => 'AngularJS is instructed to trust dynamic markup (`$sce.trustAsHtml` or `$compile`), bypassing its escaping',
  ANGULAR_BIND_HTML_UNSAFE: () => '`ng-bind-html-unsafe` renders its expression as raw HTML',
  CSP: () => 'no Content Security Policy is defined for the application’s pages',
  CSP_DIRECTIVES: (i) => { const d = detailOf(i.description); return d ? `the Content Security Policy is incomplete: ${d}` : 'the Content Security Policy permits unsafe sources or omits protective directives'; },
  RENDERER_INPUT: (i) => { const event = { 'file-reader': 'a file read by the page', paste: 'pasted content', drop: 'dropped content', change: 'a file chosen in a file picker', message: 'a message posted to the page' }[i.properties?.event] || 'content received by the page';
    const reached = /input reaches ([^;]+)/.exec(i.description || ''); return `${event} reaches ${reached ? reached[1] : 'a sensitive operation'} without validation`; },
  DOCUMENT_PIPELINE: (i) => { const d = detailOf(i.description); return d ? `documents are processed by ${d}` : 'documents from external sources are processed by a parser or converter'; },
  FUSES: (i) => /No Electron Fuses configuration/i.test(i.description || '') ? 'no Electron fuse configuration is applied when the application is packaged, so `RunAsNode`, `NODE_OPTIONS`, `--inspect` and archive integrity remain at their insecure defaults' : 'the Electron fuse configuration leaves security hardening features disabled',
  PACKAGED_FUSES: (i) => i.properties?.fuse ? `the ${code(i.properties.fuse)} fuse is ${i.properties.value === true || i.properties.value === 'enabled' ? 'enabled' : i.properties.value === false || i.properties.value === 'disabled' ? 'disabled' : 'in an insecure state'} in the shipped executable` : 'the shipped executable’s fuses leave security hardening features disabled',
  ASAR_INTEGRITY: () => 'the application archive is not protected by an integrity hash embedded in the executable',
  SOURCE_MAP_SHIPPED: () => 'source maps are included in the distributed application',
  CODE_SIGNING: (i) => i.properties?.status ? `the file does not have a valid publisher signature (status: ${i.properties.status})` : 'the file does not have a valid publisher signature',
  BINARY_HARDENING: (i) => { const d = detailOf(i.description); return d ? `exploit mitigations are missing (${d})` : 'operating system exploit mitigations are missing from the file'; },
  UPDATE_SECURITY: (i) => { const d = detailOf(i.description); return d ? `the update configuration is insecure: ${d}` : 'the update configuration is insecure'; },
  DEVTOOLS: (i) => /always opened/.test(i.description || '') ? 'the application opens the developer tools in every build, including production builds' : 'the application can open the developer tools in production builds',
  DEVELOPMENT_CODE: () => 'development-only code is included in the production build',
  DEBUG_LOGGING: () => 'verbose logging is enabled in the production build',
  HARDCODED_SECRET: (i) => i.properties?.kind ? `a value resembling a credential (${i.properties.kind}) is embedded in the application` : 'a value resembling a credential is embedded in the application',
  PLAINTEXT_SECRETS: () => 'a secret is stored without encryption',
  SECRET_FILE_WRITE: () => 'a secret is written to a file without encryption',
  ELECTRON_STORE_ENCRYPTION: () => '`electron-store` keeps its data unencrypted',
  COOKIE_FLAGS: () => 'a cookie is set without the security attributes appropriate to its use',
  CERTIFICATE_VERIFY_PROC: (i) => /every certificate is accepted/.test(i.description || '') ? 'the certificate verification handler accepts every certificate, which disables certificate validation' : 'a certificate verification handler overrides certificate validation',
  CERTIFICATE_ERROR_EVENT: (i) => /every invalid certificate is accepted/.test(i.description || '') ? 'the `certificate-error` handler accepts every invalid certificate' : 'the `certificate-error` handler can accept invalid certificates',
  NODE_TLS_REJECT_UNAUTHORIZED: (i) => { const script = /npm script "([^"]+)"/.exec(i.description || ''); return script ? `certificate validation for Node.js connections is disabled in the ${code(script[1])} npm script. This applies only when the application is started from source with that script, typically during development, and not to the packaged application` : 'certificate validation is disabled for Node.js connections'; },
  HTTP_RESOURCES: (i) => { if (i.properties?.loopback) return `the application loads its own local server over HTTP (${code(i.properties.url)}); the traffic does not leave the computer, but another program that takes the port first could serve its own content`;
    const d = detailOf(i.description); return d && /https?:/i.test(d) ? `a resource is loaded over unencrypted HTTP (${d})` : 'content is loaded over unencrypted HTTP'; },
  CERTIFICATE_PINNING: () => 'no certificate pinning is implemented for the application’s connections',
  MALICIOUS_DEPENDENCY: (i) => i.properties?.package ? `the dependencies include ${code(`${i.properties.package}${i.properties.version ? `@${i.properties.version}` : ''}`)}, a version identified as malicious` : 'the dependencies include a package version identified as malicious',
};

// runtime and traffic observations: their own description, without the caveats and instructions to the tester (those go
// to the tester notes)
const CAVEATS = /\s*(?:[.;:]\s*|\s)(?:This (?:establishes|confirms|does not)|Script execution (?:and|remains)|Whether |Path traversal|The handler['’]s|[Cc]heck (?:that|the|what|which|whether)|[Vv]erify |[Rr]eview (?:which|the|whether)|Delivery to|Identity with|Command injection|Cross-account|Exploitability|only https?\(s\)|URLs end up in|Authentication and origin enforcement|the storage provider issues)[\s\S]*$/;
// well-known Windows groups an access control entry can name
const GROUPS = { 'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users', 'S-1-5-32-545': 'Users', 'S-1-5-4': 'INTERACTIVE', 'S-1-5-32-546': 'Guests', 'S-1-2-0': 'LOCAL' };
const groupName = e => GROUPS[e?.sid] || GROUPS[e?.identity] || String(e?.identity || e?.sid || 'a broad group').replace(/^BUILTIN\\/i, '');
// the access control list of install folders: which of them other accounts can write to
export function aclFact(issues, shown = folder => folder) {
  const writable = issues.filter(i => (i.properties?.broadWrite || []).length);
  if (!writable.length) return undefined;
  const paths = writable.map(i => i.properties.path).filter(Boolean).map(shown);
  const groups = [...new Set(writable.flatMap(i => i.properties.broadWrite.map(groupName)))].map(name => name.replace(/[\\`*_[\]<>]/g, ''));
  const list = items => items.length === 1 ? items[0] : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
  return `the access control ${paths.length === 1 ? 'list' : 'lists'} of ${list(paths)} ${paths.length === 1 ? 'grants' : 'grant'} write access to the ${list(groups)} ${groups.length === 1 ? 'group' : 'groups'}, which other accounts on the computer belong to; deny entries and inherited permissions were not assessed`;
}

export function runtimeFact(i) {
  if (/^WINDOWS_INSTALL_PERMISSIONS/.test(i.id) && i.properties?.path) return aclFact([i]);
  let text = String(i.description || '').replace(/^(?:Observed|Seen) at runtime:\s*/i, '').replace(CAVEATS, '').replace(/\s+/g, ' ').trim().replace(/[.;:]$/, '');
  text = text.replace(/\b(\d+) of (\d+) (.+?) were\b/, (m, a, b, what) => `${a} of ${b} ${what} ${a === '1' ? 'was' : 'were'}`)
    .replace(/\b(?!https?\()(\w+)\((s|es)\)/g, '$1$2');
  text = text.replace(/\bplanted marker\b/gi, 'test marker').replace(/\bmarker (markup|data)\b/gi, 'test $1').replace(/\bmarker path\b/gi, 'path containing the test marker')
    .replace(/\bmarker link\b/gi, 'test link').replace(/\bapp window\b/g, 'application window').replace(/\bthe app\b/g, 'the application')
    .replace(/\breached '([^']+)'/, 'reached the IPC channel ‘$1’');
  return lower(text);
}

export function staticFact(i, normalId) {
  const id = normalId(i.id);
  const fn = STATIC[id] || STATIC[id.replace(/_(TAG|GLOBAL)$/, '')];
  if (fn) return fn(i);
  // a check with no sentence of its own: its finding detail, or its description
  return lower(detailOf(i.description) || String(i.description || '').replace(/\.$/, ''));
}

// the names of the weaknesses the checks link to, as MITRE titles them
const CWE_TITLES = {
  15: 'External Control of System or Configuration Setting', 20: 'Improper Input Validation', 73: 'External Control of File Name or Path',
  78: 'Improper Neutralization of Special Elements used in an OS Command', 79: 'Improper Neutralization of Input During Web Page Generation',
  89: 'Improper Neutralization of Special Elements used in an SQL Command', 200: 'Exposure of Sensitive Information to an Unauthorized Actor',
  201: 'Insertion of Sensitive Information Into Sent Data', 248: 'Uncaught Exception', 295: 'Improper Certificate Validation',
  306: 'Missing Authentication for Critical Function', 312: 'Cleartext Storage of Sensitive Information', 319: 'Cleartext Transmission of Sensitive Information',
  359: 'Exposure of Private Personal Information to an Unauthorized Actor', 427: 'Uncontrolled Search Path Element', 489: 'Active Debug Code',
  494: 'Download of Code Without Integrity Check', 506: 'Embedded Malicious Code', 522: 'Insufficiently Protected Credentials',
  524: 'Use of Cache Containing Sensitive Information', 532: 'Insertion of Sensitive Information into Log File',
  598: 'Use of GET Request Method With Sensitive Query Strings', 601: 'URL Redirection to Untrusted Site', 639: 'Authorization Bypass Through User-Controlled Key',
  653: 'Improper Isolation or Compartmentalization', 693: 'Protection Mechanism Failure', 732: 'Incorrect Permission Assignment for Critical Resource',
  749: 'Exposed Dangerous Method or Function', 798: 'Use of Hard-coded Credentials', 862: 'Missing Authorization', 1104: 'Use of Unmaintained Third Party Components',
};

// a reference's title, from its address
export function referenceTitle(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  const NAMES = { nodejs: 'Node.js', electron: 'Electron', apis: 'APIs', api: 'API', ipc: 'IPC', csp: 'CSP', http: 'HTTP', https: 'HTTPS',
    url: 'URL', urls: 'URLs', html: 'HTML', xss: 'XSS', dom: 'DOM', asar: 'ASAR', webview: 'webview' };
  const words = (text) => decodeURIComponent(text).replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/\b[a-z]+\b/gi, word => NAMES[word.toLowerCase()] || word);
  const sentence = (text) => text.charAt(0).toUpperCase() + text.slice(1);
  if (parsed.hostname === 'www.electronjs.org') {
    if (/\/tutorial\/security$/.test(parsed.pathname) && parsed.hash) {
      const anchor = parsed.hash.slice(1).match(/^(\d+)-(.+)$/);
      return anchor ? `Electron security checklist: ${anchor[1]}. ${sentence(words(anchor[2]))}` : 'Electron security checklist';
    }
    if (/\/tutorial\/security$/.test(parsed.pathname)) return 'Electron security checklist';
    const page = parsed.pathname.split('/').pop();
    // an API page's anchors run words together (#sessetcertificateverifyprocproc): only an event's name is shown
    const event = /^#event-(.+)$/.exec(parsed.hash);
    return `Electron ${/\/api\//.test(parsed.pathname) ? 'API ' : ''}documentation: ${sentence(words(page))}${event ? ` (‘${event[1]}’ event)` : ''}`;
  }
  if (parsed.hostname === 'cwe.mitre.org') {
    const number = (parsed.pathname.match(/(\d+)\.html$/) || [])[1];
    return number ? `CWE-${number}${CWE_TITLES[number] ? `: ${CWE_TITLES[number]}` : ''}` : 'CWE';
  }
  if (parsed.hostname === 'cheatsheetseries.owasp.org') return `OWASP ${words(parsed.pathname.split('/').pop().replace(/\.html$/, '').replace(/_Cheat_Sheet$/, ''))} Cheat Sheet`;
  if (parsed.hostname === 'owasp.org') return `OWASP: ${sentence(words(parsed.pathname.split('/').filter(Boolean).pop() || ''))}`;
  if (parsed.hostname === 'developer.mozilla.org') return `MDN Web Docs: ${words(parsed.pathname.split('/').filter(Boolean).pop() || '')}`;
  if (parsed.hostname === 'nodejs.org') {
    const variable = /^#(node_[a-z_]+?)(?:value)?$/i.exec(parsed.hash);
    if (variable) return `Node.js documentation: ${variable[1].toUpperCase()} environment variable`;
    return `Node.js documentation: ${parsed.hash ? words(parsed.hash.slice(1)) : words(parsed.pathname.split('/').pop().replace(/\.html$/, ''))}`;
  }
  if (parsed.hostname === 'learn.microsoft.com' || parsed.hostname === 'docs.microsoft.com') return `Microsoft documentation: ${sentence(words(parsed.pathname.split('/').filter(Boolean).pop() || ''))}`;
  if (parsed.hostname === 'github.com' && /\/security\/advisories/.test(parsed.pathname)) return `${parsed.pathname.split('/')[1]} security advisories`;
  return parsed.hostname.replace(/^www\./, '');
}
