// Reviewed, client-facing scenario copy. Each entry is [condition, consequence, action and closure test].
// A matching check selects a scenario; it does not establish the scenario's preconditions.
export const CLIENT_COPY = {
  'Node access in a renderer': [
    'The affected window is configured to expose Node.js capability to page code. The relevant trust boundary is whether content outside the application’s control can run in that window.',
    'Where untrusted script executes in this renderer, Node.js access can turn a page-level injection into access to local files, processes or application data within the user’s privileges. The scan does not establish that an untrusted script path exists.',
    'Disable Node integration for the affected window. Expose only required operations through a narrowly scoped preload and verify that untrusted page code cannot access Node.js or unrestricted main-process functions.'
  ],
  'Isolation or sandbox disabled': [
    'The affected window has a configuration that can reduce separation between its page, preload and operating-system process. The effective settings must be confirmed in the packaged application.',
    'If less trusted script runs in that window, reduced isolation can expose preload state or increase the consequences of a renderer compromise. The degree of access depends on the actual preload API and effective sandbox.',
    'Enable context isolation and renderer sandboxing in the production window configuration. Retest the intended preload functions and confirm the effective settings after packaging.'
  ],
  'Additional privilege sharing': [
    'The application uses a legacy remote capability or process affinity that can connect renderers across different trust levels. The affected windows and imports determine whether this creates an accessible boundary.',
    'If lower-trust content shares a privileged process or remote interface, it could reach application state or operations reserved for trusted content. A configuration match alone does not demonstrate that access.',
    'Remove remote-module access and separate renderers with different trust levels. Verify the shipped windows no longer share privileged process state or a remote interface.'
  ],
  'Origin or transport protections': [
    'The identified setting or Chromium switch can relax origin, mixed-content or transport protections for an affected window. The precise protection affected depends on the recorded setting.',
    'Where the window loads lower-trust resources, a weakened browser boundary can permit cross-origin access or content loading that the default configuration would restrict. This outcome requires an applicable content path.',
    'Restore the relevant Chromium security setting and remove security-disabling launch switches. Implement any legitimate cross-origin exchange through narrowly scoped server policy and confirm the packaged window enforces the intended boundary.'
  ],
  'Experimental or legacy capability': [
    'An optional Chromium capability is enabled or available in the affected renderer. Its security relevance depends on whether the production workflow actually uses it.',
    'An unnecessary capability expands the browser features reachable by page content; its practical impact depends on the feature, loaded origin and any separate vulnerability. Enabling it alone does not demonstrate exploitation.',
    'Disable capabilities that the production workflow does not require. For required features, restrict their use to trusted windows and verify the packaged configuration and expected functionality.'
  ],
  'Warning or keyboard safeguard': [
    'A browser warning or platform safeguard for sensitive input is disabled or not applied in the identified context. The impact differs between developer diagnostics and operating-system input protection.',
    'Disabled warnings can conceal insecure configuration during development; absent secure keyboard entry can matter when a user types a secret on a platform with a relevant local interception threat. Neither observation establishes disclosure by itself.',
    'Restore Electron security warnings in the development and release verification process. Enable secure keyboard entry for sensitive-input workflows where supported, and confirm the setting is active during entry and released afterwards.'
  ],
  'Broad preload bridge': [
    'The preload exposes application operations to a page or runs on an origin outside the intended trust boundary. The callable methods and actual loaded origin define the exposure.',
    'If a lower-trust page can invoke a broad bridge, it may request privileged main-process actions with the application’s authority. The impact is limited by the operations exposed and the handler-side checks.',
    'Expose a small, typed API limited to required operations. Validate the calling frame, arguments and authorisation in each main-process handler, then confirm an unapproved origin cannot invoke the operations.'
  ],
  'Shared session between trust levels': [
    'The affected windows may reuse a session partition despite loading content with different trust levels. Confirm their live origins and effective partition identifiers.',
    'A lower-trust window using a trusted session could gain access to cookies, storage or permission decisions available in that partition. The consequence depends on which data and grants are actually shared.',
    'Assign separate session partitions and permission policies to windows with different trust levels. Verify isolation of cookies, storage and grants in the packaged workflow.'
  ],
  'Sender not restricted': [
    'The identified IPC handler does not establish an explicit caller boundary in the observed path. A renderer’s ability to name a channel should not itself authorise the requested operation.',
    'If an untrusted frame can send on that channel, it could invoke the handler’s privileged behaviour. The scan identifies a validation gap; actual exploitability depends on the sender and operation.',
    'Check the sender frame and its origin before processing the message, then authorise the requested operation separately. Confirm that calls from an unapproved frame are rejected in a representative runtime test.'
  ],
  'Arguments or file paths trusted': [
    'A main-process handler receives renderer-supplied values that may influence a sensitive operation. The handler’s use of each value determines the security boundary.',
    'If a caller can supply an unconstrained path or command argument, the handler could read, modify or open resources outside the caller’s intended scope. This requires a reachable caller and a permissive handler.',
    'Validate input types and allowed operations at the handler, and resolve file paths within an approved base directory. Test an out-of-scope value and confirm it is rejected before the sensitive action.'
  ],
  'Unused or unexpected channel': [
    'An exposed IPC channel was not seen in the observed renderer traffic. Absence from a scan session does not establish that the channel is unused across all workflows.',
    'A retained handler can expand the set of privileged actions available to a renderer if it can be called by served or injected content. The risk depends on reachability and handler controls.',
    'Trace the channel across shipped renderers and representative workflows. Remove it if unused; otherwise document its intended callers and enforce sender, input and operation checks in the handler.'
  ],
  'External URL or protocol': [
    'The application passes a URL to an operating-system hand-off API. The relevant boundary is whether a page, document or other external input can select the destination.',
    'If a user follows an attacker-selected destination, an unsafe scheme or host may invoke another local handler or disclose information through a network request. The outcome depends on the accepted schemes and user action.',
    'Parse the URL and allow only approved schemes and destinations before the hand-off. Verify that crafted but harmless disallowed links are rejected in the affected workflow.'
  ],
  'Non-web protocol launch': [
    'The URL hand-off could include file, custom or application protocols unless the application constrains its input. This scenario requires confirmation of the accepted scheme.',
    'If external content selects such a protocol, the operating system may launch a local handler or open a resource outside the intended web-link flow. The behaviour is platform and handler dependent.',
    'Reject non-web schemes by default and allow a specific protocol only for a documented business need with a restricted destination. Verify disallowed schemes cannot reach the operating-system API.'
  ],
  'Network-share credential exposure': [
    'The hand-off path may accept a UNC, SMB or equivalent network-share destination. Confirm that an external input can supply such a target before applying this scenario.',
    'On a host configured to authenticate to a remote share, opening an attacker-selected network location could disclose authentication material. The preconditions include destination control, user action and host authentication behaviour.',
    'Block network-share paths and equivalent URL forms from untrusted content. Validate with a benign destination that the application rejects the path before any operating-system hand-off.'
  ],
  'File path handed to the host': [
    'The application passes a local path to an API that opens or reveals a file. The path’s source, canonical form and permitted directory determine the exposure.',
    'If lower-trust input controls the path, a user may be directed to an unintended document or location. An executable outcome depends on the file type and the particular operating-system API.',
    'Resolve and validate the final path within an approved directory, reject traversal and disallowed file types, and confirm that an out-of-scope test path never reaches the host API.'
  ],
  'Executable file path': [
    'An open-path operation may receive a script, shortcut or executable path. The scenario applies only if an external or lower-trust source can select that final path.',
    'Where the host opens an executable file selected by untrusted content, it could run under the current user’s account. The scan does not establish execution or attacker control from the API call alone.',
    'Deny executable file types in document-opening workflows and require an explicit, separately authorised action for program launch. Confirm path validation using a harmless file without executing untrusted code.'
  ],
  'Download or shortcut destination': [
    'A download or shortcut operation writes to a destination that may be influenced by content or configuration. The final folder, filename and target require review.',
    'If an untrusted source controls these values, the application could place an unexpected file or launcher in a sensitive location. The consequence depends on write permissions and whether the artefact is later opened.',
    'Constrain output directories and shortcut targets to approved locations, validate the final resolved path and require user intent for sensitive writes. Verify a path outside the approved location is rejected.'
  ],
  'Shell command construction': [
    'The observed process-launch path may place a variable value into a command string or invocation. The input source and shell option determine whether the value is executable syntax.',
    'If an untrusted actor controls shell metacharacters or executable arguments, the process could run unintended commands with the application’s privileges. A data-flow match alone does not confirm command execution.',
    'Call a fixed executable with a validated argument array and disable shell interpretation. Confirm that a harmless metacharacter-bearing input remains data and cannot change the invoked program or arguments.'
  ],
  'Dynamic code evaluation': [
    'The application uses a code-evaluation function on a value whose provenance requires review. The security boundary depends on whether external data reaches that value.',
    'If lower-trust content is evaluated as code, it can execute in the relevant JavaScript context and inherit its available APIs. The scan does not establish an attacker-controlled input path by itself.',
    'Replace dynamic evaluation with structured data parsing or a fixed dispatch table. Confirm that externally supplied strings cannot become executable code in the affected context.'
  ],
  'Word launch command': [
    'The Microsoft Word launch flow constructs an invocation or document path that may include external input. The final executable, argument array and document location define the boundary.',
    'If the input is not constrained, a user may open an unintended document or launch Word with unintended arguments. The impact depends on the actual invocation and file provenance.',
    'Invoke a fixed Word executable with a separate, validated argument array and restrict document paths to the authorised workflow. Confirm the resolved path and arguments using a benign document.'
  ],
  'Document provenance and Protected View': [
    'A document-opening flow may copy or transform a downloaded file before Word receives it. Confirm whether its Mark-of-the-Web provenance survives that transition.',
    'If an untrusted document loses its zone information, Word may no longer apply the Protected View treatment expected for downloaded files. The outcome depends on the file, host policy and actual open path.',
    'Preserve the document’s zone provenance through download, copy and launch, or apply an equivalent isolated review process. Confirm the stream on the exact file opened by Word and verify the expected Protected View behaviour.'
  ],
  'External handler input': [
    'A registered protocol or file association accepts parameters supplied outside the application. Those parameters cross into an application action or file-opening path.',
    'If the handler trusts an external action or path, a crafted link or associated file could trigger behaviour beyond the intended entry point. The result depends on parsing, routing and downstream authorisation.',
    'Parse handler input against a fixed schema, allow only documented actions and canonicalise permitted paths. Confirm unknown actions and out-of-scope paths are rejected before any privileged operation.'
  ],
  'Privileged custom scheme or file URL': [
    'The application registers or loads a custom scheme or file URL with privileges that may exceed its intended resource scope. The effective privilege set and resolver need confirmation.',
    'If an external input selects a resource through that scheme, it may reach local files or a privileged renderer. The consequence depends on resource mapping and which origins can initiate the load.',
    'Grant only the scheme privileges needed for the documented workflow and resolve resources from an explicit allowlist. Verify that traversal and unauthorised origins cannot load protected resources.'
  ],
  'Top-level navigation or redirect': [
    'An affected window can navigate, or follow a redirect, beyond its intended origin unless both direct and redirected destinations are checked.',
    'If a foreign page loads in a window that retains preload, session or other application capability, that page may gain access to privileges intended for trusted content. The scan does not establish this outcome without the final URL and window settings.',
    'Deny unapproved destinations in navigation and redirect handlers. Confirm that a benign redirect to an external origin is blocked and that the final loaded page cannot inherit privileged window settings.'
  ],
  'Popup or middle-click': [
    'Page content can request a new window or a link hand-off through popup or auxiliary-click behaviour. The child window policy and destination restrictions determine the risk.',
    'A crafted link could create a child with unintended privileges or pass an unsafe destination to the operating system if the request is accepted without policy checks.',
    'Deny new windows by default and route approved links through a scheme and destination allowlist. Test ordinary clicks, middle-clicks and scripted popups in the packaged renderer.'
  ],
  'Embedded content': [
    'An embedded frame or webview may load a resource without the intended sandbox or attachment policy. Its source and effective preferences require inspection.',
    'If it loads lower-trust content, the child’s privileges, preload or navigation behaviour could expose application capability beyond the parent page’s intended boundary.',
    'Avoid webviews where the workflow permits. Otherwise validate each source, enforce restrictive attachment preferences and sandbox attributes, and verify the effective child settings at runtime.'
  ],
  'Permission request callback': [
    'The affected session lacks an explicit, restrictive decision for a browser permission request. The requesting origin and capability must be evaluated together.',
    'If an unapproved page can request a capability such as camera, location or notifications, it may obtain access the application did not intend. The actual grant depends on the runtime handler and platform decision.',
    'Install a permission request handler with an explicit origin and capability allowlist and deny all other requests. Verify both an approved request and an unapproved-origin request.'
  ],
  'Synchronous permission check': [
    'The synchronous permission-check path may not apply the same policy as the request handler. Some browser APIs consult this path independently.',
    'An API could proceed under a permissive check even where interactive permission requests are constrained. The outcome depends on the API, origin and effective session handlers.',
    'Implement a permission check handler using the same origin and capability policy as the request handler. Confirm that an unapproved origin is denied on both decision paths.'
  ],
  'HTML sink or editor': [
    'A content-rendering sink or rich-text editor may place externally supplied markup into a page. The source of that markup and its interpretation in the destination view determine the finding.',
    'If another actor controls markup that executes in a viewer’s renderer, it could act within that viewer’s session and available application APIs. A flagged sink alone does not establish cross-user execution.',
    'Render plain text as text and sanitise the narrow HTML subset the workflow needs at the output boundary. Verify that a benign script probe is inert in the destination view.'
  ],
  'Sanitiser or framework bypass': [
    'A sanitiser configuration or framework trust override may allow active HTML, event attributes or unsafe URLs through a rendering path. Confirm the exact input and binding.',
    'If untrusted content enters that path, the override could bypass the expected output encoding and permit script execution in the receiving renderer. This depends on the actual allowed constructs.',
    'Remove trust overrides for user content, restore a restrictive allowlist and encode output in the destination context. Verify representative active markup is rejected without breaking permitted formatting.'
  ],
  'Runtime reflection or message': [
    'A tracked value appeared in a rendered response, DOM path or WebSocket message during the observed workflow. Reflection and script execution are distinct evidence states.',
    'Where the value is rendered as active content for another user, it can affect that user’s renderer. The scan must show the source, destination account and execution signal before stating a cross-account compromise.',
    'Encode or sanitise at the final rendering boundary and apply a restrictive Content Security Policy as a secondary control. Repeat the same source-to-destination workflow and confirm the marker cannot execute.'
  ],
  'Markup without proven execution': [
    'A marker reached an HTML sink or appeared as live markup. This observation supports a rendering boundary concern but does not confirm that a script ran.',
    'If active attributes or elements survive the same path, a script-execution scenario may be possible. Cross-account reach and resulting privileges remain unproven until the destination workflow is observed.',
    'Replace the unsafe sink or sanitise its HTML input. Confirm the marker is rendered safely, and use a harmless execution probe only where the authorised test workflow permits it.'
  ],
  'Script execution observed': [
    'A benign script probe executed during the recorded workflow. The source input, destination account and renderer context must remain linked in the evidence.',
    'The confirmed execution can act within the affected renderer; access to another account or to privileged APIs depends on the observed account boundary and window configuration. Do not infer those additional effects from execution alone.',
    'Repair the exact input-to-output path, add appropriate encoding or sanitisation and restrict renderer privileges. Repeat the recorded benign probe and confirm execution no longer occurs.'
  ],
  'No effective policy': [
    'The affected page may lack an enforceable Content Security Policy in its final loaded response. A report-only policy or a policy on a different page does not provide the same protection.',
    'If markup injection reaches this page, the browser has fewer restrictions on what injected script can load or execute. A missing policy is a defence gap and does not itself demonstrate an injection path.',
    'Define and enforce a restrictive policy for each relevant page, including redirect and frame flows. Confirm the effective policy in the packaged renderer and exercise legitimate content loading.'
  ],
  'Unsafe script directives': [
    'A present policy may permit inline script, evaluation or overly broad script sources. Its actual enforcement depends on the final directives, nonces and report-only status.',
    'Where untrusted markup reaches the page, permissive script rules can allow execution that a stricter policy would block. The policy weakness does not establish that such markup is reachable.',
    'Remove unsafe script permissions where feasible and narrowly define approved sources, nonces or hashes. Verify that legitimate scripts run and a benign injected script is blocked by the enforced policy.'
  ],
  'Runtime violation or mismatch': [
    'The runtime policy or a recorded violation differs from the expected release configuration. A violation can indicate either an effective block or a legitimate resource that needs policy work.',
    'A configuration mismatch may leave an intended control absent, while an effective violation can interrupt a business flow. The direction and consequence require the actual directive and blocked resource.',
    'Reconcile the packaged policy with the intended resource list, fix the underlying loading path and keep enforcement restrictive. Verify both the expected business flow and rejection of an unapproved source.'
  ],
  'Untrusted document intake': [
    'The application accepts a document format and passes it to a parser or converter. The source, parser version and execution boundary determine the exposure.',
    'If an externally supplied malformed file reaches vulnerable parser code, it could disrupt the process or exploit a separate parser defect. An intake path alone is not evidence of such a defect.',
    'Constrain file type and size, maintain the parser and isolate conversion with minimal privileges. Confirm unsupported formats are rejected and a benign malformed fixture does not affect the host application.'
  ],
  'Rendered conversion output': [
    'A document conversion flow may produce HTML or external resource references for a renderer. The output needs its own trust boundary even when the input was a valid document.',
    'If active markup or external relationships survive conversion, a viewer could run unintended page code or load resources selected by the document author. The outcome depends on the converter output and renderer policy.',
    'Sanitise converted HTML, block unapproved external resources and render the result in a restricted context. Verify a benign document containing active markup and a remote link remains inert.'
  ],
  'Local Node entry points': [
    'Packaged Electron fuses may leave RunAsNode, Node options or inspector entry points available. The exact fuse values must be read from the distributed executable.',
    'Someone with local ability to launch the application could use an enabled entry point under the application’s identity. This is a local hardening concern and does not establish a remote compromise.',
    'Disable unnecessary Node and inspector entry points at package time. Read the fuses from the shipped executable and verify the production launch and supported diagnostics still work.'
  ],
  'Asar integrity and loading': [
    'The package may lack embedded asar integrity enforcement or a restriction on loading code outside the application archive. Both the fuse state and embedded digest matter.',
    'If a local actor can alter the installation, missing enforcement can allow modified application code to load without this integrity check. The scenario presupposes local write access.',
    'Enable embedded asar integrity validation and load only from the asar, with a valid embedded digest. Verify the packaged executable rejects a deliberately altered test archive.'
  ],
  'Cookie or file-protocol privileges': [
    'The cookie-encryption or file-protocol fuse may differ from the intended release configuration. The affected storage or file-URL workflow determines relevance.',
    'Unencrypted cookies may be more accessible to a local profile reader; unnecessary file-protocol privileges can expand what a renderer may load. Neither effect follows without the corresponding workflow.',
    'Enable cookie encryption where supported and grant file-protocol privileges only for documented needs. Check the shipped fuse values, stored cookie behaviour and actual file-URL access.'
  ],
  'Source map exposure': [
    'Production source maps are present in the distributed application and may include original source content and internal paths. Their presence is observable by anyone who obtains the package.',
    'The maps can aid inspection of application logic and expose implementation details. This is an information-exposure concern; source maps alone do not confer privileged access.',
    'Exclude maps containing original source from distributable artefacts or upload them to a restricted diagnostic service. Inspect the final package to confirm no unintended maps or embedded sources remain.'
  ],
  'Asar integrity': [
    'The packaged application archive may not be checked against an embedded trusted digest. The relevant fuses and actual archive must be reviewed together.',
    'If a local actor can replace packaged files, absent integrity enforcement can permit modified application code to run. The control does not protect against a fully compromised host or authorised update channel.',
    'Enable embedded asar integrity validation and restrict application loading to the archive. Verify the shipped digest and confirm a modified test archive is rejected.'
  ],
  'Publisher signature': [
    'The distributed executable or installer may lack a verifiable publisher signature or trusted timestamp. The exact shipped artefact is the subject of this observation.',
    'Without a valid signature, recipients have less assurance of publisher identity and whether the artefact changed after release. This does not prove that the current binary has been tampered with.',
    'Sign and timestamp each release executable and installer using the authorised publisher identity. Verify the signature chain, signer and timestamp on the distributed artefacts.'
  ],
  'Platform exploit mitigations': [
    'One or more platform exploit mitigations may be absent from a shipped binary or native module. The relevant flags vary by operating system and build target.',
    'If a separate memory-corruption flaw is present, missing mitigations can make exploitation easier. The mitigation gap alone is not evidence of a memory-corruption vulnerability.',
    'Build Electron and native modules with supported platform hardening options. Inspect the exact release binaries and verify the expected mitigation flags are present.'
  ],
  'Update feed transport': [
    'The configured update feed may use a transport that does not authenticate the server or protect metadata in transit. The effective packaged URL and updater behaviour determine this scenario.',
    'An actor on the network path could alter update metadata or release selection if the client lacks independent verification. Package signature enforcement may limit the resulting installation risk.',
    'Serve update metadata and packages over HTTPS with normal certificate validation. Inspect a release build during an update check and confirm the final feed and package URLs use the intended transport.'
  ],
  'Update signature or publisher': [
    'The update workflow may install a package without enforcing its expected publisher or cryptographic signature. The updater’s actual verification step requires inspection.',
    'If an attacker can substitute a release and the client accepts it, untrusted code could be installed for users. This requires both a substitution path and a missing or bypassed trust check.',
    'Enforce package signature and publisher verification before installation, including failed-download and rollback paths. In an isolated test, confirm a package with an invalid signature is rejected.'
  ],
  'Developer tooling or test hooks': [
    'A production build may retain a developer-tools entry point or test-only operation. The relevant question is whether it is reachable in the shipped configuration.',
    'A local user or an actor already able to run page script could gain additional inspection or actions through these facilities. The finding does not imply unauthenticated remote access to developer tools.',
    'Remove test hooks and restrict developer tools in production unless there is an approved operational need. Verify the release build blocks the documented entry points while required support workflows remain available.'
  ],
  'Logs, console secrets or exceptions': [
    'A recorded log, console event or exception may contain a sensitive value or internal implementation detail. The data’s classification and log destination define the exposure.',
    'Anyone with access to the affected log or console could obtain information outside their intended role if the value is sensitive. A generic exception without such content has a different impact.',
    'Remove credentials and sensitive fields from logs, control access and retention, and handle exceptions without disclosing internals. Check representative release events for the previously observed value.'
  ],
  'Credential or token in code': [
    'A credential-like value appears in a distributable file. Its provider, validity and privileges must be established before treating it as a live secret.',
    'If the value is a shared live credential, anyone with the package could reuse it within its granted scope until it is revoked. Public identifiers and inert test fixtures do not carry that consequence.',
    'Confirm the value’s classification and scope with its owner, rotate any live secret and remove it from the client package. Keep privileged credentials server side or in an appropriate operating-system store and rescan the release.'
  ],
  'Public key or false positive': [
    'The detected value may be a public identifier, public key or non-production fixture rather than a secret. Its classification requires provider and privilege evidence.',
    'If the value cannot authenticate or authorise an operation, its presence does not establish credential compromise. Any separate quota or identifier-abuse exposure should be assessed on its own terms.',
    'Record the provider’s classification and effective permissions. Scope public client identifiers as tightly as the provider permits and remove unnecessary fixtures from the production package.'
  ],
  'Plaintext credential or file': [
    'A credential or other sensitive value may be persisted in a file or store without operating-system-backed protection. The actual value, write path and protection must be confirmed.',
    'Someone who can read the affected user profile, backup or file may recover the value and exercise its privileges. The access required and value lifetime govern practical impact.',
    'Store secrets in the operating-system credential store or an appropriate protected API, remove obsolete plaintext copies and limit retention. Verify a benign canary is protected in the final storage location.'
  ],
  'Application settings or cached responses': [
    'Settings, cookies or cached responses may retain data that the application regards as sensitive. Confirm the stored fields, profile permissions and effective encryption settings.',
    'If credentials or protected content persist in a general-purpose store, a person with profile or backup access may retrieve them. The impact depends on the fields and their protection at rest.',
    'Keep secrets out of general settings, enable supported cookie encryption and prevent caching of sensitive responses. Inspect the resulting profile with benign test data to confirm the retention policy.'
  ],
  'Cleartext HTTP or WebSocket': [
    'An affected request, socket or page resource may use an unencrypted final transport. The captured scheme, host and data identify the specific exposure.',
    'An actor able to observe or alter the network path could read or modify that traffic. Script resources and authentication data have greater potential impact than public static content.',
    'Use HTTPS or WSS for the affected endpoint and its redirects, with valid certificates. Confirm the final request and socket scheme in a representative packaged run.'
  ],
  'Certificate validation bypass': [
    'The application may override a certificate error or disable TLS verification for an affected request. A logged error that the client rejected is not an accepted bypass.',
    'If an invalid certificate is accepted, an actor on the network path could impersonate the affected server and read or alter that connection. The impacted host and session must be identified.',
    'Remove permissive certificate callbacks and global verification overrides; trust only the intended server identity or CA. Verify a deliberately invalid test certificate is rejected.'
  ],
  'Credential transport or cookie flags': [
    'An authentication request or cookie may lack a transport or browser attribute appropriate to its use. The final scheme and exact cookie attributes determine the case.',
    'Credentials sent over cleartext transport can be observed on the network; missing Secure, HttpOnly or SameSite attributes can enable distinct exposure paths. Do not treat the presence of Basic authentication over valid TLS as cleartext disclosure.',
    'Use authenticated transport and set Secure, HttpOnly and SameSite according to the session workflow. Recheck the final requests and Set-Cookie response for the affected host.'
  ],
  'Secret in URL or response': [
    'A captured URL or response may contain a sensitive value. The value’s classification, recipients and retention channels require confirmation using redacted evidence.',
    'Secrets in URLs can enter logs, history or diagnostics; an overbroad response can expose data to a client not entitled to receive it. The latter requires a separate access-control determination.',
    'Move credentials to a suitable protected request channel, minimise response fields and enforce recipient authorisation. Verify the value is absent from URLs, logs and unauthorised responses.'
  ],
  'WebSocket secret': [
    'A WebSocket URL or message may carry a credential or other sensitive value. Endpoint logging and server-side recipient routing define who can see it.',
    'A secret in the URL may persist in infrastructure logs; a misrouted message may expose it to another subscriber. The scan does not establish a cross-user disclosure without a recipient trace.',
    'Use short-lived connection credentials outside logged URLs where feasible and authorise each message recipient. Confirm redacted traces show the intended subscriber and no secret in the URL.'
  ],
  'Third-party destination': [
    'Captured traffic sends authentication material or user input to a host outside the initially identified first-party set. Host ownership and contractual purpose must be confirmed.',
    'If the host is an unapproved third party, it may receive data beyond the intended service boundary. A client-owned or approved service should be assessed against its actual data-handling purpose.',
    'Allow authentication headers only for their intended API and minimise data sent to other destinations. Verify host ownership, approved purpose and the resulting request fields.'
  ],
  'Unsupported release line': [
    'The packaged Electron major release may be outside its upstream support window. Confirm the exact shipped version and support status at the report date.',
    'An unsupported line may not receive future security fixes, leaving the application exposed to defects found after support ends. This does not establish that a specific exploitable defect exists today.',
    'Move to a supported Electron release through a tested upgrade path. Confirm the version in the packaged executable and rerun the compatibility and security checks.'
  ],
  'Missing Electron or Chromium fixes': [
    'The bundled Electron or Chromium build may predate an applicable upstream security fix. Version comparisons must account for affected platforms and backports.',
    'If the application exposes the vulnerable browser feature or API, it may remain susceptible to the advisory’s stated conditions. A version match alone does not establish reachability.',
    'Upgrade to an Electron build containing the relevant fixes, or document a verified backport. Confirm the shipped component versions and reassess the cited advisory conditions.'
  ],
  'Published dependency advisory': [
    'A shipped dependency version matches the range in a published advisory. The affected code path and its presence in the application require assessment.',
    'If the vulnerable function is present and reachable, the advisory’s stated impact may apply to this application. A package-version match is not proof that the exploit conditions hold.',
    'Upgrade to a fixed version, prioritising components used in exposed workflows. Verify the resolved lockfile and packaged artefact, then reassess the advisory conditions.'
  ],
  'Unsupported library': [
    'A dependency release line may no longer receive maintenance. Confirm the shipped copy, runtime use and upstream support status.',
    'A maintained fix may be unavailable if a vulnerability is later identified. Unsupported status alone does not establish a present exploitable flaw.',
    'Replace or upgrade the component to a maintained line and test the affected application paths. Confirm that the old version is absent from the final dependency inventory.'
  ],
  'Malicious version in inventory': [
    'The dependency inventory includes a package version identified by a malicious-package source. Its installation and execution in the build environment must be established promptly.',
    'If that version executed during installation or build, it could have accessed available credentials or modified produced artefacts. Inventory presence alone does not prove execution or exfiltration.',
    'Remove the affected version, pin a trusted replacement and rebuild from a clean environment. Establish installation and execution history, then verify the resulting artefacts and dependency graph.'
  ],
  'Exposure response': [
    'The response to a malicious dependency may need to cover developer machines, CI and release artefacts as well as the distributed application. Scope follows where the package actually executed.',
    'Credentials or signing material available in an affected environment may be exposed; artefacts produced there may require independent verification. The affected set must be based on execution and access evidence.',
    'Review install scripts, build logs, environment access and release provenance. Rotate credentials that were accessible during execution and rebuild and verify impacted artefacts from a trusted environment.'
  ],
  'Untrusted module path': [
    'A module path in the main process or a preload is built from a value that may come from a renderer, a navigation or a deep link, and is passed to require() or import(). Whether a caller outside the application controls that value needs confirmation.',
    'If a lower-trust caller can choose the path, the application may load and run a different module or file, including one reached through directory traversal, with the privileges of the process that loads it. The scan does not establish that such a caller exists.',
    'Load modules only from a fixed map of known names to fixed paths, and reject any other value before resolution. Verify that a traversal value and an unlisted module name are rejected in the packaged application.'
  ],
  'Injected script reached Node or Electron APIs': [
    'A configured test payload, delivered through the application’s own save and view workflow, executed in a renderer and reported access to Node.js, the Electron module or the local file system from page script.',
    'Content that reaches this view as script can use the same access: reading local files, loading modules or calling Electron APIs with the user’s privileges. The recorded signal establishes this access for the tested view; other views and accounts need separate evidence.',
    'Disable Node integration and enable context isolation and the sandbox for windows that render stored or external content, and render that content as text or sanitised HTML. Repeat the same campaign case and confirm that the payload no longer reports Node, Electron or file access.'
  ],
  'Script evaluation permitted': [
    'A configured test payload executed in a renderer and was able to call eval(). The effective Content Security Policy of the tested view does not block string evaluation.',
    'Where injected content runs as script, permitted evaluation makes it easier to turn a data value into executable code and weakens a policy’s ability to contain an injection. It does not by itself show how the content was injected.',
    'Remove unsafe-eval from the policy of the affected view and replace string evaluation in the application code. Repeat the campaign case and confirm the evaluation attempt is blocked and reported as a violation.'
  ],
  'No certificate pinning': [
    'The scanner did not identify certificate or public-key pinning in the reviewed paths. Confirm the exact backend connection before concluding pinning is absent. This is a hardening observation, not a certificate validation failure.',
    'If the affected connection accepts an intercepting proxy’s certificate, an actor able to supply such a trusted certificate could read or alter that connection. A supplied capture alone does not establish which app accepted which certificate.',
    'Decide from the threat model whether pinning is required for the backend hosts. Where it is, verify the server certificate or public key in session.setCertificateVerifyProc against an allowlist with a rotation plan, and confirm an intercepting proxy’s certificate is rejected.'
  ],
  'Untrusted URL loaded in an app window': [
    'An application window loads a URL that is taken from a less trusted input, such as a deep link, an IPC message or navigation data, without an allowlist of destinations being established by the scan.',
    'If an external party can choose that URL, their page runs inside the application window with that window’s preload, session and permissions. The consequence depends on what the window exposes to page content.',
    'Parse the incoming URL and allow only known application origins and paths before loading it; open everything else in the system browser after scheme validation. Verify that a crafted link to an unapproved origin is not loaded in the window.'
  ],
  'HTTPS exchanges in a proxy capture': [
    'A supplied proxy capture contains HTTPS exchanges with responses. The originating app, certificate and affected connection must be established independently.',
    'If the test confirms the application accepted the proxy certificate for the affected backend, interception is demonstrated for that connection. Capture presence alone does not prove absence of pinning or acceptance of an invalid certificate.',
    'Where the threat model calls for it, pin the backend certificates or keys and reject connections that do not match. Repeat the capture through the proxy and confirm the application refuses the connection.'
  ],
};
