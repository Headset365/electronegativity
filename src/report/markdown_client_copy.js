// Client-facing scenario copy, in Australian English and an impersonal voice. Each entry is [issue, implication,
// recommendation]: what the condition is, what it could lead to, and what to do about it (with how to verify the fix).
// A matching check selects a scenario. Limits of testing are stated once per finding, in its note, not in each scenario.
export const CLIENT_COPY = {
  'Node access in a renderer': [
    'Node.js integration is enabled for an application window, which gives any script running in that window direct access to Node.js and, through it, to the operating system.',
    'If an attacker can run script in the window, for example through cross-site scripting or a compromised remote resource, they could read and modify local files, run programs and access application data with the privileges of the logged-in user.',
    'Disable Node.js integration for every window that renders web content, and expose only the operations the interface needs through a narrowly scoped preload script. Verify in the packaged application that page script can no longer access `require` or `process`.'
  ],
  'Isolation or sandbox disabled': [
    'Context isolation or the renderer sandbox is disabled for an application window, which removes the separation between page script, the preload script and the operating system.',
    'Script running in the page could tamper with the preload script’s objects and reach the privileged functions it holds, and a compromise of the renderer process would not be contained by the sandbox.',
    'Enable context isolation and the renderer sandbox for every window. Verify in the packaged application that the preload functions still work and that page script cannot access the preload script’s objects.'
  ],
  'Additional privilege sharing': [
    'The application uses the deprecated remote module or process affinity, which connects renderer processes to privileged functionality or to each other.',
    'Content in a less trusted window could reach application state or privileged operations intended only for trusted windows.',
    'Remove the remote module and process affinity, and provide required functionality through validated inter-process communication (IPC) handlers. Verify that no window can reach the main process other than through those handlers.'
  ],
  'Injected script reached Node or Electron APIs': [
    'During testing, a harmless test payload saved through the application’s normal workflow executed when the content was viewed, and confirmed access to Node.js, the Electron module or the local file system from page script.',
    'Any content that reaches this view as script has the same access, and could read local files, load modules or call Electron functions with the privileges of the logged-in user.',
    'Disable Node.js integration and enable context isolation and the sandbox for windows that display stored or external content, and render that content as text or sanitised HTML. Repeat the same test and confirm the payload no longer executes or reports privileged access.'
  ],
  'Origin or transport protections': [
    'A browser security protection, such as the same-origin policy or the blocking of insecure content, is disabled for an application window or for the whole application.',
    'Content loaded in the affected window could read data from other origins or load scripts over unencrypted connections, which the browser would otherwise prevent.',
    'Re-enable the affected protection and remove security-disabling command-line switches. Where the application needs to exchange data across origins, allow it through narrowly scoped server-side policy, and verify the packaged window enforces the default protections.'
  ],
  'Experimental or legacy capability': [
    'An experimental, deprecated or unnecessary browser feature is enabled for an application window.',
    'Each enabled feature adds browser functionality that page content can use, which increases the attack surface available to any script running in the window.',
    'Disable features the application does not need. Where a feature is required, enable it only for trusted windows and verify the packaged configuration.'
  ],
  'Warning or keyboard safeguard': [
    'Electron security warnings are suppressed, or Secure Keyboard Entry is not enabled where users type passwords on macOS.',
    'Suppressed warnings can hide insecure configuration from developers, and without Secure Keyboard Entry other software on the same Mac could observe what users type into password fields.',
    'Remove the setting that suppresses Electron security warnings, and enable Secure Keyboard Entry while password fields have focus on macOS. Verify the warnings appear in development builds and that Secure Keyboard Entry is active during password entry.'
  ],
  'Broad preload bridge': [
    'The preload script exposes privileged functionality to page script, such as the whole inter-process communication (IPC) interface rather than a small set of specific functions.',
    'Any script running in the page, including injected script, could use the exposed functionality to invoke privileged operations in the main process with the authority of the application.',
    'Expose only a small, specific set of functions through the context bridge, each passing validated arguments to a dedicated handler, and never expose Electron or Node.js objects directly. Verify that page script cannot reach any other privileged functionality.'
  ],
  'Shared session between trust levels': [
    'Application windows that display content of different trust levels share the same browser session, and with it the same cookies, storage and permission decisions.',
    'Content in a less trusted window could use the session’s cookies, stored data or permissions granted to a trusted window.',
    'Assign separate session partitions to windows that display content of different trust levels, with their own permission handling. Verify that cookies, storage and permissions are no longer shared.'
  ],
  'Sender not restricted': [
    'An inter-process communication (IPC) handler in the main process acts on messages without checking which page or frame sent them.',
    'Any page able to send a message on the channel, including a page loaded from an unexpected origin or a frame within it, could trigger the handler’s privileged operation.',
    'Validate the sender of every IPC message against the expected application origin before acting on it, and authorise the requested operation separately. Verify that a message sent from an unapproved page or frame is rejected.'
  ],
  'Arguments or file paths trusted': [
    'An inter-process communication (IPC) handler in the main process uses values received from the renderer in a sensitive operation, such as a file system, process or shell operation, without validating them.',
    'A page able to send the message could choose the value and make the handler read, modify or open files, or run programs, outside the intended scope of the operation.',
    'Validate the type and value of every argument at the handler, allow only the specific operations required, and resolve file paths within an approved directory. Verify that an out-of-scope value is rejected before the sensitive operation.'
  ],
  'Unused or unexpected channel': [
    'The main process handles an inter-process communication (IPC) channel that no reviewed code in the user interface sends. The channel may be unused or used only in development; code the application loads from a server was not part of the review.',
    'A handler that is no longer needed still adds privileged functionality that a page could call, without serving a business need.',
    'Remove handlers that are not required. For each one that is, document its intended callers and validate the sender, arguments and requested operation.'
  ],
  'External URL or protocol': [
    'The application passes a URL to the operating system to open, using `shell.openExternal()`, without restricting which schemes and destinations are allowed.',
    'A link or value controlled by an attacker could make the operating system open an arbitrary destination or launch the handler for another protocol on the user’s computer.',
    'Parse every URL before passing it to the operating system and allow only approved schemes, normally `https:`, and approved destinations. Verify that links using other schemes or destinations are rejected.'
  ],
  'Non-web protocol launch': [
    'The URLs passed to the operating system are not restricted to web protocols, so `file:` URLs and custom application protocols are also opened.',
    'An attacker-controlled link could launch another application registered for a custom protocol, or open a local file, which on some systems can lead to running a program.',
    'Reject every scheme other than `https:` (and `mailto:` where required) before passing a URL to the operating system. Verify that `file:` and custom protocol links are rejected.'
  ],
  'Network-share credential exposure': [
    'The URLs and paths passed to the operating system are not checked for network-share locations, such as UNC (`\\\\server\\share`) or `file://server/` paths.',
    'Opening an attacker-chosen network share can make Windows send the user’s credentials to the attacker’s server, where they could be captured and cracked or relayed.',
    'Block UNC paths and `file:` URLs that refer to remote hosts before any hand-off to the operating system. Verify with a harmless test location that such paths are rejected.'
  ],
  'File path handed to the host': [
    'The application passes a file path to the operating system to open or reveal, without validating the path.',
    'If the path can be influenced by a page, document or message, the user could be presented with, or made to open, a file other than the one intended.',
    'Resolve each path to its final location, allow only paths within an approved directory and reject path traversal. Verify that a path outside the approved directory never reaches the operating system.'
  ],
  'Executable file path': [
    'The paths the application asks the operating system to open are not restricted by file type, so executables, scripts and shortcuts are also opened.',
    'If an attacker can choose the path, opening an executable file would run it with the privileges of the logged-in user.',
    'Reject executable file types (such as `.exe`, `.bat`, `.cmd`, `.ps1`, `.js`, `.lnk`, `.msi` and `.scr`) in document-opening workflows, and require an explicit user action to launch a program. Verify the restriction with a harmless test file.'
  ],
  'Download or shortcut destination': [
    'A download or shortcut is written to a location, or points to a target, that is derived from content or configuration without validation.',
    'An attacker able to influence these values could place an unexpected file or launcher in a sensitive location, such as a startup folder.',
    'Restrict download destinations and shortcut targets to approved locations, validate the final path and require the user’s confirmation for sensitive writes. Verify that a destination outside the approved location is rejected.'
  ],
  'Shell command construction': [
    'The application starts a process with a command that is built from a variable value, using a function that runs the command through the system shell.',
    'An attacker able to influence the value could add shell syntax and run arbitrary commands with the privileges of the logged-in user.',
    'Run a fixed program with a separate, validated argument list (for example `execFile()` rather than `exec()`) so that input is never interpreted by a shell. Verify that input containing shell syntax is treated as data.'
  ],
  'Dynamic code evaluation': [
    'The application evaluates a string as code, for example with `eval()`, `new Function()` or `executeJavaScript()`, where the string is built from a variable value.',
    'If an attacker can influence the string, their input would run as code with the privileges of the context that evaluates it.',
    'Replace dynamic evaluation with structured data parsing or a fixed set of operations, so that input can never become code. Verify that externally supplied strings are not executed.'
  ],
  'Untrusted module path': [
    'The main process or a preload script loads a module with `require()` or `import()` from a path built from a value received from a renderer, a navigation or a deep link.',
    'An attacker able to choose the path could make the application load and run a different module or file, including one reached through path traversal, with the privileges of the process that loads it.',
    'Load modules only from a fixed list of known names mapped to fixed paths, and reject any other value before it is resolved. Verify that a traversal path and an unlisted module name are rejected.'
  ],
  'Word launch command': [
    'The application launches Microsoft Word with a command line or document path that is built from variable values.',
    'If an attacker can influence these values, the user could be made to open an unintended document, or Word could be started with unintended arguments.',
    'Start Word through a fixed executable path with a separate, validated argument list, and restrict document paths to the approved workflow. Verify the final command line with a harmless test document.'
  ],
  'Document provenance and Protected View': [
    'The application copies or converts documents before opening them in Microsoft Word, which can remove the Mark of the Web that records a file was downloaded from the internet.',
    'Without the Mark of the Web, Word opens a downloaded document outside Protected View, so macros and other active content in a malicious document are not held back for the user’s approval.',
    'Preserve the Mark of the Web (the `Zone.Identifier` stream) when downloading, copying and opening documents, or open them through an equivalent isolated review process. Verify the stream is present on the exact file Word opens, and that Word opens it in Protected View.'
  ],
  'External handler input': [
    'The application registers a custom protocol or file association, and acts on the parameters it receives from outside the application without validating them.',
    'A crafted link on a web page or in an email, or a crafted file, could make the application perform an unintended action or open a file of the attacker’s choosing.',
    'Parse deep link and file association input against a fixed format, allow only documented actions and resolve file paths within approved locations. Verify that unknown actions and out-of-scope paths are rejected.'
  ],
  'Privileged custom scheme or file URL': [
    'The application registers a custom protocol with elevated privileges, or loads its content over `file:` URLs, which have additional privileges in Electron.',
    'Content that can load resources through the scheme could reach local files or other privileged resources beyond those the application intends to serve.',
    'Grant custom protocols only the privileges they need and serve resources from an explicit list of allowed files. Prefer a custom protocol over `file:` URLs. Verify that path traversal and unauthorised pages cannot load protected resources.'
  ],
  'Untrusted URL loaded in an app window': [
    'An application window loads a URL taken from external input, such as a deep link, an inter-process communication (IPC) message or navigation data, without checking it against the destinations the application expects.',
    'An attacker able to choose the URL could load their own page inside the application window, where it would inherit the window’s preload script, session and permissions.',
    'Parse every URL before loading it in a window and allow only known application origins and paths. Open other links in the system browser after validating their scheme. Verify that a link to an unapproved origin is not loaded in the window.'
  ],
  'Top-level navigation or redirect': [
    'Application windows are not prevented from navigating, or following a server redirect, to destinations outside the application.',
    'A link or redirect could load an external page in an application window, where it would inherit the window’s preload script, session and other privileges.',
    'Block navigation to unapproved destinations in `will-navigate` and `will-redirect` handlers, allowing only the application’s own origins. Verify that links and redirects to an external origin are blocked.'
  ],
  'Popup or middle-click': [
    'Page content can open new windows, through scripted popups, links or middle-clicks, without restriction.',
    'A crafted link could open an external page in a new application window with privileges it should not have, or pass an unsafe destination to the operating system.',
    'Deny new windows by default in `setWindowOpenHandler()`, and open approved external links in the system browser after validating their scheme and destination. Verify ordinary clicks, middle-clicks and scripted popups.'
  ],
  'Privileged procedure exposed': [
    'The application exposes procedures through a single inter-process channel (a remote procedure call router), and some of them write or delete files, open paths, change network settings or return decrypted secrets for any page that can reach the channel.',
    'If script runs in any page that can reach the channel, through cross-site scripting or less trusted embedded content, it could call these procedures with its own input and act with the privileges of the main process.',
    'Restrict each procedure to the pages that need it by checking the sender, validate every input against the narrowest acceptable values (for example, keep file paths inside an application folder), and remove procedures the interface does not use. Verify that a call from an unapproved page is rejected.'
  ],
  'HTML built from unescaped values': [
    'The application builds HTML by inserting values, such as titles, tags or names, into a markup template without escaping them.',
    'If an attacker can influence one of those values, for example a shared note title, their markup and script would run wherever the built HTML is displayed, exported or printed.',
    'Escape every value for the context it is placed in (element text or attribute value), or build the document with DOM methods that treat values as text. Verify that a title containing markup appears as text in the output.'
  ],
  'Pasted, dropped or opened content': [
    'Content the user pastes, drops or opens in the application reaches a sensitive operation, such as HTML insertion or file access, without validation.',
    'A crafted file or clipboard content, for example from a shared document, could carry markup or paths that the application acts on with its own privileges.',
    'Treat pasted, dropped and opened content as untrusted: sanitise HTML before insertion and validate file names and types before use. Verify that a harmless crafted file is handled as data.'
  ],
  'Update files fetched during testing': [
    'The application downloaded an update while it was being tested.',
    'Later testing could examine a different version from the one assessed, so results may not reflect the release in scope.',
    'Disable automatic updates in the test environment, or confirm the version before each session.'
  ],
  'Authentication skipped in one mode': [
    'The application runs a local service whose authentication middleware is skipped in the desktop build, so the listed routes answer requests that carry no credentials.',
    'Any program on the computer, or a web page that can reach the port (for example through a permissive cross-origin policy or DNS rebinding), could read or change the user’s data through these routes.',
    'Require the same authentication on every route in every build, for example a per-session token the application’s own windows hold. Verify that a request without the token is rejected.'
  ],
  'Cross-origin reads allowed': [
    'The application’s local service allows other web origins, or browser extensions, to read its responses.',
    'A web page or extension the user opens could call the service in the background and read the data it returns, and possibly act on the user’s behalf.',
    'Allow cross-origin requests only from the application’s own origins, bind the service to the loopback interface, and require authentication. Verify that a request with a foreign Origin header is refused.'
  ],
  'Page-chosen destination': [
    'The main process stores an address sent by a page and later loads it in application windows.',
    'A page that can send the message, for example through a cross-site scripting flaw or a less trusted site opened in an application window, could load its own content into windows that have the application’s privileged functions.',
    'Keep the application’s addresses in the main process, or accept only addresses on the application’s own domains over HTTPS. Verify that an address on another domain is rejected.'
  ],
  'Page-chosen credential destination': [
    'The main process stores an address sent by a page and later sends requests carrying the user’s access token to it.',
    'A page that can send the message could have the user’s access token sent to a server of its choosing, and use it to act as the user against the application’s services.',
    'Send the access token only to the application’s own API addresses, held in the main process. Verify that a request to an address on another domain is not sent with the token.'
  ],
  'Installation folder writable by other accounts': [
    'The permissions of the application’s installation folder allow accounts other than its owner and administrators to modify the files in it.',
    'Another user or a program running under another account on the same computer could replace the application’s files, so that their code runs the next time the application is started, with the privileges of the user who starts it.',
    'Install the application in a folder that only administrators (or, for a per-user installation, only the owning user) can modify, and remove write access for broad groups such as Users and Authenticated Users. Verify with icacls that a standard user cannot modify the folder.'
  ],
  'Page-written file opened': [
    'A message handler writes a file whose name and content are supplied by the user interface, then asks the operating system to open it with its default program.',
    'Script able to send the message could write a script, shortcut or other executable file and have it run with the privileges of the logged-in user, in a single step and without any further interaction.',
    'Generate the file name in the main process, or accept only names that match the expected pattern and an allowlisted document extension, keep the file inside the application’s own folder, and open only file types the application created. Verify that a name with another extension or a path separator is rejected.'
  ],
  'Program found through the working directory': [
    'The application starts a program or script named by a path relative to the folder it was started from, rather than its installation folder.',
    'If the application is started from a folder an attacker can write to, for example by opening a document from a download or shared folder, a file planted there could run instead of the shipped one.',
    'Build the path from the installation folder (process.resourcesPath or __dirname). Verify that starting the application from another folder still runs the shipped file.'
  ],
  'Values from the user interface in a query': [
    'The application builds a database query by inserting a value received from the user interface into the statement text.',
    'Script running in an application window could read or change other records in the database through this query, beyond what the interface allows.',
    'Pass the value as a query parameter, or reject anything other than the expected type (for example, an integer identifier). Verify that a value containing a quote is treated as data.'
  ],
  'Values from other data in a query': [
    'The application builds a database query by inserting values from other data, such as stored records, into the statement text.',
    'A stored value containing SQL syntax could change the query when it is read back (second-order injection).',
    'Pass every value as a query parameter. Verify with a stored value that contains a quote.'
  ],
  'Embedded content': [
    'The application allows embedded content, through `<webview>` tags or iframes, without restricting its source and privileges.',
    'Less trusted embedded content could gain privileges, such as Node.js access or the parent window’s preload script, that should be limited to the application’s own pages.',
    'Avoid `<webview>` where possible. Otherwise, validate the source and settings of each embedded view before it is created (`will-attach-webview`) and apply the `sandbox` attribute to iframes. Verify the settings in effect at runtime.'
  ],
  'Permission request callback': [
    'The application grants browser permission requests, such as camera, microphone, location or notifications, without checking which page is asking or which permission is requested.',
    'Any page loaded in the application, including injected or external content, could obtain these capabilities without the user being asked.',
    'Handle permission requests with `setPermissionRequestHandler()`, granting only the specific permissions the application needs to its own origins and denying all others. Verify that a request from an unapproved origin is denied.'
  ],
  'Synchronous permission check': [
    'Permission checks made by browser features are allowed by default, because the application does not handle them with `setPermissionCheckHandler()`.',
    'Some features consult this check rather than a permission request, so they could be used even where permission requests are restricted.',
    'Handle permission checks with `setPermissionCheckHandler()`, applying the same rules as for permission requests. Verify that an unapproved origin is denied on both paths.'
  ],
  'HTML sink or editor': [
    'The application inserts dynamic content into a page as HTML, for example through `innerHTML` or a rich-text editor, without sanitising it first.',
    'If an attacker can influence that content, for example by saving it for another user to view, their markup and script would run in the viewer’s application window, with access to the user’s session and to any privileged functions available to the page.',
    'Render untrusted content as text. Where HTML formatting is required, sanitise it with a maintained library (such as DOMPurify) before insertion, allowing only the elements and attributes needed. Verify that a harmless script test is displayed as text.'
  ],
  'Sanitiser or framework bypass': [
    'An HTML sanitiser or framework protection is configured, or overridden in code, so that it allows script-bearing markup through.',
    'Content that passes through the affected path could run script in the application window, despite the expected protection.',
    'Remove trust overrides for user content and restore a restrictive sanitiser configuration. Verify that markup containing script is removed while permitted formatting still works.'
  ],
  'Runtime reflection or message': [
    'During testing, test input was returned by the application and rendered or relayed as markup, for example in a page, a response or a WebSocket message.',
    'Content that reaches another user in this way could run in their application window if it contains script.',
    'Encode or sanitise content where it is rendered, and apply a restrictive Content Security Policy as an additional control. Repeat the same test and confirm the test input is displayed as text.'
  ],
  'Markup without proven execution': [
    'During testing, a harmless test marker containing HTML was rendered as live markup rather than as text.',
    'Because the application renders this content as HTML, markup carrying script could run in the same view, which is the condition required for cross-site scripting.',
    'Replace the unsafe rendering with text output, or sanitise the HTML before it is inserted. Repeat the test and confirm the marker is displayed as text.'
  ],
  'Script execution observed': [
    'During testing, a harmless test script entered through the application’s normal workflow executed in an application window.',
    'An attacker able to enter content in the same way could run script in the window of any user who views it, with access to that user’s session and to any privileged functions available to the page.',
    'Fix the rendering path so the content is displayed as text or sanitised HTML, and restrict the window’s privileges. Repeat the same test and confirm the script no longer executes.'
  ],
  'No effective policy': [
    'No Content Security Policy is applied to the application’s pages.',
    'Without a policy, the browser places no restrictions on the scripts and other resources that injected content can load and run, so an injection flaw has its full effect.',
    'Define a restrictive Content Security Policy for every page, for example `default-src \'self\'; script-src \'self\'; object-src \'none\'`, delivered as a response header or meta tag. Verify the policy is applied in the packaged application and that legitimate content still loads.'
  ],
  'Unsafe script directives': [
    'The Content Security Policy in use allows inline script, string evaluation or script from overly broad sources, or omits directives that restrict injected content.',
    'Injected markup could still run script that a stricter policy would block, which reduces the protection the policy provides.',
    'Remove `unsafe-inline` and `unsafe-eval` from script directives where possible, limit script sources to specific origins, nonces or hashes, and set `object-src \'none\'`, `base-uri` and `form-action`. Verify that legitimate scripts run and injected script is blocked.'
  ],
  'Runtime violation or mismatch': [
    'During testing, the Content Security Policy applied at runtime differed from the expected configuration, or the policy reported violations.',
    'A policy that differs from the intended one may leave pages without the expected protection, or block functionality users rely on.',
    'Align the policy delivered at runtime with the intended policy and fix the resources that trigger violations. Verify the expected functionality works and that an unapproved source is blocked.'
  ],
  'Script evaluation permitted': [
    'During testing, a harmless test payload executed in an application window and was able to call `eval()`, because the page’s Content Security Policy does not block string evaluation.',
    'Where injected content runs as script, permitted evaluation makes it easier to turn data into executable code and limits the policy’s ability to contain the injection.',
    'Remove `unsafe-eval` from the policy of the affected page and replace string evaluation in the application code. Repeat the test and confirm the evaluation is blocked.'
  ],
  'Untrusted document intake': [
    'The application accepts documents from users or external sources and processes them with a parser or converter.',
    'A malformed or malicious document could exploit a flaw in the parser, causing the application to fail or, in the worst case, run code.',
    'Restrict accepted file types and sizes, keep parsers up to date, and process documents in an isolated process with minimal privileges. Verify that unsupported formats are rejected.'
  ],
  'Rendered conversion output': [
    'Documents are converted to HTML and displayed in an application window, without the converted output being sanitised.',
    'A document containing active markup or links to external resources could run script or load attacker-chosen content when it is viewed.',
    'Sanitise converted HTML, block external resources and display the result in a restricted window. Verify that a test document containing markup and an external link is displayed without executing or loading them.'
  ],
  'Local Node entry points': [
    'The application’s Electron fuses leave Node.js entry points enabled, such as `RunAsNode`, the `NODE_OPTIONS` environment variable or the `--inspect` debugging arguments.',
    'Someone able to start the application on the device, including malware running as the user, could use these entry points to run arbitrary code under the application’s identity and with any trust the application has been granted, for example by security software.',
    'Disable the `RunAsNode`, `EnableNodeOptionsEnvironmentVariable` and `EnableNodeCliInspectArguments` fuses when packaging the application. Verify the values with `npx @electron/fuses read --app <executable>`.'
  ],
  'Asar integrity and loading': [
    'The application’s Electron fuses do not enforce the integrity of the application archive (`app.asar`) or restrict loading code to it.',
    'Someone able to modify the installation folder could change the application’s code without detection, and the modified code would run whenever a user starts the application.',
    'Enable the `EnableEmbeddedAsarIntegrityValidation` and `OnlyLoadAppFromAsar` fuses when packaging the application. Verify that the application refuses to start with a modified test archive.'
  ],
  'Cookie or file-protocol privileges': [
    'The application’s Electron fuses leave cookie encryption disabled, or grant extra privileges to content loaded over `file:` URLs.',
    'Cookies, including session cookies, are stored unencrypted in the user’s profile, and `file:` content has more access than the application needs.',
    'Enable the `EnableCookieEncryption` fuse and disable `GrantFileProtocolExtraPrivileges` when packaging the application. Verify the values in the shipped executable.'
  ],
  'Source map exposure': [
    'The distributed application includes source maps, which contain or point to the application’s original source code.',
    'Anyone who obtains the application can read its original source code and internal file paths, which makes it easier to understand its logic and identify weaknesses.',
    'Remove source maps from distributed builds, or upload them only to a restricted error-reporting service. Verify that the final package contains no source maps.'
  ],
  'Asar integrity': [
    'The application archive (`app.asar`) is not checked against an integrity hash embedded in the executable.',
    'Someone able to modify the installation folder could change the application’s code without detection, and the modified code would run whenever a user starts the application.',
    'Enable embedded archive integrity validation and the `OnlyLoadAppFromAsar` fuse. Verify that the application refuses to start with a modified test archive.'
  ],
  'Publisher signature': [
    'The distributed executable or installer does not have a valid publisher signature and timestamp.',
    'Users and security software cannot verify who published the software or whether it has been modified since release, and Windows displays security warnings when it is run.',
    'Sign and timestamp every released executable and installer with the organisation’s code-signing certificate. Verify the signature, signer and timestamp on the distributed files.'
  ],
  'Platform exploit mitigations': [
    'One or more exploit mitigations provided by the operating system, such as Address Space Layout Randomisation (ASLR) or Data Execution Prevention (DEP), are not enabled for a distributed executable or native module.',
    'If a memory corruption flaw exists in the affected file, the missing mitigation makes it easier to exploit.',
    'Build executables and native modules with the platform’s exploit mitigations enabled. Verify the flags on the released files.'
  ],
  'Update feed transport': [
    'The application’s update feed is configured to use a connection that does not protect the update information in transit, such as unencrypted HTTP.',
    'An attacker on the network path could change the update information the application receives, for example to offer an older or malicious release.',
    'Serve update information and packages over HTTPS with certificate validation. Verify the URLs used during an update check.'
  ],
  'Update signature or publisher': [
    'The update process can install an update without verifying its publisher signature.',
    'An attacker able to substitute an update, for example through a compromised server or network path, could have malicious software installed for every user.',
    'Verify the publisher signature of every update before it is installed, including on retries and rollbacks. Verify in a test environment that an update with an invalid signature is rejected.'
  ],
  'Developer tooling or test hooks': [
    'The production build retains developer functionality, such as code that opens the Chromium developer tools or test-only functions.',
    'A user, or someone with access to the device, could use these functions to inspect and modify the application’s behaviour and data, or bypass controls enforced in the user interface.',
    'Disable developer tools and remove test-only functionality from production builds, for example by setting `devTools: !app.isPackaged`. Verify that the developer tools cannot be opened in the released application.'
  ],
  'Logs, console secrets or exceptions': [
    'Sensitive information, such as credentials, tokens or internal details, is written to the application’s logs or console, or disclosed in error messages.',
    'Anyone with access to the logs, crash reports or console could obtain the information.',
    'Remove credentials and other sensitive values from log and console output, restrict access to logs and handle errors without disclosing internal details. Verify the output of the released application.'
  ],
  'Credential or token in code': [
    'A credential, such as an API key, password or token, is embedded in the distributed application.',
    'Anyone who obtains the application can extract the credential and use it with whatever access it grants, until it is revoked.',
    'Revoke and replace the credential, remove it from the application, and keep privileged credentials on the server side. Where a client credential is unavoidable, restrict its permissions to the minimum required. Verify that the released application no longer contains it.'
  ],
  'Public key or false positive': [
    'A value resembling a credential, such as a public key or client identifier, is embedded in the distributed application.',
    'If the value is public by design, it does not give access on its own, but it may still allow use of the associated service or quota.',
    'Confirm the value is intended to be public, and restrict its permissions as tightly as the service allows. Remove test values from production builds.'
  ],
  'Plaintext credential or file': [
    'The application stores a credential or other sensitive value on the device without encryption, for example in a settings file, local storage or a plain text file.',
    'Anyone, or any malware, able to read the user’s profile or a backup of it could recover the value and use it.',
    'Store secrets using the operating system’s protected storage (Electron `safeStorage` or the Windows Credential Manager), remove existing plain-text copies, and keep sensitive data only as long as required. Verify the stored value is encrypted.'
  ],
  'Application settings or cached responses': [
    'The application keeps data that may be sensitive in its settings, cookies or HTTP cache on the device, without additional protection.',
    'Anyone with access to the user’s profile or a backup of it could read cached documents, API responses or session cookies.',
    'Prevent caching of sensitive responses (`Cache-Control: no-store`), enable cookie encryption and keep sensitive values out of general settings. Verify the profile no longer retains the data after use.'
  ],
  'Cleartext HTTP or WebSocket': [
    'The application loads content or communicates over unencrypted HTTP or WebSocket connections.',
    'An attacker on the same network, or anywhere on the network path, could read or modify the traffic, including injecting script into content the application loads.',
    'Use HTTPS and secure WebSocket (WSS) connections for all communication. Verify that no request, redirect or resource uses an unencrypted connection.'
  ],
  'Certificate validation bypass': [
    'Certificate validation is disabled or overridden, so the application accepts invalid TLS certificates.',
    'An attacker on the network path could impersonate the application’s servers with their own certificate, and read or modify traffic that should be protected, including credentials.',
    'Remove the code and settings that accept invalid certificates, and rely on the operating system’s certificate validation. Verify that a connection presenting an invalid test certificate is rejected.'
  ],
  'Credential transport or cookie flags': [
    'Credentials are sent over an unencrypted connection, or cookies are set without the `Secure`, `HttpOnly` or `SameSite` attributes appropriate to their use.',
    'Credentials or session cookies could be read from network traffic, accessed by script running in the page, or sent with requests initiated by other sites.',
    'Send credentials only over HTTPS and set the `Secure`, `HttpOnly` and `SameSite` attributes on session cookies. Verify the attributes in the server’s responses.'
  ],
  'Secret in URL or response': [
    'A sensitive value, such as an access token, is included in a URL or returned in a response where it is not required.',
    'Values in URLs are recorded in proxy and server logs, browser history and `Referer` headers, and unnecessary data in responses can be read by anyone able to call the endpoint.',
    'Send tokens in the `Authorization` header or the request body rather than in URLs, and return only the data each response needs. Verify the value no longer appears in URLs or responses.'
  ],
  'WebSocket secret': [
    'A sensitive value, such as an access token, is sent in a WebSocket URL or message.',
    'Tokens in WebSocket URLs are recorded in server and proxy logs, and messages routed to the wrong recipient could disclose them.',
    'Authenticate WebSocket connections with short-lived tokens sent after the connection is established, and authorise each recipient. Verify the token no longer appears in the URL.'
  ],
  'Third-party destination': [
    'The application sends authentication data or information entered by users to a host that does not belong to the application’s own services.',
    'The third party receives data beyond what is needed for its service, which could breach privacy obligations or expose credentials.',
    'Send authentication headers only to the application’s own services, and minimise the data sent to third parties. Verify the destinations and contents of the application’s requests.'
  ],
  'Unsupported release line': [
    'The application uses an Electron release that no longer receives security updates.',
    'Vulnerabilities discovered after the end of support will not be fixed in this release.',
    'Upgrade to a supported Electron release. Verify the version in the packaged executable.'
  ],
  'Missing Electron or Chromium fixes': [
    'The Electron release in use predates published security fixes for Electron or its bundled Chromium.',
    'Known vulnerabilities in the runtime remain present in the application.',
    'Upgrade to an Electron release that includes the fixes. Verify the version in the packaged executable.'
  ],
  'Published dependency advisory': [
    'A third-party component in use is affected by a published security advisory.',
    'Known vulnerabilities in the component remain present in the application.',
    'Upgrade the component to a fixed version. Verify the version in the packaged application.'
  ],
  'Unsupported library': [
    'A third-party component in use no longer receives security updates.',
    'Vulnerabilities discovered in the component will not be fixed.',
    'Replace or upgrade the component to a maintained release. Verify the version in the packaged application.'
  ],
  'Malicious version in inventory': [
    'The application’s dependencies include a package version that has been identified as malicious.',
    'If the package ran during installation or build, it could have stolen credentials or tampered with the software produced, including releases distributed to users.',
    'Remove the package, replace it with a trusted version and rebuild from a clean environment. Determine where the package was installed and run, and verify the resulting software.'
  ],
  'Exposure response': [
    'Any environment where the malicious package was installed, such as developer workstations, build servers and release pipelines, should be treated as potentially compromised.',
    'Credentials, signing keys and other secrets available in those environments could have been stolen, and software built there could have been modified.',
    'Review installation and build logs to determine where the package ran, rotate credentials and signing material available in those environments, and rebuild affected releases from a trusted environment.'
  ],
  'No certificate pinning': [
    'The application accepts any certificate trusted by the operating system for its own services, without pinning the expected certificates or public keys.',
    'Someone able to install a trusted certificate on the device, or a compromised certificate authority, could intercept the application’s encrypted traffic.',
    'Determine from the threat model whether certificate pinning is required for the application’s services. Where it is, verify the server’s certificate or public key against a pinned set in `setCertificateVerifyProc()`, with a plan for certificate rotation, and confirm that an intercepting proxy’s certificate is rejected.'
  ],
  'HTTPS exchanges in a proxy capture': [
    'During testing, the application’s encrypted traffic was intercepted and read through a proxy using a test certificate trusted on the device.',
    'Anyone able to install a trusted certificate on a user’s device, including malware or a device administrator, could read and modify the application’s traffic in the same way.',
    'Where the threat model requires it, pin the certificates or public keys of the application’s services and reject connections that do not match. Repeat the interception test and confirm the connection is refused.'
  ],
};

// How each scenario is named in a client finding: a short statement of the problem
export const CLIENT_LABELS = {
  'Node access in a renderer': 'Node.js integration enabled',
  'Isolation or sandbox disabled': 'Context isolation or sandbox disabled',
  'Additional privilege sharing': 'Remote module or process affinity in use',
  'Injected script reached Node or Electron APIs': 'Injected script reached Node.js or Electron',
  'Origin or transport protections': 'Browser security protections disabled',
  'Experimental or legacy capability': 'Unnecessary browser features enabled',
  'Warning or keyboard safeguard': 'Security warnings or Secure Keyboard Entry disabled',
  'Broad preload bridge': 'Privileged functionality exposed by the preload script',
  'Shared session between trust levels': 'Session shared between windows of different trust',
  'Sender not restricted': 'Message sender not validated',
  'Arguments or file paths trusted': 'Message arguments not validated',
  'Unused or unexpected channel': 'Message handler with no identified caller',
  'Installation folder writable by other accounts': 'Installation folder writable by other accounts',
  'External URL or protocol': 'Unvalidated URLs opened by the operating system',
  'Non-web protocol launch': 'Non-web protocols not blocked',
  'Network-share credential exposure': 'Network share locations not blocked',
  'File path handed to the host': 'Unvalidated file paths opened by the operating system',
  'Executable file path': 'Executable files not blocked',
  'Download or shortcut destination': 'Unvalidated download or shortcut destination',
  'Shell command construction': 'Operating system command built from variable input',
  'Dynamic code evaluation': 'Variable input evaluated as code',
  'Untrusted module path': 'Module loaded from a variable path',
  'Word launch command': 'Microsoft Word started with variable arguments',
  'Document provenance and Protected View': 'Mark of the Web not preserved',
  'External handler input': 'Unvalidated deep link or file association input',
  'Privileged custom scheme or file URL': 'Excessive custom protocol or file URL privileges',
  'Untrusted URL loaded in an app window': 'Untrusted URL loaded in an application window',
  'Top-level navigation or redirect': 'Navigation and redirects not restricted',
  'Popup or middle-click': 'New windows not restricted',
  'Embedded content': 'Embedded content not restricted',
  'Page-chosen destination': 'Page decides the address application windows load',
  'Page-chosen credential destination': 'Page decides where the access token is sent',
  'Page-written file opened': 'File written from page input and opened by the operating system',
  'Program found through the working directory': 'Program started from the working directory',
  'Values from the user interface in a query': 'Query built from user interface values',
  'Values from other data in a query': 'Query built from stored values',
  'Authentication skipped in one mode': 'Authentication skipped in the desktop build',
  'Cross-origin reads allowed': 'Local service readable from other origins',
  'Privileged procedure exposed': 'Privileged procedures exposed over IPC',
  'HTML built from unescaped values': 'HTML built from unescaped values',
  'Pasted, dropped or opened content': 'Pasted or opened content not validated',
  'Update files fetched during testing': 'Update downloaded during testing',
  'Permission request callback': 'Permission requests granted without restriction',
  'Synchronous permission check': 'Permission checks granted without restriction',
  'HTML sink or editor': 'Dynamic content inserted as HTML',
  'Sanitiser or framework bypass': 'Sanitiser or framework protection bypassed',
  'Runtime reflection or message': 'Test input reflected as markup',
  'Markup without proven execution': 'Test markup rendered as live HTML',
  'Script execution observed': 'Script execution confirmed',
  'No effective policy': 'No Content Security Policy',
  'Unsafe script directives': 'Content Security Policy allows unsafe script',
  'Runtime violation or mismatch': 'Content Security Policy differs at runtime',
  'Script evaluation permitted': 'Script evaluation permitted',
  'Untrusted document intake': 'Untrusted documents processed',
  'Rendered conversion output': 'Converted document content rendered',
  'Local Node entry points': 'Node.js entry points enabled',
  'Asar integrity and loading': 'Archive integrity not enforced',
  'Cookie or file-protocol privileges': 'Cookie encryption or file protocol fuse insecure',
  'Source map exposure': 'Source maps distributed',
  'Asar integrity': 'Archive integrity not enforced',
  'Publisher signature': 'Executable not signed',
  'Platform exploit mitigations': 'Exploit mitigations missing',
  'Update feed transport': 'Update information not protected in transit',
  'Update signature or publisher': 'Update signature not verified',
  'Developer tooling or test hooks': 'Developer tools or test functions available',
  'Logs, console secrets or exceptions': 'Sensitive information in logs or errors',
  'Credential or token in code': 'Credential embedded in the application',
  'Public key or false positive': 'Public key or identifier embedded in the application',
  'Plaintext credential or file': 'Credential stored without encryption',
  'Application settings or cached responses': 'Data retained in settings, cookies or cache',
  'Cleartext HTTP or WebSocket': 'Unencrypted connections',
  'Certificate validation bypass': 'Certificate validation disabled',
  'Credential transport or cookie flags': 'Credentials or cookies not adequately protected',
  'Secret in URL or response': 'Sensitive data in URLs or responses',
  'WebSocket secret': 'Sensitive data in WebSocket traffic',
  'Third-party destination': 'Data sent to third parties',
  'Unsupported release line': 'Unsupported Electron release',
  'Missing Electron or Chromium fixes': 'Missing Electron or Chromium security fixes',
  'Published dependency advisory': 'Component with a published advisory',
  'Unsupported library': 'Unsupported component',
  'Malicious version in inventory': 'Known malicious package version',
  'Exposure response': 'Build environments potentially exposed',
  'No certificate pinning': 'No certificate pinning',
  'HTTPS exchanges in a proxy capture': 'Encrypted traffic intercepted by a proxy',
};
