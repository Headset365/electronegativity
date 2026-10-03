# Windows watch evidence and bounded proofs

## Passive evidence and reachability

The watch hook observes node-adodb, better-sqlite3 and sqlite3 APIs when they are
loaded through CommonJS. A marker in SQL statement text is recorded at the query
API, including preparation frames when a prepared statement is executed. Bound
parameter markers do not count. No SQL payload is injected and query text and
values are omitted from the evidence. Successful query execution and SQL injection
are separate questions. Bundled private copies, native APIs captured before the
hook, and libraries loaded exclusively through ESM can remain outside coverage.

electron-trpc request envelopes retain their procedure path and whether the
marker was in the input. Local nested routers explicitly registered through
createIPCHandler can be matched by path; a leaf name is matched only when it is
unique. A multiplexed channel does not exercise every procedure. Incoming IPC
HTTP(S) endpoint hosts are correlated with later window navigation; the log stores
hosts without endpoint credentials or query strings and labels the result as a
temporal correlation. Completed filesystem writes and subsequent shell path
handoffs are linked by normalized path and, where possible, the same asynchronous
IPC invocation. An OS handoff is not proof that the file opened or executed.

`--prove` adds synthetic handler checks for `http://<allowed-host>/` and
`https://eng-proof.<allowed-host>/` from static navigation allowlists. These URLs
are never loaded. Window-open decisions record returned preload options without
creating a child or calling createWindow. Naturally created app child windows
record their effective options separately. Electron does not automatically inherit
the parent's preload through its security-preference inheritance rules.
See Electron's [guest-window preference merger](https://github.com/electron/electron/blob/v34.5.8/lib/browser/guest-window-manager.ts).

For observed app-owned loopback TCP listeners, declared GET routes ending in
handshake/status/health/version/info/ping are requested without credentials when
an AUTH_MODE_BYPASS finding lists them as read-only candidates. POST, app.use,
query strings, traversal, mutation-looking paths and inline handlers with known
mutation calls are excluded. Named external handler effects are not comprehensively
resolved. Review any additional routes in a proof profile. Redirects are not followed;
HTTP 200 is an observed response, not a confirmed authentication bypass.

On Windows, `--prove` starts the app in an empty temporary working folder and
records relative child command candidates. No executable is planted. App-owned
process images observed by the Windows inventory provide actual resolution when
available; short-lived children or access restrictions can leave only a calculated
candidate. Folders containing files written by the app are retained instead of
being recursively deleted. Applications depending on their original working
folder may fail to start; that failure is not a successful binary-planting proof.
The launch folder and the effective working directory recorded by the hook are
distinct: Electron or application code can change the latter during startup.

Every static finding carries reachability metadata in report.json and HTML:

| Label | Rating treatment |
| --- | --- |
| Called | Reachable through entry-point references, registered callbacks or a packaged IPC sender; keep rating. |
| Exposed but not called | Preload capability with no established packaged caller; keep rating because remote UI or injected code may call it. Remove it if unused. |
| Development-only | Proven Electron production-state guard excludes the statement; informational. An unknown variable named isDev is insufficient. |
| Unreferenced | Closed static graph has no reachable import, registration or caller; informational with removal advice. |
| Unresolved | Missing entry, dynamic imports/evaluation, classic renderer globals/HTML events, remote scripts, recovered parse errors, framework asset loading, exports, ambiguous bindings or analysis limits; keep rating. |
| Exercised | Runtime evidence overlays the static status with its scope; a channel dispatch is not proof that every statement in its handler ran. |

Static status and session exercise are separate fields. Runtime use contradicting
a reduced rating restores its original rating. An unpackaged development session
exercising an expected development-only branch retains its production observation.
The client Markdown places unreferenced/development-only code under Additional
Security Observations with N/A ratings. Saved-log replay and report rerendering
retain these labels; silence during a watch session never establishes dead code.

These additions target **Windows 10 and Windows 11**. Run as the ordinary tester account first. Access errors, timeouts, incomplete instrumentation and missing contracts are recorded as coverage limits, not safe results. Registry/ACL checks never change the installation. The tool never tests a discovered credential against a live service.

## Start a session

```powershell
node .\src\index.js --watch 'C:\Program Files\Example\Example.exe' --report-dir results
```

Ordinary native watch records install-path ACLs, matching protocol registrations in both HKCU/HKLM and both registry views, process-owned TCP/UDP listeners, observed file zone streams, and the app's user-data/log/crash-dump paths. Use `--app ... --sessions 1 --out results` for the guided static-plus-watch report. A project folder uses its own Electron and does not count that shared executable as a packaged app.

Enable bounded tests explicitly:

```powershell
node .\src\index.js --app 'C:\Program Files\Example' --sessions 1 --prove --proof-profile .\proof.json --out results
```

`--prove` independently runs navigation/new-window handler decisions, camera permission request/check handler decisions, self-signed HTTPS requests through each observed app session, Chromium certificate-error navigation through hidden tool windows, and the Windows packaged RunAsNode exit-code probe. Successful packaged Node inspector attachment is always recorded as evidence because native watch already performs that operation. The CLI-opened inspector and tool-created receivers/windows are excluded from ordinary app exposure findings.

The application is still driven by the tester. Callback probes run after a real app page loads; late hooks and once-only navigation listeners are skipped. Session proof records carry the outcome, time, scope and test inputs. Replaying `--watch-log session.jsonl` reproduces these findings without executing probes again.

## Profiles

Copy `docs/proof.example.json`. The profile contains:

| Field | Contract |
| --- | --- |
| `origins` | Up to eight exact HTTP(S) origins used as foreign handler inputs. Default is `https://eng-proof.invalid`; handler probes do not contact it. |
| `feeds` | Up to eight exact HTTP(S) `latest.yml`/`RELEASES` URLs, without URL credentials. Only metadata is fetched. Empty by default. |
| `links` | A reviewed existing page URL prefix and dotted page API method that accepts one URL. The tester must review the route as safe on a disposable app session. |
| `services` | A reviewed read-only path, loopback port, `http`/`websocket` transport, and expected `requiresAuth` policy. The app must own the observed listener. |

Examples of optional reviewed entries (replace these with the target app's actual contract):

```json
{
  "origins": ["https://eng-proof.invalid"],
  "feeds": ["https://updates.example.com/latest.yml"],
  "links": [{"reviewed": true, "page": "https://app.example.com/", "method": "appLinks.open"}],
  "services": [{"reviewed": true, "port": 8123, "path": "/read-only-status", "transport": "http", "requiresAuth": true}]
}
```

Link tests invoke that existing page API with `file:///C:/eng-proof-does-not-exist.txt` and an unregistered `eng-proof-unregistered:` URL. The actual shell handoff is blocked. Merely invoking the API is not proof of a missing scheme filter: a distinct shell-handoff record is required. Page methods can have app-specific side effects outside the main-process guards, so review the method first.

Service tests make a credential-free GET or WebSocket handshake with no Origin, then with a foreign Origin. They keep status/handshake metadata and disconnect, without retaining bodies or sending WebSocket application messages. Public status routes can legitimately return 200; status alone is not proof of authentication bypass. `requiresAuth` records the tester's policy and is not inferred from the response. The tool never enumerates or probes unrelated machine ports.

The hook observes native/electron-updater `setFeedURL` calls where available, and `--prove` also reads the packaged app's `resources\app-update.yml`: for the `generic`, `github` (public), `s3` and `spaces` providers it works out the exact `latest.yml` (or `<channel>.yml`) address; a private repository, a token, a query string, `${...}` macros or another provider are recorded as skipped with the reason. Exact metadata URLs without query credentials can be inspected automatically under `--prove`; provider URLs and feed directories require an exact profile URL. `--offline` skips feed requests while allowing loopback proofs. Redirect transport, hash syntax/algorithm and publisher metadata are recorded. Missing publisher names are not automatically failures: some feed formats omit them. No artifact is downloaded or installed, and signature/hash enforcement is not inferred from metadata.

## Separate IPC opt-in

```powershell
node .\src\index.js --watch 'C:\Program Files\Example\Example.exe' --ipc-profile .\ipc.json --report-dir results
```

Use `docs/ipc-proof.example.json` as a template. It deliberately has `reviewed: false`; set it to true only after reviewing that exact handler and its callees. Profiles allow at most eight `ipcMain.handle` channels with `read-only` or `file-read` contracts, bounded JSON arguments, and no command/write/delete/install/update channels. File-read arguments must contain `$CANARY_PATH`. The tool creates a random file, supplies a path containing `..` within its own temporary fixture, and removes it afterwards. It never supplies an existing customer's file for a traversal test.

IPC tests use a real, hidden, sandboxed foreign-origin renderer and a tool-supplied preload bridge. They establish handler response and unique canary return. They **do not** establish that an attacker can reach the channel through the app's own preload, escape an app-defined directory, or violate its authorization policy. Missing/once-only/command-capable handlers are skipped. Late hooks skip IPC tests entirely.

Common child-process execution, filesystem mutation, dialog and OS handoff APIs are guarded in probe async contexts, including timers and promises. These guards are defense in depth, **not a sandbox for arbitrary application callbacks or native addons**. They cannot make an unknown handler safe. No command handler is eligible; reviewed read-only contracts and disposable sessions remain required. Normal app calls outside probe contexts continue normally.

## Logout checkpoints and log/dump markers

```powershell
node .\src\index.js --watch 'C:\Program Files\Example\Example.exe' --logout-check --canary 'ENG_unique_test_password_123' --search-dir 'C:\Example\ExtraLogs' --report-dir results
```

1. Sign in and exercise the test workflow, keeping the app open.
2. Type `BEFORE` at the terminal checkpoint. Wait for confirmation that the signed-in snapshot completed.
3. Log out using the app, wait for completion, then type `AFTER`.
4. Close the app to finish the report. `SKIP` leaves the comparison incomplete.

Snapshots compare live cookies plus local/session storage from observed app sessions/pages. Per-run HMACs identify unchanged values without writing raw cookie/storage values or their names. Credential-like names are labelled candidates, not verified credentials. File snapshots and supplied `--canary` passwords/tokens cover the reported profile, logs, crash-dumps and `--search-dir` roots. Existing bounded scanners look for plaintext/common encodings; they do not decrypt secrets. Repeated `--canary` options can supply both a test password and test tokens. Extra log paths can be supplied without changing the profile path.

Unchanged historical log/dump bytes can remain after logout without an active credential remaining. The file comparison reports this separately from live-value retention. IndexedDB values, unvisited origins, OS credential values, encrypted secrets and server-side invalidation are outside the live-value comparison. Storage errors and missing/out-of-order snapshots remain visible. Logout checkpoints need an interactive terminal and a separate session from `--auto-campaign` so there is one terminal prompt owner.

## What each result establishes

| Area | Evidence and limit |
| --- | --- |
| Navigation/popups | Captured app callbacks allowed/blocked synthetic URL inputs. No app navigation or popup is performed. This is handler-decision evidence, not foreign-renderer reachability. |
| Permissions | Camera request/check handlers receive a foreign requesting URL/origin and the existing real renderer. Its actual URL is recorded; handlers consulting that actual renderer can behave differently for a real foreign renderer. No camera device is opened. |
| Certificates | Unique tool response accepted over self-signed loopback HTTPS, separately through session network and Chromium navigation. Success proves acceptance at that endpoint/time; other hosts and the responsible bypass mechanism are not established. Failures distinguish certificate rejection, transport failure and timeout. |
| RunAsNode | Only exit 42 for the tool's expression confirms execution. A pinned disabled fuse skips a second app launch. Other exit codes/timeouts are inconclusive. |
| Node inspector fuse | Actual successful CLI inspector attachment. The tool opened this port; ordinary app launches were not observed to expose it. |
| Mark-of-the-Web | Read the observed file's `Zone.Identifier`, keeping only ZoneId/status. Missing files, absent streams and access denial differ. This does not establish Word Protected View behavior. |
| Shell schemes | A reviewed existing link route reached a blocked real shell API. Directly calling shell yourself is never treated as an app filter test. |
| IPC | Real foreign sender and a unique tool-owned canary. App bridge exposure, intended path policy and privileged business effects remain untested. |
| Updates | Metadata transport/hashes/publisher fields. Actual publisher and artifact verification remain untested. |
| Dependencies | Actual `app.asar`/unpacked installed package manifests and detected library copies take priority over lockfile declarations, even if declared dev. Development-only metadata stays in the catalog for build/supply-chain review. Missing package manifests do not prove absence from bundles. |
| Static/runtime differences | Flag uniquely matched preload setting differences, and session-wide Node integration contrasts. Static findings retain severity; unvisited code is not declared dead. |
| Install permissions | SIDs/allow/deny/inheritance for folder, executable, DLLs and resources. Broad and current-token write grants are recorded, including elevation context. DACL grants alone do not prove effective write access or privilege escalation. |
| Protocol registry | App-executable matches across both hives/views, executable/URL quoting and switch delimiter. Second-instance argument counts/switch names are observed, without storing URL arguments. Actual switch injection and parser validation remain untested. |
| Listening services | App process tree, TCP/UDP addresses and ports; tool ports excluded. Authentication/origin requests require reviewed read-only route contracts. |
| Logs/crash dumps | Supplied test-marker hits within reported/app-scoped folders and scan bounds. No decryption or live token use. |
| Logout | Before/after live-value and file-marker retention, with explicit coverage limits. Retention does not prove that a credential still works. |
| Live credentials | Manual checklist only; testing against a live service requires the client's written permission. |

The PEM files under `src/watch/fixtures` are public test-only loopback credentials. They are not trusted or installed in Windows certificate stores and must never be used for a real server.

## Validation on Windows 10 and 11

On each OS, from a normal non-administrator terminal:

```powershell
npm ci
npm install --no-save --package-lock=false electron@38
npm run test:windows-proofs
```

The suite forbids skipping native Windows fixtures. It checks permissive/hardened packaged apps, real NTFS streams, temporary tool-owned HKCU protocol keys and app-owned listener attribution. CI runs these fixtures with Electron 34 and 38 on its Windows runner. Hosted Windows CI is not a claim that both desktop OS versions have been exercised: record the Windows 10/11 local runs separately. Then use a disposable target app to validate the reviewed link/service/IPC contracts and interactive logout workflow.
