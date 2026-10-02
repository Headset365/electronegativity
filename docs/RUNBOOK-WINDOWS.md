# Running Electronegativity on a Windows host against a packaged app (.exe)

Run everything against a **test environment** with **test accounts**, never production. All commands are PowerShell.

## 1. Install

1. Install Node.js **24 LTS** (x64 `.msi`) from <https://nodejs.org/>, with the defaults. Git is not needed.
2. Open a **new** PowerShell window (so the new `PATH` applies) and check the version: it must be 24.11 or later (or 22.18+).

   ```powershell
   node -v
   ```

3. Install the tool from GitHub (no administrator rights needed; it installs for your user):

   ```powershell
   npm install -g https://github.com/Headset365/electronegativity/archive/refs/heads/merged-electron-dynamic.tar.gz
   electronegativity -h | findstr debug-launch   # prints a line: this branch is installed
   ```

   To update later, run the same `npm install -g` command again.

   If PowerShell refuses to run `electronegativity` ("running scripts is disabled"), use `electronegativity.cmd` instead, or
   run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

4. Network (only if it applies to this host):

   ```powershell
   # outbound traffic goes through a proxy (needed for the advisory lookups and --remote)
   $env:HTTPS_PROXY = "http://proxy.example:8080"; $env:NODE_USE_ENV_PROXY = "1"
   # the test server's HTTPS certificate comes from an internal CA (needed for --remote only)
   $env:NODE_EXTRA_CA_CERTS = "C:\certs\internal-ca.pem"
   ```

   With no internet access at all, add `--offline` to every command below (the Electron end-of-life and advisory checks
   are then skipped).

## 2. Before you start

- Watch mode loads its observer into the installed app through the Node inspector (started on a local port for the
  session only). Builds with the `EnableNodeCliInspectArguments` fuse off can't be observed: the tool checks this before
  starting and says so (the static scan works on any build). If that happens, use a test build with the fuse on.
- Close the app completely, including any tray icon: a second copy usually hands over to the running one and exits.

  ```powershell
  Get-Process MyApp -ErrorAction SilentlyContinue | Stop-Process
  ```

## 3. Run it

Point the tool at where the app is installed. It finds the executable and the app's code itself (install folder, the
`.exe`, Squirrel's `app-<version>` folders, or the folder above the install folder such as `C:\Program Files\<Company>`):

```powershell
cd C:\
electronegativity --app "C:\Program Files\MyApp" --redact "CompanyName,internal.host.name"
```

`--redact` is optional: the app's name, your user name, the machine name and your home folder are always removed from the
diagnostics files; list any other words to remove (company name, internal host names).

What happens:

1. It prints what it found and the results folder (`C:\electronegativity-<UTC date and time>`, e.g. `C:\electronegativity-2026-09-30T08-52-43Z`), then scans all of the app's
   code, including screens behind the login.
2. It prints a **marker** for this run (e.g. `ENGK7Q2XM`) and asks: **Start watch session 1?** Press Enter. The app
   opens. As **account A**:
   - log in, then open every main screen, menu, dialog and settings page;
   - in the editor: create a document containing the marker (e.g. `Test ENGK7Q2XM`), paste formatted content from Word,
     drag and drop text and a file, import a `.docx`, use any file picker or "open" dialog;
   - share the document with account B (or put it where other users see it: comments, notes, previews);
   - try a `myapp://` link or a file association if the app has them;
   - close the app completely (File > Exit or the tray's Quit).
   While the app runs, the terminal shows `[validate]` lines: follow them. They ask you to send a request again with the
   marker in named fields, to paste formatted content (open the `<marker>-paste-me.html` file from the results folder in
   a browser, select all, copy, paste into the editor), to click the marker link `https://example.invalid/<marker>`
   placed in a document, or to attach the `<marker>.txt` file. They also say what the marker showed (✓ shown safely or
   blocked, ✗ confirmed). A summary is printed when the app closes.
3. **Optional, tests the server:** before the next session, in Burp, take account A's request that saves a document and
   put this harmless markup in the body: `<span data-ENGK7Q2XM="1">ENGK7Q2XM</span>` (with your marker). The endpoint is
   in `steps\session-1-report.html` under "API endpoint called", flagged "contains HTML".
4. It asks: **Start watch session 2?** Press Enter. As **account B**: log in, open everything that shows account A's
   content (the document, previews, search results, notifications, comments, exports or print preview), then close the
   app completely.
5. Press `s` when asked about session 3 to finish. The results folder then holds:
   - `report.html` and `report.json`: **one report of the whole run**, the static findings with what each session
     validated (marked with the session that showed it) and what the sessions found;
   - `reports\`: the client findings, one Markdown file per finding, ready for the client report (Australian English,
     reproduction steps and recommendations as bullets, the app named after its `.exe`), and `components.xlsx`, the
     components workbook the "Outdated Software Components" finding refers to (its links are checked; any that couldn't
     be are named in its "Links to validate manually" column);
   - `testerNotes\`: for each finding, your working notes: how it was rated, every instance with its recorded evidence
     (including those left out of the client finding), how to check each one by hand, and what the sessions covered.
     They are not for the client;
   - `diagnostics.json`, with a section per step;
   - `steps\`: each step's own reports (`static-report.html`, `session-1-report.html`, ...), kept as backups.

In the report, use the **Validation** filter: "Seen at runtime" lists the findings the marker reached (with the
script line for HTML sinks), "Confirmed at runtime" the ones the captured traffic proved (requests over plain http, an
intercepting proxy's certificate accepted), and "Needs review, not validated" what is left, each with how to check it.

In `report.html`, `RUNTIME_MARKER` LOW (with `live` in its details) means the marker came back as live markup (stored
content reaches another user's view unneutralized, script execution not proven); INFORMATIONAL means it was shown safely
as text. Don't filter the report to HIGH only: this finding would be hidden.

The code the app's pages loaded from the server is downloaded during each session with your logged-in session and
scanned too: findings in it point at the URL it came from.

## 4. Useful variations

```powershell
# point at the .exe directly, or choose the results folder
electronegativity --app "$env:LOCALAPPDATA\MyApp\app-2.4.1\MyApp.exe" --out C:\eng-results

# static scan only (no sessions), or two sessions without being asked
electronegativity --app "C:\Program Files\MyApp" --sessions 0
electronegativity --app "C:\Program Files\MyApp" --sessions 2

# the app needs command-line arguments, or shows a blank window on a VM
electronegativity --app "C:\Program Files\MyApp" --watch-args "--disable-gpu"

# also fetch templates and screens the sessions never opened, from the test servers only (nothing from any other host),
# logged in with the same Cookie and Authorization the app sent them during the session (log in, use the app, close it
# without logging out: the download runs right after)
electronegativity --app "C:\Program Files\MyApp" --remote app.example.com,api.example.com --remote-header Authorization,Cookie

# or set a header by hand, e.g. account A's cookie from Burp (typed at a prompt, which keeps it out of the PowerShell history)
$Cookie = Read-Host "Cookie (name=value)"
electronegativity --app "C:\Program Files\MyApp" --remote https://test-server.example/ --remote-header "Cookie: $Cookie"

# the Electron version couldn't be detected (the output says "Couldn't detect Electron version")
electronegativity --app "C:\Program Files\MyApp" -e 38.2.0

# only HIGH and MEDIUM findings with firm or certain confidence in the reports
electronegativity --app "C:\Program Files\MyApp" -s medium -c firm

# re-analyze a session without running the app again (the log path is printed at the end of each session)
electronegativity --watch-log "$env:TEMP\electronegativity-watch-XXXXXX\session.jsonl" -i "C:\Program Files\MyApp" -r -o session-1b.html
```

The individual options still work on their own: `-i "C:\Program Files\MyApp" -o static.html` for a static scan, and
`--watch "C:\Program Files\MyApp" -o session.html` for one watch session. Every run also writes the client findings and
the components workbook to a `reports` folder, and the tester notes to a `testerNotes` folder next to it: in the run's
report folder, next to the first `-o` file, or in the folder you ran it from, with `report.json` next to them: the data
the findings were written from.

### Updating the findings of an earlier scan to new templates

After a finding template changes (a revised fuse finding, say), the findings of an earlier scan can be written again
from that scan's `report.json`, without scanning again:

```powershell
electronegativity --rerender "C:\eng-results\report.json"
```

The new findings go to `reports\newReports\`, with a new `components.xlsx`, and their tester notes to
`reports\newTesterNotes\`. All their content comes from the scan's data; the earlier findings are only read and left as
they are. `reports\newReports-review.md` lists what was changed by hand in the earlier findings (a rating, an edited,
added or removed section), quoting the earlier text so you can carry it over. A finding since renamed (such as "Renderer
Isolation Weakened", now "Insufficient Renderer Process Isolation") is compared with its new file. For findings written
before this version, the tool can't tell a template change from a manual edit: the review then lists every part that
differs, for you to check. Use `--old-reports <folder>` if the earlier findings are not in the `reports` folder next to
`report.json` (an older scan may have them in a `markdown` folder, which is found by itself).

## 5. What to send back

Only `diagnostics.json`. Open it first and check it contains nothing identifying: the app name, user name,
machine name, home folder and the `--redact` words are replaced, and hosts are pseudonymized. Keep the `.html` reports
yourself: they contain code locations and URLs.

## 6. Clean up

```powershell
Remove-Item -Recurse -Force "$env:TEMP\electronegativity-watch-*", "$env:TEMP\electronegativity-remote-*"
Remove-Variable Cookie -ErrorAction SilentlyContinue
```

Delete the marker documents from the test environment if others use it.
