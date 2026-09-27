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
   npm install -g https://github.com/Headset365/electronegativity/archive/refs/heads/master.tar.gz
   electronegativity -V          # prints 2.0.0
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

- Use a **test build** of the app: watch mode loads through `NODE_OPTIONS`, which production builds usually switch off
  with the `EnableNodeOptionsEnvironmentVariable` fuse. If it can't load, the tool says "The app did not load the watch
  mode hook" (the static scan works on any build).
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

1. It prints what it found and the results folder (`C:\electronegativity-results-<date>`), then scans all of the app's
   code, including screens behind the login.
2. It prints a **marker** for this run (e.g. `ENGK7Q2XM`) and asks: **Start watch session 1?** Press Enter. The app
   opens. As **account A**:
   - log in, then open every main screen, menu, dialog and settings page;
   - in the editor: create a document containing the marker (e.g. `Test ENGK7Q2XM`), paste formatted content from Word,
     drag and drop text and a file, import a `.docx`, use any file picker or "open" dialog;
   - share the document with account B (or put it where other users see it: comments, notes, previews);
   - try a `myapp://` link or a file association if the app has them;
   - close the app completely (File > Exit or the tray's Quit).
3. **Optional, tests the server:** before the next session, in Burp, take account A's request that saves a document and
   put this harmless markup in the body: `<span data-ENGK7Q2XM="1">ENGK7Q2XM</span>` (with your marker). The endpoint is
   in `session-1.html` under "API endpoint called", flagged "contains HTML".
4. It asks: **Start watch session 2?** Press Enter. As **account B**: log in, open everything that shows account A's
   content (the document, previews, search results, notifications, comments, exports or print preview), then close the
   app completely.
5. Press `s` when asked about session 3 to finish. The results folder then holds `static.html`, `session-1.html`,
   `session-2.html` and a `-diag.json` file for each.

In `session-2.html`, `RUNTIME_MARKER` HIGH means the marker came back as live markup (stored content reaches another
user's view unneutralized); INFORMATIONAL means it was shown safely as text.

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

# also fetch templates and screens the sessions never opened, from the test server, with account A's cookie from Burp
# (typed at a prompt, which keeps it out of the PowerShell history)
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
`--watch "C:\Program Files\MyApp" -o session.html` for one watch session.

## 5. What to send back

Only the `*-diag.json` files. Open each one first and check it contains nothing identifying: the app name, user name,
machine name, home folder and the `--redact` words are replaced, and hosts are pseudonymized. Keep the `.html` reports
yourself: they contain code locations and URLs.

## 6. Clean up

```powershell
Remove-Item -Recurse -Force "$env:TEMP\electronegativity-watch-*", "$env:TEMP\electronegativity-remote-*"
Remove-Variable Cookie -ErrorAction SilentlyContinue
```

Delete the marker documents from the test environment if others use it.
