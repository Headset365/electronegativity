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

## 2. Prepare

1. Find the app's real executable and check that `resources\app.asar` (or a `resources\app` folder) is next to it:

   | Installer | Typical location |
   |---|---|
   | NSIS, per user | `$env:LOCALAPPDATA\Programs\<App>\<App>.exe` |
   | NSIS / MSI, per machine | `C:\Program Files\<App>\<App>.exe` |
   | Squirrel | `$env:LOCALAPPDATA\<App>\app-<version>\<App>.exe` (not the `<App>.exe` one folder up, which is only a launcher) |

   ```powershell
   Test-Path "C:\Program Files\MyApp\resources\app.asar"     # must be True (or resources\app for an unpacked app)
   ```

2. Use a **test build**: watch mode loads through `NODE_OPTIONS`, which production builds usually switch off with the
   `EnableNodeOptionsEnvironmentVariable` fuse. If the hook can't load, the tool says "The app did not load the watch mode hook"
   and the diagnostics file shows `"hookStarted": false`. The static scan (step 3.1) works on any build.

3. Close the app completely, including any tray icon, before each watch session: a second instance usually hands over to
   the running one and exits, and nothing gets observed.

   ```powershell
   Get-Process MyApp -ErrorAction SilentlyContinue | Stop-Process
   ```

4. Set these once per PowerShell window (adjust the values):

   ```powershell
   $App    = "C:\Program Files\MyApp\MyApp.exe"
   $Asar   = "C:\Program Files\MyApp\resources\app.asar"
   $Redact = "CompanyName,ProductName,internal.host.name"   # extra words to remove from diagnostics files
   $Marker = "ENG42X"                                       # a unique token for planted content
   mkdir C:\eng-results -Force; cd C:\eng-results
   ```

## 3. Runs

### 3.1 Static scan of the app package

Reads all of the app's code, including screens behind the login.

```powershell
electronegativity -i $Asar -r -o 01-static.html --diagnostics 01-static-diag.json --redact $Redact
```

Optional extra formats of the same scan: `-o 01-static.json`, `-o 01-static.sarif` or `-o 01-static.csv`.

### 3.2 Watch session 1: author account

```powershell
electronegativity --watch $App --watch-marker $Marker -r -o 02-watch-author.html --diagnostics 02-watch-author-diag.json --redact $Redact
```

The app opens. As **account A**:

- log in, then open every main screen, menu, dialog and settings page;
- in the editor: create a document containing the marker as plain text (e.g. `Test ENG42X`), paste formatted content
  from Word, drag and drop text and a file, import a `.docx`, use any file picker or "open" dialog;
- share the document with account B (or put it wherever other users see it: comments, notes, previews);
- if the app handles links or file types from outside (`myapp://` links, double-clicking a file), try one;
- close the app completely (File > Exit or the tray icon's Quit). The report is written when the app exits; Ctrl+C in
  the terminal also closes it.

The code the pages loaded from the server is downloaded with your logged-in session and scanned too: findings in it
point at the URL it came from.

### 3.3 Plant marker markup through the API (optional, tests the server)

The editor's client-side filter may strip markup, so this checks what the **server** accepts. In Burp, take account A's
request that saves a document, and put this harmless markup in the body field:

```html
<span data-ENG42X="1">ENG42X</span>
```

Send it and check the response is a success. The endpoint to use is in 02-watch-author.html under "API endpoint
called", flagged "contains HTML".

### 3.4 Watch session 2: viewer account

```powershell
electronegativity --watch $App --watch-marker $Marker -r -o 03-watch-viewer.html --diagnostics 03-watch-viewer-diag.json --redact $Redact
```

As **account B**: log in and open everything that shows account A's content (the document, previews, search results,
notifications, comments, exports or print preview), then close the app completely.

In 03-watch-viewer.html, `RUNTIME_MARKER` HIGH means the marker came back as live markup (stored content reaches another
user's view unneutralized); INFORMATIONAL means it was shown safely as text.

### 3.5 Templates and screens you didn't open (optional)

Downloads the front end from the test server again, including the templates and code chunks the code names but the
sessions never loaded. Copy account A's session cookie from Burp (`name=value`) and paste it at the prompt, which keeps it
out of the PowerShell history:

```powershell
$Cookie = Read-Host "Cookie (name=value)"
electronegativity -i $Asar --remote https://test-server.example/ --remote-header "Cookie: $Cookie" -r -o 04-remote.html --diagnostics 04-remote-diag.json --redact $Redact
```

## 4. Useful variations

```powershell
# the app needs command-line arguments (or shows a blank window on a VM: try --disable-gpu)
electronegativity --watch $App --watch-args "--disable-gpu" ...

# re-analyze a session without running the app again (the log path is printed at the end of each session)
electronegativity --watch-log "$env:TEMP\electronegativity-watch-XXXXXX\session.jsonl" -i $Asar -r -o 02b.html

# only HIGH and MEDIUM findings, with firm or certain confidence
electronegativity -i $Asar -s medium -c firm -r -o 01-high-medium.html

# the Electron version couldn't be detected: set it (the report says "Couldn't detect Electron version")
electronegativity -i $Asar -e 38.2.0 -r -o 01-static.html

# don't download the pages' code during a watch session
electronegativity --watch $App --no-watch-capture ...
```

## 5. What to send back

Only the `*-diag.json` files. Open each one first and check it contains nothing identifying: the app name, user name,
machine name, home folder and the `$Redact` words are replaced, and hosts are pseudonymized. Keep the `.html` reports
yourself: they contain code locations and URLs.

## 6. Clean up

```powershell
Remove-Item -Recurse -Force "$env:TEMP\electronegativity-watch-*", "$env:TEMP\electronegativity-remote-*"
Remove-Variable Cookie -ErrorAction SilentlyContinue
```

Delete the marker documents from the test environment if others use it.
