'use strict';
// Windows 10/11 inventory. PowerShell receives data as JSON in an environment variable,
// never as interpolated executable code. These checks do not write to the install or registry.
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { StringDecoder } = require('node:string_decoder');

function powershell(script, data, { run = spawn, timeout = 12000 } = {}) {
  return new Promise(resolve => {
    const preamble = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); $d=ConvertFrom-Json $env:ENG_WINDOWS_INPUT; ";
    const command = Buffer.from(preamble + script, 'utf16le').toString('base64');
    const child = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', command], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ENG_WINDOWS_INPUT: JSON.stringify(data) },
    });
    const decoder = new StringDecoder('utf8');
    let out = '', done = false;
    const finish = result => { if (done) return; done = true; clearTimeout(timer); resolve(result); };
    const timer = setTimeout(() => { child.kill(); finish({ status: 'timeout' }); }, timeout);
    child.stdout.on('data', b => { out += decoder.write(b); if (out.length > 2 * 1024 * 1024) { child.kill(); finish({ status: 'limit' }); } });
    // stderr can contain app data; report the failure category only.
    child.stderr.on('data', () => {});
    child.once('error', () => finish({ status: 'unavailable' }));
    child.once('exit', code => {
      if (code !== 0) return finish({ status: 'access-error' });
      try { finish({ status: 'observed', data: JSON.parse((out + decoder.end()).replace(/^\uFEFF/, '').trim()) }); }
      catch { finish({ status: 'invalid-output' }); }
    });
  });
}

const ACL_SCRIPT = `
$rows=@(); foreach($p in $d.paths) {
  try {
    $a=Get-Acl -LiteralPath $p; $aces=@($a.Access | ForEach-Object {
      $sid=$null; try {$sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value} catch {}
      @{sid=$sid; identity=$_.IdentityReference.Value; rights=[int64]$_.FileSystemRights; type=[string]$_.AccessControlType;
        inherited=$_.IsInherited; propagation=[string]$_.PropagationFlags; inheritance=[string]$_.InheritanceFlags}
    }); $rows+=@{path=$p; status='observed'; owner=$a.Owner; entries=$aces}
  } catch {$rows+=@{path=$p; status='access-error'}}
}; $identity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$principal=New-Object System.Security.Principal.WindowsPrincipal($identity);
@{paths=$rows; user=$identity.Name; userSid=$identity.User.Value; groups=@($identity.Groups | ForEach-Object {$_.Value});
 elevated=$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)} | ConvertTo-Json -Depth 7 -Compress`;

const PROTOCOL_SCRIPT = `
$rows=@(); $errors=0;
foreach($h in @([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryHive]::LocalMachine)) {
 foreach($v in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
  $base=$null; $root=$null;
  try {
   $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($h,$v); $root=$base.OpenSubKey('Software\\Classes');
   foreach($name in $root.GetSubKeyNames()) {
    $k=$null; $c=$null;
    try {
     $k=$root.OpenSubKey($name); if($null -eq $k.GetValue('URL Protocol',$null)){continue}
     $c=$k.OpenSubKey('shell\\open\\command'); if($null -eq $c){continue}
     $command=[Environment]::ExpandEnvironmentVariables([string]$c.GetValue(''));
     $exe=$null; if($command -match '^\\s*"([^"]+)"'){$exe=$Matches[1]} elseif($command -match '^\\s*(.+?\\.exe)(?:\\s|$)'){$exe=$Matches[1]}
     if($exe -and [string]::Equals($exe,[string]$d.executable,[StringComparison]::OrdinalIgnoreCase)) {
      $rows+=@{hive=[string]$h; view=[string]$v; scheme=$name; command=$command}
     }
    } catch {$errors++} finally {if($c){$c.Dispose()};if($k){$k.Dispose()}}
   }
  } catch {$errors++} finally {if($root){$root.Dispose()};if($base){$base.Dispose()}}
 }
}; @{protocols=$rows; errors=$errors} | ConvertTo-Json -Depth 5 -Compress`;

const PORT_SCRIPT = `
$pids=@([int]$d.pid); $all=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId);
for($i=0;$i -lt 12;$i++) {$new=@($all | Where-Object {$pids -contains [int]$_.ParentProcessId -and $pids -notcontains [int]$_.ProcessId} | ForEach-Object {[int]$_.ProcessId});if(!$new.Count){break};$pids+=$new}
$tcp=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {$pids -contains [int]$_.OwningProcess} | ForEach-Object {
 @{pid=[int]$_.OwningProcess; address=$_.LocalAddress; port=[int]$_.LocalPort; transport='tcp'}
}); $udp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {$pids -contains [int]$_.OwningProcess} | ForEach-Object {
 @{pid=[int]$_.OwningProcess; address=$_.LocalAddress; port=[int]$_.LocalPort; transport='udp'}
}); @{listeners=@($tcp+$udp); processes=$pids} | ConvertTo-Json -Depth 5 -Compress`;

// Common low-privilege groups by SID: unaffected by the machine's UI language.
const BROAD = new Set(['S-1-1-0', 'S-1-5-11', 'S-1-5-32-545']);
const WRITE = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288;
function assessAcl(row) {
  const entries = row.entries || [];
  return entries.filter(a => BROAD.has(a.sid) && a.type === 'Allow' && (a.rights & WRITE) && !/InheritOnly/.test(a.propagation))
    .map(a => ({ ...a, denyPresent: entries.some(d => d.type === 'Deny' && (d.rights & WRITE) && (d.sid === a.sid || d.sid === 'S-1-1-0')) }));
}
function assessProtocol(row) {
  const command = String(row.command || '');
  return { ...row, argumentQuoted: /"%[1l]"/i.test(command), hasArgument: /%[1l]/i.test(command),
    executableQuoted: /^\s*"[^"]+"/.test(command), switchDelimiter: /(?:^|\s)--\s+"?%[1l]/i.test(command) };
}
async function inventory(executable, write, options = {}) {
  if ((options.platform || process.platform) !== 'win32') return;
  const folder = path.dirname(executable);
  const paths = [folder, executable, path.join(folder, 'resources')];
  for (const name of ['app.asar', 'app', 'app.asar.unpacked']) {
    const p = path.join(folder, 'resources', name); if (fs.existsSync(p)) paths.push(p);
  }
  try { for (const name of fs.readdirSync(folder).filter(n => /\.dll$/i.test(n)).slice(0, 100)) paths.push(path.join(folder, name)); } catch { /* inaccessible */ }
  const acl = await powershell(ACL_SCRIPT, { paths }, options);
  const identities = new Set([acl.data?.userSid, ...(acl.data?.groups || [])]);
  write('windows-acl', { status: acl.status, elevated: acl.data?.elevated, paths: acl.data?.paths?.map(r => ({ ...r, broadWrite: assessAcl(r),
    currentTokenWriteGrants: (r.entries || []).filter(a => identities.has(a.sid) && a.type === 'Allow' && (a.rights & WRITE) && !/InheritOnly/.test(a.propagation)) })) });
  const protocols = await powershell(PROTOCOL_SCRIPT, { executable }, options);
  write('windows-protocol', { status: protocols.status, errors: protocols.data?.errors, protocols: protocols.data?.protocols?.map(assessProtocol) });
}
function observePorts(pid, write, { interval = 10000, inspectorPort, ...options } = {}) {
  if ((options.platform || process.platform) !== 'win32' || !Number.isInteger(pid) || pid <= 0) return () => {};
  let closed = false, busy = false;
  const seen = new Set();
  const poll = async () => {
    if (closed || busy) return; busy = true;
    const result = await powershell(PORT_SCRIPT, { pid }, options); busy = false;
    if (closed) return;
    if (result.status !== 'observed') { if (!seen.has(result.status)) { seen.add(result.status); write('windows-ports', { status: result.status }); } return; }
    for (const row of result.data.listeners || []) {
      const key = JSON.stringify(row); if (seen.has(key)) continue; seen.add(key);
      write('windows-listener', { ...row, toolInspector: row.pid === pid && row.port === inspectorPort });
    }
  };
  void poll(); const timer = setInterval(poll, interval); timer.unref();
  return () => { closed = true; clearInterval(timer); };
}
function readZone(file, { platform = process.platform, read = fs.readFileSync, stat = fs.statSync } = {}) {
  if (platform !== 'win32') return { status: 'unsupported' };
  // Only paths observed in the app; URLs and UNC paths do not cause network filesystem access.
  if (!/^[a-z]:[\\/]/i.test(file || '') || /[\0\r\n]/.test(file) || file.slice(2).includes(':')) return { status: 'skipped' };
  try { if (!stat(file).isFile()) return { status: 'skipped' }; }
  catch (e) { return { status: e.code === 'ENOENT' ? 'file-missing' : 'access-error' }; }
  try {
    const text = read(`${file}:Zone.Identifier`, 'utf8');
    const match = /^ZoneId\s*=\s*(\d+)\s*$/im.exec(text);
    return { status: 'present', zone: match ? Number(match[1]) : undefined };
  } catch (e) { return { status: e.code === 'ENOENT' ? 'absent' : 'access-error' }; }
}
module.exports = { powershell, inventory, observePorts, readZone, assessAcl, assessProtocol };
