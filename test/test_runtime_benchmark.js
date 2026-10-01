import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
chaiShould();
let electron;
try { electron = createRequire(import.meta.url)('electron'); } catch { /* installed by runtime CI */ }
const display = process.platform !== 'linux' || spawnSync('which',['xvfb-run']).status === 0;
const available = !!electron && display;
if (process.env.ELECTRONEGATIVITY_REQUIRE_RUNTIME_TESTS === '1' && !available) throw Error('Required live benchmark needs Electron and a display; skips are forbidden');
const live = available ? it : it.skip;

describe('Live vulnerable/hardened Electron benchmark', function () {
  this.timeout(150000);
  for (const mode of ['native','debug']) for (const hardened of [false,true]) live(`${mode}: ${hardened?'hardened':'vulnerable'} IPC, content and restoration`, async () => {
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'eng-live-benchmark-'));
    const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const port=server.address().port;await new Promise(resolve=>server.close(resolve));
    const url=`http://127.0.0.1:${port}`;
    try {
      fs.mkdirSync(path.join(root,'allowed'));
      fs.writeFileSync(path.join(root,'allowed','inside.txt'),'tool-owned-canary');fs.writeFileSync(path.join(root,'outside.txt'),'tool-owned-canary');
      const profile=path.join(root,'campaign.json'),output=path.join(root,'report.json');
      fs.writeFileSync(profile,JSON.stringify({version:1,capture:{method:'PUT',route:`${url}/api/documents/{id}`},field:'body',view:`${url}/view`,
        cases:['text','event-handler','svg-handler','cookie-canary'],waitMs:500,verify:{url:`${url}/api/documents/42`}}));
      const cli=[path.join(import.meta.dirname,'..','src','index.js'),'--watch',path.join(import.meta.dirname,'apps','debug-app'),
        '--campaign',profile,'--watch-marker','ENG_LIVE_BENCHMARK','--offline','--no-report-dir','--no-watch-traffic','-o',output];
      if(mode==='debug')cli.push('--debug-launch','--debug-duration','25','--debug-target',`${url}/view`);
      cli.push('--watch-args','--no-sandbox');
      const env={...process.env,DEBUG_APP_PORT:String(port),DEBUG_APP_PROFILE:path.join(root,'profile'),DEBUG_APP_PROBE_ROOT:root,
        DEBUG_APP_HARDENED:hardened?'1':'0',DEBUG_APP_AUTO_SAVE:'1',DEBUG_APP_SEED_DELAY:'5000'};
      const options={env,encoding:'utf8',timeout:120000};
      const result=process.platform==='linux'?spawnSync('xvfb-run',['-a',process.execPath,...cli],options):spawnSync(process.execPath,cli,options);
      result.status.should.equal(0,`${result.error||''}\n${result.stderr}\n${result.stdout}`);
      const report=JSON.parse(fs.readFileSync(output)),metrics=JSON.parse(fs.readFileSync(path.join(root,'metrics.json')));
      metrics.insideAllowed.should.equal(true);metrics.outsideAllowed.should.equal(!hardened);metrics.restored.should.equal(true);metrics.navigationAllowed.should.equal(!hardened);
      report.runtime.campaign.cases.should.have.length(4);
      report.runtime.campaign.cases.some(c=>c.execution==='observed').should.equal(!hardened);
      report.issues.some(i=>i.id==='RUNTIME_CAMPAIGN_RESTORE').should.equal(false);
      result.stdout.should.include('Original saved fields verified');
      if(mode==='native')report.issues.some(i=>i.id==='RUNTIME_IPC').should.equal(true);
      else report.issues.some(i=>i.id==='RUNTIME_DEBUG_COVERAGE').should.equal(true);
    } finally {fs.rmSync(root,{recursive:true,force:true});}
  });
});
