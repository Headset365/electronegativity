import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import { normalizeCampaign, hostsOutsideScope } from '../src/watch/campaign.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';
const require = createRequire(import.meta.url);
const { runCampaign } = require('../src/watch/campaign.cjs');
const { fillMarkerBody } = require('../src/watch/hook.cjs');
chaiShould();
const marker = 'verification_marker';
const profile = () => normalizeCampaign({version:1,request:{method:'PUT',url:'https://app.test/save',body:'{"body":"original"}'},
  field:'body',view:'reload',cases:['text','html'],waitMs:500,verify:{url:'https://app.test/read',bodyPath:['record']}});

describe('Campaign read-back and cancellation', () => {
  it('verifies saved mutations and restored fields without logging their contents', async () => {
    let body='original';const events=[];
    await runCampaign({profile:profile(),marker,campaignId:'run-one',fill:fillMarkerBody,delay:async()=>{},view:async()=>true,
      fetch:async(url,options)=> {if(options.method==='GET')return {ok:true,status:200,text:async()=>JSON.stringify({record:{body}})};
        body=JSON.parse(options.body).body;return {ok:true,status:200};},write:(kind,data)=>events.push({kind,...data})});
    body.should.equal('original');
    events.filter(e=>e.kind==='campaign-verification').every(e=>e.verification==='matched').should.equal(true);
    events.find(e=>e.kind==='campaign-restore').verification.should.equal('matched');
    JSON.stringify(events).should.not.include('original');
    hostsOutsideScope(profile(),['elsewhere.test']).should.include('app.test');
  });
  it('attempts restoration after cancellation and reports a 200 response that did not restore data', async () => {
    const controller=new AbortController(),events=[];let body='original',writes=0;
    let error;
    try {await runCampaign({profile:profile(),marker,signal:controller.signal,fill:fillMarkerBody,delay:async()=>{},view:async()=>true,
      fetch:async(url,options)=> {if(options.method==='GET')return {ok:true,status:200,text:async()=>JSON.stringify({record:{body}})};
        if(++writes===1){body=JSON.parse(options.body).body;controller.abort();}return {ok:true,status:200};},write:(kind,data)=>events.push({kind,...data})});}catch(e){error=e;}
    error.message.should.include('cancelled');writes.should.equal(2);
    events.find(e=>e.kind==='campaign-restore').verification.should.equal('mismatch');
    analyzeWatchLog(events).issues.some(i=>i.id==='RUNTIME_CAMPAIGN_RESTORE').should.equal(true);
  });
  it('does not attach another campaign execution signal or ambiguous legacy evidence', () => {
    const report=analyzeWatchLog([
      {kind:'campaign-send',campaignId:'one',case:'event-handler',ok:true},
      {kind:'campaign-send',campaignId:'two',case:'event-handler',ok:true},
      {kind:'campaign-result',campaignId:'one',case:'event-handler',signal:'executed',url:'https://app.test'},
      {kind:'campaign-send',case:'script-tag',ok:true},{kind:'campaign-send',case:'script-tag',ok:true},
      {kind:'campaign-result',case:'script-tag',signal:'executed',url:'https://app.test'},
    ]);
    const cases=report.summary.campaign.cases;
    cases.find(c=>c.campaignId==='one').execution.should.equal('observed');
    cases.find(c=>c.campaignId==='two').execution.should.equal('not observed');
    cases.filter(c=>c.case==='script-tag').every(c=>c.correlation==='ambiguous'&&c.execution==='not observed').should.equal(true);
  });
});
