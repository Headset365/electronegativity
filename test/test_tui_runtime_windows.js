/* eslint-disable no-control-regex -- Read VT frame coordinates to exercise real dashboard mouse hit targets. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { runDashboard, launchWorker, cleanText } from '../src/tui/dashboard.js';
import { watchApp } from '../src/watch/launch.js';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('Windows TUI with real Electron', function () {
  if (process.env.ELECTRONEGATIVITY_REQUIRE_TUI_RUNTIME !== '1') return;
  this.timeout(240000);
  before(() => assert.equal(process.platform, 'win32'));

  it('pipes real app diagnostics separately without giving the app terminal input', async () => {
    const oldTrace = process.env.ELECTRONEGATIVITY_TRACE;
    process.env.ELECTRONEGATIVITY_TRACE = '1';
    const output = [], root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-tui-app-output-'));
    try {
      await watchApp(path.join(import.meta.dirname, 'apps', 'runtime-app'), {
        args: [`--user-data-dir=${path.join(root, 'profile')}`], log: path.join(root, 'watch.jsonl'),
        onOutput: (stream, text) => output.push({ stream, text }),
      });
      assert.ok(output.some(item => item.stream === 'stderr' && item.text.includes('[runtime-app] document saved')));
    } finally {
      if (oldTrace === undefined) delete process.env.ELECTRONEGATIVITY_TRACE; else process.env.ELECTRONEGATIVITY_TRACE = oldTrace;
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    }
  });

  it('uses mouse buttons to review, run and finish a native campaign, then reviews the session before finishing', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-tui-live-'));
    const input = new PassThrough(), output = new PassThrough();
    input.isTTY = true; input.isRaw = false; input.setRawMode = value => { input.isRaw = value; };
    output.isTTY = true; output.columns = 140; output.rows = 40;
    let frame = '', worker, automationError;
    const messages = [], automation = [];
    output.on('data', chunk => { frame = chunk.toString(); });
    const click = async label => {
      const deadline = Date.now() + 20000;
      while (Date.now() < deadline) {
        for (const match of frame.matchAll(/\x1b\[(\d+);1H\x1b\[2K(.*?)(?=\x1b\[\d+;1H|$)/g)) {
          const column = cleanText(match[2]).indexOf(label);
          if (column >= 0) { input.write(`\x1b[<0;${column + 2};${match[1]}M`); return; }
        }
        await pause(50);
      }
      throw new Error(`Button not rendered: ${label}; frame: ${frame}`);
    };
    const old = { save: process.env.DEBUG_APP_AUTO_SAVE, profile: process.env.DEBUG_APP_PROFILE };
    process.env.DEBUG_APP_AUTO_SAVE = '1'; process.env.DEBUG_APP_PROFILE = path.join(root, 'profile');
    const args = ['--tui', '--app', path.join(import.meta.dirname, 'apps', 'debug-app'), '--auto-campaign', '--prove',
      '--user-data', 'auto', '--watch-screenshots', 'screenshots', '--watch-marker', 'ENG_TUI_LIVE', '--all-files',
      '--scope', '127.0.0.1', '--remote', '127.0.0.1', '--remote-header', 'Authorization', '--redact', 'private',
      '--show-secrets', '--share-code', '--offline', '--no-nvd', '--out', path.join(root, 'results'), '-o', 'report.html,report.json'];
    let reviewedFirst = false;
    try {
      const running = runDashboard(args, { input, output, launch: passed => {
        worker = launchWorker(passed);
        worker.on('message', message => {
          messages.push(message);
          if (message.type !== 'prompt') return;
          const task = (async () => {
            // The worker message precedes the dashboard's next frame; click only after the new controls are drawn.
            await pause(100);
            if (message.kind === 'session') {
              input.write('\r\r'); // neither keypress may start another session
              await pause(100);
              if (!reviewedFirst) { reviewedFirst = true; await click('Start next session'); }
              else await click('Finish & write reports');
            } else if (message.kind === 'campaign') await click('Review & run');
            else if (message.kind === 'text') await click('Use value / default');
            else if (message.kind === 'confirm') await click('Approve');
          })().catch(error => { automationError = error; if (worker.connected) worker.disconnect(); worker.kill(); });
          automation.push(task);
        });
        worker.once('exit', () => { setTimeout(() => input.write('q'), 100); });
        return worker;
      } });
      const result = await running; await Promise.all(automation);
      if (automationError) throw automationError;
      assert.equal(result.code, 0);
      assert.equal(messages.filter(message => message.type === 'session-start').length, 1);
      assert.ok(messages.some(message => message.type === 'campaign' && message.status === 'running'));
      assert.ok(messages.some(message => message.type === 'campaign' && message.status === 'completed'));
      const report = JSON.parse(fs.readFileSync(path.join(root, 'results', 'report.json'), 'utf8'));
      assert.ok(report.issues.some(issue => issue.id.startsWith('RUNTIME_CAMPAIGN_')));
      assert.equal(input.isRaw, false);
    } finally {
      if (worker?.connected) worker.disconnect(); worker?.kill();
      for (const [key, value] of [['DEBUG_APP_AUTO_SAVE', old.save], ['DEBUG_APP_PROFILE', old.profile]]) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    }
  });
});
