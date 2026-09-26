// End-to-end scans of two sample applications: one following every Electron security recommendation, one making
// every classic mistake. They guard against both false positives and false negatives across all checks at once.
import { should as chaiShould } from 'chai';
import run from '../src/runner.js';

chaiShould();

const NETWORK_CHECKS = ['availablesecurityfixesglobalcheck', 'unsupportedversionglobalcheck', 'dependencyvulnerabilitiesglobalcheck'];
const scanApp = (dir) => run({ input: dir, excludeFromScan: NETWORK_CHECKS, offline: true, isRelative: true });
const list = (issues) => issues.map(i => `${i.id} ${i.severity.name}/${i.confidence.name} ${i.file}:${i.location.line} ${i.description}`).join('\n  ');

describe('Sample applications', () => {
  describe('hardened app', () => {
    let result;
    before(async () => { result = await scanApp('test/apps/hardened-app'); });

    it('parses every file', () => {
      result.errors.filter(e => !e.tolerable).should.deep.equal([]);
    });

    it('has no MEDIUM or HIGH findings', () => {
      const serious = result.issues.filter(i => i.severity.value >= 2);
      serious.should.have.length(0, `unexpected findings:\n  ${list(serious)}`);
    });

    it('has no TENTATIVE findings', () => {
      const tentative = result.issues.filter(i => i.confidence.name === 'TENTATIVE');
      tentative.should.have.length(0, `tentative findings:\n  ${list(tentative)}`);
    });

    it('only leaves allowlists to review', () => {
      const low = result.issues.filter(i => i.severity.name === 'LOW').map(i => i.id).sort();
      low.should.deep.equal(['OPEN_EXTERNAL_JS_CHECK', 'PERMISSION_REQUEST_HANDLER_JS_CHECK', 'PERMISSION_REQUEST_HANDLER_JS_CHECK', 'PROTOCOL_HANDLER_JS_CHECK'], list(result.issues));
    });
  });

  describe('vulnerable app', () => {
    let result;
    before(async () => { result = await scanApp('test/apps/vulnerable-app'); });

    const EXPECTED = [
      ['NODE_INTEGRATION_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['CONTEXT_ISOLATION_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['SANDBOX_JS_CHECK', 'MEDIUM', 'FIRM'],
      ['WEB_SECURITY_JS_CHECK', 'MEDIUM', 'CERTAIN'],
      ['HTTP_RESOURCES_JS_CHECK', 'MEDIUM', 'CERTAIN'],
      ['HTTP_RESOURCES_HTML_CHECK', 'MEDIUM', 'CERTAIN'],
      ['CSP_GLOBAL_CHECK', 'MEDIUM', 'CERTAIN'],
      ['PERMISSION_REQUEST_HANDLER_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['CERTIFICATE_VERIFY_PROC_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['CERTIFICATE_ERROR_EVENT_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['CUSTOM_ARGUMENTS_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['NODE_TLS_REJECT_UNAUTHORIZED_JSON_CHECK', 'MEDIUM', 'CERTAIN'],
      ['LIMIT_NAVIGATION_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['LIMIT_NAVIGATION_GLOBAL_CHECK', 'HIGH', 'CERTAIN'],
      ['WINDOW_OPEN_HANDLER_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['OPEN_EXTERNAL_JS_CHECK', 'HIGH', 'FIRM'],
      ['OPEN_PATH_JS_CHECK', 'HIGH', 'FIRM'],
      ['COMMAND_INJECTION_JS_CHECK', 'HIGH', 'FIRM'],
      ['IPC_SENDER_VALIDATION_JS_CHECK', 'MEDIUM', 'FIRM'],
      ['PROTOCOL_HANDLER_JS_CHECK', 'HIGH', 'FIRM'],
      ['CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', 'HIGH', 'CERTAIN'],
      ['XSS_SINK_JS_CHECK', 'MEDIUM', 'FIRM'],
      ['WEBVIEW_GLOBAL_CHECK', 'HIGH', 'FIRM'],
      ['ALLOWPOPUPS_HTML_CHECK', 'LOW', 'CERTAIN'],
      ['DEVTOOLS_JS_CHECK', 'MEDIUM', 'CERTAIN'],
      ['FUSES_GLOBAL_CHECK', 'MEDIUM', 'FIRM'],
    ];

    for (const [id, severity, confidence] of EXPECTED) {
      it(`reports ${id} (${severity}, ${confidence})`, () => {
        const found = result.issues.some(i => i.id === id && i.severity.name === severity && i.confidence.name === confidence);
        found.should.equal(true, `${id} ${severity}/${confidence} not found in:\n  ${list(result.issues)}`);
      });
    }

    it('has no TENTATIVE findings', () => {
      const tentative = result.issues.filter(i => i.confidence.name === 'TENTATIVE');
      tentative.should.have.length(0, `tentative findings:\n  ${list(tentative)}`);
    });
  });
});
