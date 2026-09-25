import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class CustomArgumentsJSCheck {
  constructor() {
    this.id = "CUSTOM_ARGUMENTS_JS_CHECK";
    this.description = __("CUSTOM_ARGUMENTS_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/command-line-switches";
    this.dangerousArguments = [
      "ignore-certificate-errors",
      "ignore-certificate-errors-spki-list",
      "ignore-urlfetcher-cert-requests",
      "disable-web-security",
      "host-rules",
      "host-resolver-rules",
      "auth-server-whitelist",
      "auth-negotiate-delegate-whitelist",
      "js-flags",
      "allow-file-access-from-files",
      "allow-no-sandbox-job",
      "allow-running-insecure-content",
      "cipher-suite-blacklist",
      "debug-packed-apps",
      "disable-features",
      "disable-kill-after-bad-ipc",
      "disable-webrtc-encryption",
      "disable-xss-auditor",
      "enable-local-file-accesses",
      "enable-nacl-debug",
      "remote-debugging-address",
      "remote-debugging-port",
      "inspect",
      "inspect-brk",
      "explicitly-allowed-ports",
      "expose-internals-for-testing",
      "gpu-launcher",
      "nacl-dangerous-no-sandbox-nonsfi",
      "nacl-gdb-script",
      "net-log-capture-mode",
      "no-sandbox",
      "reduce-security-for-testing",
      "unsafely-treat-insecure-origin-as-secure",
      "disable-site-isolation-trials",
      "disable-renderer-backgrounding-for-testing"
    ];
    // switches that directly disable a security boundary
    this.highRisk = ["ignore-certificate-errors", "disable-web-security", "no-sandbox", "remote-debugging-port", "remote-debugging-address",
      "inspect", "inspect-brk", "allow-running-insecure-content", "unsafely-treat-insecure-origin-as-secure", "disable-site-isolation-trials", "reduce-security-for-testing"];
  }

  match(astNode, astHelper) {
    const methods = ['appendArgument', 'appendSwitch'];

    if (astNode.type !== 'CallExpression') return null;
    if ((astNode.callee.name && methods.includes(astNode.callee.name)) || (astNode.callee.property && methods.includes(astNode.callee.property.name))) {
      if (astNode.arguments && astNode.arguments.length > 0 && astNode.arguments[0].type === astHelper.StringLiteral && astNode.arguments[0].value) {
        const value = astNode.arguments[0].value.replace(/^-+/, '');
        const switchName = value.split('=')[0];
        const matched = this.dangerousArguments.find(arg => switchName === arg) || this.dangerousArguments.find(arg => value.includes(arg));

        if (matched) {
          // exact switch names are certain, substring matches (e.g. inside a larger argument) only firm
          const exact = switchName === matched;
          return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: `${this.description}: --${matched}`, shortenedURL: this.shortenedURL,
            severity: this.highRisk.includes(matched) ? severity.HIGH : severity.MEDIUM, confidence: exact ? confidence.CERTAIN : confidence.FIRM, manualReview: false, properties: { switch: matched } }];
        }
      }
    }
  }
}
