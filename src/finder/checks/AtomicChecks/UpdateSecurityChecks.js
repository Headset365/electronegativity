import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, isProperty, findProperty, literalValue, finding } from '../helpers.js';
import { constantValue, isCall } from '../analysis.js';

// Update feeds decide what code the app runs next: they need TLS and signature verification
export class UpdateSecurityJSCheck {
  constructor() {
    this.id = "UPDATE_SECURITY_JS_CHECK";
    this.description = __("UPDATE_SECURITY_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/updates";
  }

  match(astNode, astHelper, scope) {
    // autoUpdater.setFeedURL('http://...') / setFeedURL({ url: 'http://...' }) / electron-updater { provider: 'generic', url }
    if (isCall(astNode) && memberName(astNode.callee) === 'setFeedURL' && astNode.arguments[0]) {
      const arg = astNode.arguments[0];
      const url = arg.type === 'ObjectExpression' ? (findProperty(arg, 'url') || [])[1] : arg;
      const value = url && constantValue(url, scope);
      if (typeof value === 'string' && /^http:/i.test(value))
        return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false,
          description: `${this.description} (updates are downloaded over plain HTTP: ${value})` })];
      return null;
    }
    // { allowDowngrade: true } or autoUpdater.allowDowngrade = true
    const isAssignment = astNode.type === 'AssignmentExpression' && astNode.operator === '=' && memberName(astNode.left);
    if ((isProperty(astNode) && !astNode.computed) || isAssignment) {
      const name = isAssignment ? memberName(astNode.left) : keyName(astNode.key);
      const value = literalValue(isAssignment ? astNode.right : astNode.value);
      if (name === 'verifyUpdateCodeSignature' && value === false)
        return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false,
          description: `${this.description} (the code signature of Windows updates is not verified)` })];
      if (name === 'allowDowngrade' && value === true)
        return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: true,
          description: `${this.description} (downgrades are allowed, so an older vulnerable version can be installed)` })];
    }
    return null;
  }
}

// electron-builder "publish" and "win" settings in package.json / electron-builder.json|yml
export class UpdateSecurityJSONCheck {
  constructor() {
    this.id = "UPDATE_SECURITY_JSON_CHECK";
    this.description = __("UPDATE_SECURITY_JS_CHECK");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://www.electron.build/configuration/publish";
  }

  async match(content) {
    const json = content.json;
    const build = json && typeof json === 'object' && (json.build || (json.appId ? json : undefined));
    if (!build) return null;
    const lines = content.text.split('\n');
    const lineOf = (needle) => (lines.findIndex(l => l.includes(needle)) + 1) || 1;
    const issues = [];
    const report = (needle, sev, reason) => issues.push({ line: lineOf(needle), column: 0, id: this.id, description: `${this.description} (${reason})`,
      shortenedURL: this.shortenedURL, severity: sev, confidence: confidence.CERTAIN, manualReview: false });

    for (const publish of [].concat(build.publish || [])) {
      const url = publish && typeof publish === 'object' ? publish.url : undefined;
      if (typeof url === 'string' && /^http:/i.test(url)) report(url, severity.HIGH, `updates are published over plain HTTP: ${url}`);
    }
    if (build.win && build.win.verifyUpdateCodeSignature === false) report('verifyUpdateCodeSignature', severity.HIGH, 'the code signature of Windows updates is not verified');
    return issues;
  }
}
