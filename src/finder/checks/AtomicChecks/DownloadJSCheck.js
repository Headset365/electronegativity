import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, finding } from '../helpers.js';
import { handlerFunction, callsIn, paramNames, identifiersIn, visit, isCall } from '../analysis.js';

// session.on('will-download', (event, item) => ...): downloads are chosen by web content
export default class DownloadJSCheck {
  constructor() {
    this.id = "DOWNLOAD_JS_CHECK";
    this.description = __("DOWNLOAD_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/download-item";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || !['on', 'once'].includes(memberName(astNode.callee)) || literalValue(astNode.arguments[0]) !== 'will-download') return null;
    const fn = handlerFunction(astNode.arguments[1], scope, context.ancestors);
    const item = fn && paramNames(fn)[1];
    if (!item) return null;

    const issues = [];
    // shell.openPath(item.getSavePath()) / openPath(savePath): downloaded files are executed without the user asking
    const savePaths = new Set();
    visit(fn.body, (n) => {
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init && usesItem(n.init, item, 'getSavePath')) savePaths.add(n.id.name);
      return true;
    });
    for (const { call } of callsIn(fn, (c, name) => ['openPath', 'openExternal', 'openItem'].includes(name))) {
      const arg = call.arguments[0];
      if (arg && (usesItem(arg, item, 'getSavePath') || [...identifiersIn(arg)].some(n => savePaths.has(n))))
        issues.push(finding(this, call, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false,
          description: `${this.description} (downloaded files are opened automatically)` }));
    }
    // item.setSavePath(path.join(dir, item.getFilename())): the file name comes from the server
    for (const { call } of callsIn(fn, (c, name) => name === 'setSavePath')) {
      const arg = call.arguments[0];
      if (arg && usesItem(arg, item, 'getFilename') && !sanitizes(arg))
        issues.push(finding(this, call, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description} (the save path is built from the server-provided file name; strip directories with path.basename and check the extension)` }));
    }
    return issues;
  }
}

function usesItem(node, item, method) {
  let found = false;
  visit(node, (n) => {
    if (isCall(n) && memberName(n.callee) === method && n.callee.object && n.callee.object.type === 'Identifier' && n.callee.object.name === item) found = true;
    return !found;
  });
  return found;
}

function sanitizes(node) {
  let found = false;
  visit(node, (n) => { if (isCall(n) && /basename|sanitiz|filenamify|safe/i.test(memberName(n.callee) || n.callee.name || '')) found = true; return !found; });
  return found;
}
