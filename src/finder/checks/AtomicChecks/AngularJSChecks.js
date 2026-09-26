import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { constantValue, isCall } from '../analysis.js';

const calleeObject = (callee) => callee && callee.object && callee.object.type === 'Identifier' ? callee.object.name : undefined;

// $sceProvider.enabled(false) turns off AngularJS's Strict Contextual Escaping for the whole application
export class AngularSceDisabledJSCheck {
  constructor() {
    this.id = "ANGULAR_SCE_DISABLED_JS_CHECK";
    this.description = __("ANGULAR_SCE_DISABLED_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://docs.angularjs.org/api/ng/provider/$sceProvider";
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.type === 'NewExpression') return null;
    if (memberName(astNode.callee) !== 'enabled' || calleeObject(astNode.callee) !== '$sceProvider' || astNode.arguments.length === 0) return null;
    const value = constantValue(astNode.arguments[0], scope);
    if (value === undefined)
      return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true,
        description: `${this.description} (set from a value that can't be determined statically)` })];
    return value ? null : [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.CERTAIN })];
  }
}

// Resource URL allowlists decide where AngularJS may load templates from (ng-include, templateUrl)
const LIST_METHODS = ['resourceUrlWhitelist', 'trustedResourceUrlList'];

export class AngularResourceUrlListJSCheck {
  constructor() {
    this.id = "ANGULAR_RESOURCE_URL_LIST_JS_CHECK";
    this.description = __("ANGULAR_RESOURCE_URL_LIST_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://docs.angularjs.org/api/ng/provider/$sceDelegateProvider";
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.type === 'NewExpression') return null;
    if (!LIST_METHODS.includes(memberName(astNode.callee)) || astNode.arguments.length === 0) return null;
    const list = astNode.arguments[0];
    if (list.type !== 'ArrayExpression') return null;
    const entries = list.elements.map(element => constantValue(element, scope)).filter(entry => typeof entry === 'string');
    // '**' matches any URL, http: loads can be tampered with in transit, a wildcard host trusts every domain
    const risky = entries.filter(entry => entry === '**' || /^http:/i.test(entry) || /^[a-z]+:\/\/\*\*/i.test(entry));
    if (risky.length === 0) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.CERTAIN,
      description: `${this.description} (${risky.map(entry => `'${entry}'`).join(', ')})` })];
  }
}
