import { sourceTypes } from '../../../../parser/types.js';
import { severity, confidence } from '../../../attributes.js';

export default class PrivilegedSchemesRegistrationRemoval {
  constructor() {
    this.id = "PRIVILEGED_SCHEMES_REGISTRATION_REMOVAL";
    this.description = __("PRIVILEGED_SCHEMES_REGISTRATION_REMOVAL");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/breaking-changes';
  }

  match(astNode, astHelper, scope){
    if (astNode.type !== 'CallExpression') return null;
    if (!astNode.callee.property ||  
        (astNode.callee.property.name !== 'registerURLSchemeAsPrivileged' &&
        astNode.callee.property.name !== 'registerURLSchemeAsBypassingCSP' &&
        astNode.callee.property.name !== 'registerStandardSchemes')) {
      return null;
    }
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false }];
  }
}