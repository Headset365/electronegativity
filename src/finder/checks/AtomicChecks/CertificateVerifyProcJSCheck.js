import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class CertificateVerifyProcJSCheck {
  constructor() {
    this.id = "CERTIFICATE_VERIFY_PROC_JS_CHECK";
    this.description = __("CERTIFICATE_VERIFY_PROC_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/Jeu1A";
  }

  match(astNode){
    if (astNode.type !== 'CallExpression')
      return null;

    if (astNode.callee.property && astNode.callee.property.name === "setCertificateVerifyProc") {
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
    }

    if (astNode.callee.property && astNode.callee.property.name === "importCertificate") {
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
    }
  }
}
