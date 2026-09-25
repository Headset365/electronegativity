import { severity, confidence } from '../../attributes.js';

export default class CertificatePinningGlobalCheck {
  constructor() {
    this.id = "CERTIFICATE_PINNING_GLOBAL_CHECK";
    this.description = __("CERTIFICATE_PINNING_GLOBAL_CHECK");
    this.depends = ["CertificateVerifyProcJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/session#sessetcertificateverifyprocproc";
  }

  async perform(issues) {
    // a custom verification procedure is where pinning happens, those still need a manual review
    const verifyProcs = issues.filter(i => i.properties && i.properties.verifyProc);
    const others = issues.filter(i => !(i.properties && i.properties.pinning));
    if (verifyProcs.length > 0) return others;
    return [...others, { file: "N/A", location: { line: 0, column: 0 }, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: true }];
  }
}
