import { severity, confidence } from '../../attributes.js';

// An unsandboxed frame shares the origin of the page embedding it, so script in the frame can call parent.require()
// when that page's window has Node.js integration (Joplin's note viewer, CVE-2022-35131)
export default class IframeSandboxGlobalCheck {
  constructor() {
    this.id = "IFRAME_SANDBOX_GLOBAL_CHECK";
    this.description = __("IFRAME_SANDBOX_CHECK");
    this.depends = ["IframeSandboxHTMLCheck", "IframeSandboxJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#2-do-not-enable-nodejs-integration-for-remote-content";
  }

  async perform(issues, output, allIssues = []) {
    const nodeIntegration = allIssues.find(issue => /^NODE_INTEGRATION_(JS|HTML)_CHECK$/.test(issue.id) &&
      issue.severity === severity.HIGH && issue.confidence !== confidence.TENTATIVE);
    if (!nodeIntegration) return issues;
    const where = nodeIntegration.file && nodeIntegration.file !== 'N/A' ? ` (${nodeIntegration.file}:${nodeIntegration.location.line})` : '';
    return issues.map(issue => ({ ...issue, severity: severity.MEDIUM,
      description: `${issue.description}; a window of the app enables nodeIntegration${where}, so script in an unsandboxed frame of that window can reach Node.js through parent.require()` }));
  }
}
