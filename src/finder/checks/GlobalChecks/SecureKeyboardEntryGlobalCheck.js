import { severity, confidence } from '../../attributes.js';

export default class SecureKeyboardEntryGlobalCheck {
  constructor() {
    this.id = "SECUREKEYBOARDENTRY_GLOBAL_CHECK";
    this.description = __("SECUREKEYBOARDENTRY_GLOBAL_CHECK");
    this.depends = ["SecureKeyboardEntryJSCheck", "SecureKeyboardEntryHTMLCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/app#appsetsecurekeyboardentryenabledenabled-macos";
  }

  async perform(issues) {
    const passwordFields = issues.filter(i => i.properties && i.properties.passwordField);
    const calls = issues.filter(i => i.properties && 'secureKeyboardEntry' in i.properties);
    const disabled = calls.filter(i => i.properties.secureKeyboardEntry === false);
    if (passwordFields.length === 0) return disabled;
    if (calls.some(i => i.properties.secureKeyboardEntry === true)) return disabled;
    const first = passwordFields[0];
    return [...disabled, { file: first.file, location: first.location, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.LOW, confidence: confidence.FIRM, manualReview: true }];
  }
}
