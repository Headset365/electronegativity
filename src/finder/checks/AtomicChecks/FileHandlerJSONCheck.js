import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

// File associations and URL schemes registered at install time (electron-builder)
export default class FileHandlerJSONCheck {
  constructor() {
    this.id = "FILE_HANDLER_JSON_CHECK";
    this.description = __("FILE_HANDLER_JSON_CHECK");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://www.electron.build/configuration#fileassociation";
  }

  async match(content) {
    const json = content.json;
    const build = json && (json.build || (json.appId ? json : undefined));
    if (!build || typeof build !== 'object') return null;
    const lines = content.text.split('\n');
    const issues = [];
    for (const key of ['fileAssociations', 'protocols']) {
      if (!build[key]) continue;
      const entries = [].concat(build[key]);
      const names = entries.flatMap(e => [].concat(e.ext || e.schemes || e.name || [])).join(', ');
      const index = lines.findIndex(l => l.includes(`"${key}"`));
      issues.push({ line: index + 1 || 1, column: 0, id: this.id, description: `${this.description} (${key}: ${names})`, shortenedURL: this.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true, properties: { [key]: names } });
    }
    return issues;
  }
}
