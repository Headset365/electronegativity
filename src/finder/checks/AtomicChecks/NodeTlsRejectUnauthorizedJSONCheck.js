import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

// NODE_TLS_REJECT_UNAUTHORIZED=0 in package.json scripts
export default class NodeTlsRejectUnauthorizedJSONCheck {
  constructor() {
    this.id = "NODE_TLS_REJECT_UNAUTHORIZED_JSON_CHECK";
    this.description = __("NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue";
  }

  async match(content) {
    const scripts = content.json && content.json.scripts;
    if (!scripts || typeof scripts !== 'object') return null;
    const lines = content.text.split('\n');
    const issues = [];
    for (const [name, script] of Object.entries(scripts)) {
      if (typeof script !== 'string' || !/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/.test(script)) continue;
      const index = lines.findIndex(l => l.includes(`"${name}"`));
      // an npm script runs when the app is started through npm (development, tests), never in a packaged build
      issues.push({ line: index + 1 || 1, column: 0, id: this.id,
        description: `${this.description} (in the npm script "${name}": it applies when the app is started with that script, typically in development; a packaged build does not run npm scripts)`,
        shortenedURL: this.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false, properties: { script: name } });
    }
    return issues;
  }
}
