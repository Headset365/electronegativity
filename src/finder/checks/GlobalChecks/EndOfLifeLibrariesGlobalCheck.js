import { major, coerce } from 'semver';
import { severity, confidence } from '../../attributes.js';

// Frontend libraries whose versions no longer receive security fixes, per their maintainers
const ANGULARJS_MODULES = /^angular(-(animate|aria|cookies|loader|message-format|messages|mocks|parse-ext|resource|route|sanitize|touch))?$/;
const END_OF_LIFE = [
  { matches: (name, v) => ANGULARJS_MODULES.test(name) && major(v) === 1, product: 'AngularJS 1.x', ended: 'support ended in January 2022',
    url: 'https://docs.angularjs.org/misc/version-support-status' },
  { matches: (name, v) => name === 'jquery' && major(v) < 3, product: (v) => `jQuery ${major(v)}.x`, ended: 'no longer supported',
    url: 'https://jquery.com/support/' },
  { matches: (name, v) => name === 'bootstrap' && major(v) <= 4, product: (v) => `Bootstrap ${major(v)}.x`,
    ended: (v) => `end-of-life since ${{ 2: '2013-08-19', 3: '2019-07-24', 4: '2023-01-01' }[major(v)] || 'before 2023'}`,
    url: 'https://github.com/twbs/release' },
];

const value = (field, version) => typeof field === 'function' ? field(version) : field;

export default class EndOfLifeLibrariesGlobalCheck {
  constructor() {
    this.id = "END_OF_LIFE_LIBRARY_GLOBAL_CHECK";
    this.description = __("END_OF_LIFE_LIBRARY_GLOBAL_CHECK");
    this.depends = ["DependencyInventoryLockCheck"];
    this.shortenedURL = "https://docs.angularjs.org/misc/version-support-status";
  }

  async perform(issues) {
    const results = [];
    const seen = new Set();
    for (const issue of issues) {
      for (const pkg of (issue.properties && issue.properties.packages) || []) {
        const version = coerce(pkg.version);
        if (!version) continue;
        const rule = END_OF_LIFE.find(r => r.matches(pkg.name, version));
        const key = `${pkg.name}@${pkg.version}`;
        if (!rule || seen.has(key)) continue;
        seen.add(key);
        results.push({
          file: issue.file,
          location: { line: pkg.line || 1, column: 0 },
          id: this.id,
          description: `${this.description}: ${pkg.name}@${pkg.version}${pkg.vendored ? ' (copy bundled with the app)' : ''}${pkg.dev ? ' (dev)' : ''}, ${value(rule.product, version)} ${value(rule.ended, version)}`,
          properties: { package: pkg.name, version: pkg.version, dev: !!pkg.dev },
          shortenedURL: rule.url,
          severity: pkg.dev ? severity.LOW : severity.MEDIUM,
          confidence: confidence.CERTAIN,
          manualReview: false
        });
      }
    }
    return results;
  }
}
