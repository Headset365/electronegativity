import { sourceTypes } from '../../../parser/types.js';
import { fuseName } from '../fuses.js';
import { fusesFindings } from './FusesJSCheck.js';

// electron-builder `electronFuses`, in package.json ("build" key) or electron-builder.json
export default class FusesJSONCheck {
  constructor() {
    this.id = "FUSES_JSON_CHECK";
    this.description = __("FUSES_JS_CHECK");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/fuses";
  }

  async match(content) {
    const json = content.json;
    if (!json || typeof json !== 'object') return null;
    const fuses = (json.build && json.build.electronFuses) || json.electronFuses;
    if (!fuses || typeof fuses !== 'object') return null;

    const lines = content.text.split('\n');
    const lineOf = (needle) => {
      const index = lines.findIndex(l => l.includes(`"${needle}"`));
      return { loc: { start: { line: index >= 0 ? index + 1 : 1, column: 0 } } };
    };

    const config = {};
    const nodes = {};
    let dynamic = false;
    for (const [key, value] of Object.entries(fuses)) {
      const fuse = fuseName(key);
      if (!fuse) continue;
      if (typeof value !== 'boolean') { dynamic = true; continue; }
      config[fuse] = value;
      nodes[fuse] = lineOf(key);
    }

    return fusesFindings(this, config, nodes, lineOf('electronFuses'), dynamic);
  }
}
