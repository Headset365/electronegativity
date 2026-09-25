import path from 'node:path';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { objectProperties, literalValue, finding } from '../helpers.js';
import { FUSES, fuseName, evaluateFuses } from '../fuses.js';

// `FuseV1Options` for `FuseV1Options.RunAsNode`, `fuses.FuseV1Options` for `fuses.FuseV1Options.RunAsNode`
function enumName(key) {
  const object = key && key.object;
  if (!object) return '';
  if (object.type === 'Identifier') return object.name;
  return `${enumName(object)}.${object.property && object.property.name}`;
}

// Electron Fuses configured in JS, e.g. Electron Forge's FusesPlugin, @electron/fuses flipFuses() or electron-builder.config.js
export default class FusesJSCheck {
  constructor() {
    this.id = "FUSES_JS_CHECK";
    this.description = __("FUSES_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/fuses";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = {}) {
    if (astNode.type === 'Program' && /^(forge\.config|electron-builder\.config)\.[cm]?[jt]s$/.test(path.basename(context.file || '')))
      return [packagerMarker(this, path.basename(context.file))];
    if (astNode.type !== 'ObjectExpression') return null;

    const props = objectProperties(astNode);
    // [FuseV1Options.RunAsNode]: false
    const enumKeyed = props.filter(([name, , p]) => p.computed && FUSES[name] && /FuseV1Options$/.test(enumName(p.key)));
    // electronFuses: { runAsNode: false, ... } -- plain keys need at least two fuse names to avoid matching unrelated objects
    const plainKeyed = props.filter(([name, , p]) => !p.computed && fuseName(name) && fuseName(name) !== name);
    const fuseProps = enumKeyed.length > 0 ? enumKeyed : (plainKeyed.length >= 2 ? plainKeyed : []);
    if (fuseProps.length === 0) return null;

    const config = {};
    const nodes = {};
    let dynamic = false;
    for (const [name, value, prop] of fuseProps) {
      const fuse = fuseName(name);
      const v = literalValue(value);
      if (typeof v !== 'boolean') { dynamic = true; continue; }
      config[fuse] = v;
      nodes[fuse] = prop;
    }

    return fusesFindings(this, config, nodes, astNode, dynamic);
  }
}

// Tells FusesGlobalCheck that the packaging configuration was analyzed (so missing fuses are a firm finding)
export function packagerMarker(check, packager) {
  return { line: 1, column: 0, id: check.id, description: `${__("FUSES_PACKAGER_CONFIG")}: ${packager}`, shortenedURL: check.shortenedURL,
    severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: false, properties: { packagerConfig: packager } };
}

export function fusesFindings(check, config, nodes, objectNode, dynamic = false) {
  const { insecure, unset } = evaluateFuses(config);
  // marker consumed by FusesGlobalCheck, to know that fuses are configured at all
  const issues = [finding(check, objectNode, {
    severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: false,
    description: __("FUSES_JS_CHECK_CONFIGURED"), properties: { fusesConfigured: true }
  })];

  for (const { fuse, value } of insecure) {
    issues.push(finding(check, nodes[fuse] || objectNode, {
      severity: FUSES[fuse].severity, confidence: confidence.CERTAIN, manualReview: false,
      description: `${check.description}: ${fuse} = ${value} (${FUSES[fuse].risk})`, properties: { fuse, value }
    }));
  }

  if (unset.length > 0 && !dynamic) {
    issues.push(finding(check, objectNode, {
      severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${check.description}: not set, insecure by default: ${unset.join(', ')}`, properties: { unset }
    }));
  }
  return issues;
}
