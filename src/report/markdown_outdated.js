// The "Outdated Software Components" client finding: the Electron runtime and third-party components in one finding that
// refers to the components workbook for the list, with examples of the kinds of vulnerability the published advisories
// for those components describe.
import { needsAction } from './xlsx.js';

export const OUTDATED_TITLE = 'Outdated Software Components';
export const COMPONENTS_SHEET = 'components.xlsx';

// Kinds of vulnerability, by the weakness types (CWE) advisories carry, with what exploiting one could lead to in an
// Electron application. A summary's wording stands in when an advisory names no weakness type.
const KINDS = [
  { label: 'Code and command injection', cwes: [77, 78, 88, 94, 95, 917, 1336],
    words: /command injection|code injection|arbitrary code|remote code execution|code execution/i,
    impact: 'attacker-influenced input could be run as code or operating system commands with the privileges of the application, which can lead to compromise of the user’s computer and the data it holds.' },
  { label: 'Memory corruption', cwes: [119, 120, 121, 122, 125, 190, 416, 476, 787, 843],
    words: /use[- ]after[- ]free|buffer overflow|out[- ]of[- ]bounds|type confusion|heap corruption|memory corruption/i,
    impact: 'crafted content could crash the application or run code within its renderer process; where renderer isolation is weak, this can extend to the user’s computer.' },
  { label: 'Cross-Site Scripting', cwes: [79, 80, 83, 87],
    words: /cross[- ]site scripting|\bxss\b/i,
    impact: 'attacker-controlled content could run script in an application window, which can lead to theft of data or session tokens, actions performed as the user or, where that window can reach Node.js or privileged IPC, code execution on the user’s computer.' },
  { label: 'Other injection', cwes: [74, 89, 91, 93, 113, 643],
    words: /header injection|sql injection|injection/i,
    impact: 'attacker-influenced input could be interpreted as part of a query, header or other protocol data, allowing requests or stored data to be manipulated.' },
  { label: 'Prototype pollution', cwes: [915, 1321],
    words: /prototype pollution/i,
    impact: 'attacker-controlled input could change the behaviour of objects throughout the application, which can bypass security checks or, combined with other flaws, lead to code execution.' },
  { label: 'Path traversal', cwes: [22, 23, 24, 27, 35, 36, 59],
    words: /path traversal|directory traversal/i,
    impact: 'crafted file paths could read or overwrite files outside the locations the application intends, exposing or altering user data.' },
  { label: 'Security control bypass', cwes: [284, 285, 287, 290, 346, 352, 601, 693, 862, 863, 1021],
    words: /bypass|insufficient policy enforcement|inappropriate implementation|origin validation|open redirect/i,
    impact: 'a protection the application relies on, such as an origin check, sandbox or permission control, could be bypassed, making other attacks possible.' },
  { label: 'Server-side request forgery', cwes: [918],
    words: /server[- ]side request forgery|\bssrf\b/i,
    impact: 'the application could be made to send requests to internal systems or services on behalf of an attacker.' },
  { label: 'Information disclosure', cwes: [200, 201, 209, 359, 532, 922],
    words: /information disclosure|information leak|exposure of sensitive/i,
    impact: 'sensitive information such as user data, credentials or tokens could be exposed to an attacker.' },
  { label: 'Denial of service', cwes: [400, 407, 674, 770, 834, 835, 1333],
    words: /denial of service|\bredos\b|regular expression|resource exhaustion|infinite loop/i,
    impact: 'crafted input could make the application unresponsive or crash it, disrupting users’ work.' },
];

const SEVERITY = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, MODERATE: 2, LOW: 1 };
const MAX_KINDS = 5;
const MAX_COMPONENTS = 4;

function kindOf(advisory) {
  const ids = (advisory.cwes || []).map(id => Number(String(id).replace(/^CWE-/, '')));
  return KINDS.find(kind => ids.some(id => kind.cwes.includes(id))) || KINDS.find(kind => kind.words.test(advisory.summary || ''));
}

/**
 * The kinds of vulnerability published for the components needing action, most severe first: [{ label, impact,
 * components }]. The Chromium vulnerabilities of the Electron runtime count for Electron.
 */
export function vulnerabilityKinds(dependencies) {
  const found = new Map();
  const add = (advisory, component) => {
    const kind = kindOf(advisory);
    if (!kind) return;
    const entry = found.get(kind) || { ...kind, components: [], severity: 0, order: KINDS.indexOf(kind) };
    if (!entry.components.includes(component)) entry.components.push(component);
    entry.severity = Math.max(entry.severity, SEVERITY[String(advisory.severity || '').toUpperCase()] || 0);
    found.set(kind, entry);
  };
  const rows = ((dependencies && dependencies.rows) || []).filter(needsAction);
  for (const row of rows) for (const advisory of row.advisories || []) add(advisory, `${row.name} ${row.version}`);
  const electron = rows.find(row => row.name === 'electron');
  const chromium = dependencies && dependencies.chromium;
  if (electron && chromium && chromium.checked) for (const advisory of chromium.top || []) add(advisory, `${electron.name} ${electron.version}`);
  // most severe first, but every component with a recognised vulnerability is named before a kind is repeated for one
  // already named (an old Electron's many high-severity kinds would otherwise crowd out a library's Cross-Site Scripting)
  const ranked = [...found.values()].sort((a, b) => b.severity - a.severity || b.components.length - a.components.length || a.order - b.order);
  const chosen = [];
  const named = new Set();
  for (const kind of ranked) {
    if (chosen.length < MAX_KINDS && kind.components.some(component => !named.has(component))) {
      chosen.push(kind);
      kind.components.forEach(component => named.add(component));
    }
  }
  for (const kind of ranked) if (chosen.length < MAX_KINDS && !chosen.includes(kind)) chosen.push(kind);
  return chosen.sort((a, b) => ranked.indexOf(a) - ranked.indexOf(b)).map(({ label, impact, components }) => ({ label, impact, components }));
}

const list = (components) => components.length > MAX_COMPONENTS
  ? `${components.slice(0, MAX_COMPONENTS).join(', ')} and ${components.length - MAX_COMPONENTS} more` : components.join(', ');

/**
 * The sections of the finding, as Markdown lines. `app` is already escaped for Markdown.
 */
export function outdatedSections({ app, dependencies, sheet = COMPONENTS_SHEET, rating }) {
  // names and versions come from package metadata: escaped for Markdown (a version is not a numbered list)
  const text = (value) => String(value).replace(/\s+/g, ' ').replace(/[\\`*_[\]<>]/g, '\\$&');
  const attached = `the attached spreadsheet (\`${sheet}\`)`;
  const rows = ((dependencies && dependencies.rows) || []).filter(needsAction);
  const electron = rows.find(row => row.name === 'electron');
  const runtime = electron ? `, including its Electron runtime (version ${text(electron.version)}${electron.latest ? `; the latest release is ${text(electron.latest)}` : ''})` : '';
  const kinds = vulnerabilityKinds(dependencies);
  return {
    description: [
      `Testing identified the use of outdated software components in ${app}${runtime}. Vendors release updates and security patches to remediate known defects and vulnerabilities. Keeping every component on a supported, current release limits the exposure of the application and its users to compromise through publicly known weaknesses.`,
    ],
    affected: [`Refer to ${attached} for a list of affected components.`],
    implication: [
      'Vulnerabilities in outdated components are publicly documented, often together with working exploit techniques, which makes them an attractive and low-effort target. Components that are unsupported or end of life will not receive fixes for vulnerabilities discovered in future. In an Electron application the impact can be greater than on a website, because code that runs in an application window may be able to reach Node.js or operating system functionality.',
      ...(kinds.length ? [
        `It was observed that affected components in ${app} were subject to publicly disclosed vulnerabilities, including:`,
        ...kinds.map(kind => `- **${kind.label}** (${text(list(kind.components))}): ${kind.impact}`),
      ] : []),
      '*Note:* An application that uses a library or framework with a known security issue is not necessarily vulnerable to that issue. It may not use the vulnerable code, or an adversary may not be able to control how it is invoked.',
      !rating || rating.consequence === 'N/A'
        ? '*Note:* This issue was not assigned a risk rating because no published vulnerability applies to the identified versions and none was exploited during the engagement. However, it could be indicative of weaknesses within the patch management process.'
        : `*Note:* The rating reflects ${electron && (electron.support?.status === 'unsupported' || electron.support?.discontinued) ? 'the end-of-life status of the Electron runtime, which no longer receives security fixes, and ' : ''}the published vulnerabilities of the identified versions. The vulnerabilities were not exploited during the engagement. The issue could also be indicative of weaknesses within the patch management process.`,
    ],
    evidence: [`Refer to the Support status column and the advisory links for each identified component in ${attached}.`],
    recommendations: [
      `Upgrade or replace each affected component as described in the Recommended action column of ${attached}:`,
      ...(electron ? ['- Upgrade the Electron runtime to a supported release, which also brings in the security fixes of its Chromium and Node.js versions.'] : []),
      '- Upgrade components with known advisories to a release that includes the fixes, and outdated components to their latest release.',
      '- Replace components that are end of life with maintained alternatives.',
      '- Establish a patch management process that monitors components for new releases and security advisories, for example with automated dependency update pull requests or a dependency audit in the build pipeline, and applies security updates promptly.',
      '- Rebuild the packaged application and confirm the versions it ships in the final build.',
    ],
    references: [
      `- Refer to ${attached} for a list of affected components.\n\n  Refer to the Latest version column for each component for the latest identified version. Follow vendor guidance when upgrading.`,
    ],
  };
}
