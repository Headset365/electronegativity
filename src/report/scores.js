// Risk scores: 100 * (1 - product of (1 - w)) over the distinct findings, w being a weight per severity scaled by
// confidence, so each finding adds less as the total grows and repeats of one finding add nothing. The external score
// counts only what someone other than the user can exploit: shared content, anyone with the app, the network, other users
// through the server, third parties, the supply chain and known vulnerabilities. From Electron-Dynamic's model.
import { consequenceOf } from '../finder/consequences.js';

const WEIGHT = { HIGH: 0.2, MEDIUM: 0.08, LOW: 0.02, INFORMATIONAL: 0 };
const CONFIDENCE = { CERTAIN: 1, FIRM: 0.8, TENTATIVE: 0.5 };
export const EXTERNAL_ROUTES = new Set(['content', 'anyone', 'network', 'server', 'thirdparty', 'supply', 'dependency']);

export const isExternal = (issue) => EXTERNAL_ROUTES.has((consequenceOf(issue.id) || {}).route);

export function riskScore(issues, { externalOnly = false } = {}) {
  const seen = new Set();
  let remaining = 1;
  for (const issue of issues) {
    if (externalOnly && !isExternal(issue)) continue;
    const key = `${issue.id}|${issue.file}|${issue.location ? issue.location.line : ''}|${issue.description}`;
    if (seen.has(key)) continue;
    seen.add(key);
    remaining *= 1 - (WEIGHT[issue.severity.name] || 0) * (CONFIDENCE[issue.confidence.name] ?? 0.8);
  }
  return Math.round(100 * (1 - remaining));
}

export const scores = (issues) => ({ risk: riskScore(issues), external: riskScore(issues, { externalOnly: true }) });
