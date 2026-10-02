// Keep each session's evidence while retaining the single validation field used by existing outputs.
export function validationResults(issue) {
  const validation = issue.validation;
  if (!validation) return [];
  const { history = [], ...current } = validation;
  return [current, ...history].map(result => issue.session && !result.session ? { ...result, session: issue.session } : result);
}

const rank = result => ({ confirmed: 3, observed: 2 })[result.status] || 1;
const distinct = values => [...new Map(values.map(value => [JSON.stringify(value), value])).values()];

export function recordValidation(issue, result) {
  const results = distinct([...validationResults(issue), ...validationResults({ validation: result })]);
  const best = results.reduce((a, b) => rank(b) > rank(a) ? b : a);
  issue.validation = { ...best, ...(results.length > 1 ? { history: results.filter(r => r !== best) } : {}) };
  return issue;
}

export function mergeFindingEvidence(earlier, later) {
  const merged = { ...earlier, ...later, properties: { ...earlier.properties, ...later.properties } };
  for (const field of ['evidence', 'screenshots']) {
    const values = [earlier.properties?.[field], later.properties?.[field]].flat().filter(v => v != null);
    if (values.length) merged.properties[field] = distinct(values);
  }
  const shots = [earlier.properties?.screenshot, later.properties?.screenshot, ...(merged.properties.screenshots || [])].filter(Boolean);
  if (shots.length) merged.properties.screenshots = distinct(shots);
  delete merged.validation;
  for (const result of [...validationResults(earlier), ...validationResults(later)]) recordValidation(merged, result);
  if (!earlier.properties && !later.properties && !Object.keys(merged.properties).length) delete merged.properties;
  return merged;
}

// A confirmed setting, data flow or request is not proof that injected script executed.
export function executionConfirmed(issue) {
  return issue.properties?.executed === true || issue.properties?.execution === 'observed' ||
    /^RUNTIME_CAMPAIGN_(FS_READ|NODE|ELECTRON|EVAL)$/.test(issue.id) ||
    validationResults(issue).some(r => r.status === 'confirmed' && (!r.scope || ['execution', 'exploit'].includes(r.scope)));
}
