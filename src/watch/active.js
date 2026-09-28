// An opt-in execution probe. It only logs a session nonce; it does not fetch, read files or call app APIs.
// Console output comes from the app's renderer when the injected event handler actually runs.
export function activeHtml(marker) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(marker || '')) throw new Error('Active test marker must be 8–80 letters, digits, _ or -');
  return `<img src="data:,${marker}" onerror="console.log('ENG_ACTIVE_EXEC:${marker}')" alt="">`;
}
