import fs from 'node:fs';
import path from 'node:path';
import i18n from 'i18n';
import pkg from '../../package.json' with { type: 'json' };

const DEFAULT_LOCALE = 'en-US';
const LOCAL_LOCALES = ['en-US', 'es-ES', 'fr-FR']; // some widespread locales available locally

let initialized;

// Converts POSIX-style locales (e.g. "en_US.UTF-8") to the BCP 47 form used by the locale files (e.g. "en-US")
function normalizeLocale(locale) {
  if (!locale || locale === 'C' || locale === 'POSIX') return DEFAULT_LOCALE;
  return locale.split('.')[0].split('@')[0].replace('_', '-');
}

async function fetchRemoteCatalog(locale) {
  try {
    const response = await fetch(`${pkg.i18nSource}/${locale}.json`, { signal: AbortSignal.timeout(1000) });
    if (response.ok) return await response.json();
  } catch {
    console.log("Could not retrieve updated translations for the current locale");
  }
  return undefined;
}

export default function _i18n() {
  initialized ??= (async () => {
    const locale = normalizeLocale(process.env.LANG);

    const staticCatalog = {};
    for (const l of LOCAL_LOCALES)
      staticCatalog[l] = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, `${l}.json`), 'utf8'));

    const remoteCatalog = await fetchRemoteCatalog(locale);
    if (remoteCatalog)
      staticCatalog[locale] = { ...remoteCatalog, ...staticCatalog[locale] }; // bundled strings take precedence

    i18n.configure({
      staticCatalog,
      defaultLocale: DEFAULT_LOCALE,
      updateFiles: false,
      objectNotation: true,
      retryInDefaultLocale: true,
      register: globalThis
    });

    i18n.setLocale(staticCatalog[locale] ? locale : DEFAULT_LOCALE);
  })();
  return initialized;
}
