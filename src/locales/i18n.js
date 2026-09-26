import fs from 'node:fs';
import path from 'node:path';
import i18n from 'i18n';

const DEFAULT_LOCALE = 'en-US';
const LOCAL_LOCALES = ['en-US', 'es-ES', 'fr-FR']; // some widespread locales available locally

let initialized;

// Converts POSIX-style locales (e.g. "en_US.UTF-8") to the BCP 47 form used by the locale files (e.g. "en-US")
function normalizeLocale(locale) {
  if (!locale || locale === 'C' || locale === 'POSIX') return DEFAULT_LOCALE;
  return locale.split('.')[0].split('@')[0].replace('_', '-');
}

export default function _i18n() {
  initialized ??= (async () => {
    const locale = normalizeLocale(process.env.LANG);

    const staticCatalog = {};
    for (const l of LOCAL_LOCALES)
      staticCatalog[l] = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, `${l}.json`), 'utf8'));

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
