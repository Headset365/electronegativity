import fs from 'node:fs';
import { should as chaiShould } from 'chai';
import i18n from '../src/locales/i18n.js';
import { CHECKS } from '../src/finder/checks/AtomicChecks/index.js';
import { ELECTRON_ATOMIC_UPGRADE_CHECKS } from '../src/finder/checks/AtomicChecks/ElectronAtomicUpgradeChecks.js';
import { GLOBAL_CHECKS } from '../src/finder/checks/GlobalChecks/index.js';

chaiShould();

// The pages themselves are verified online by `npm run check:references`
describe('Check references', () => {
  let checks;
  before(async () => {
    await i18n();
    checks = [...CHECKS, ...Object.values(ELECTRON_ATOMIC_UPGRADE_CHECKS).flat(), ...GLOBAL_CHECKS].map(C => new C());
  });

  it('every check links to documentation over https', () => {
    const isHttps = (url) => { try { return new URL(url).protocol === 'https:'; } catch { return false; } };
    const missing = checks.filter(c => !isHttps(c.shortenedURL)).map(c => `${c.id}: ${c.shortenedURL}`);
    missing.should.deep.equal([]);
  });

  it('no check links to the retired Electronegativity wiki or git.io short links', () => {
    const dead = checks.filter(c => /doyensec\/electronegativity\/wiki|git\.io/.test(c.shortenedURL)).map(c => c.id);
    dead.should.deep.equal([]);
  });
});

describe('Translations', () => {
  const load = (locale) => JSON.parse(fs.readFileSync(new URL(`../src/locales/${locale}.json`, import.meta.url), 'utf8'));
  const english = load('en-US');
  const placeholders = (text) => (text.match(/\{\{\w+\}\}/g) || []).sort();

  for (const locale of ['es-ES', 'fr-FR']) {
    it(`${locale} translates every message, with the same placeholders`, () => {
      const translated = load(locale);
      Object.keys(english).filter(key => !(key in translated)).should.deep.equal([], 'missing keys');
      Object.keys(translated).filter(key => !(key in english)).should.deep.equal([], 'unknown keys');
      Object.keys(english).filter(key => placeholders(english[key]).join() !== placeholders(translated[key]).join()).should.deep.equal([], 'placeholders differ');
    });
  }
});
