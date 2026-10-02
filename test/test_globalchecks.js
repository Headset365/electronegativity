import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import fs from 'fs';
import path from 'path';
import { LoaderDirectory } from '../src/loader/index.js';
import { Parser } from '../src/parser/index.js';
import { Finder } from '../src/finder/index.js';
import { GlobalChecks } from '../src/finder/index.js';

chaiShould();
await _i18n();

let globalcheck_tests = "test/checks/GlobalChecks";

describe('GlobalChecks', async () => {
  const previousFetch = globalThis.fetch;
  before(() => {
    globalThis.fetch = async (url, options) => {
      url.should.equal('https://api.osv.dev/v1/querybatch');
      options.method.should.equal('POST');
      const { queries } = JSON.parse(options.body);
      return { ok: true, json: async () => ({ results: queries.map(query => ({ vulns:
        query.package.name === 'lodash' && query.version === '4.17.15' ? [{ id: 'GHSA-test-lodash' }] : [] })) }) };
    };
  });
  after(() => { globalThis.fetch = previousFetch; });
  const electronVersions = '4..8';
  const globalChecker = new GlobalChecks(null, null, electronVersions);
  // These are rule unit tests: fixed service data keeps them independent of connectivity and release dates.
  const vulnerableVersions = new Set(['4.1.4', '1.0.0', '3.0.4', '4.0.7']);
  for (const check of globalChecker._constructed_checks) {
    if (check.id === 'AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK')
      check.fetchAdvisories = async versions => new Map(versions.map(version => [version, vulnerableVersions.has(version) ? ['GHSA-test-electron'] : []]));
    if (check.id === 'UNSUPPORTED_VERSION_GLOBAL_CHECK') check.getReleases = async () => ['40.1.0', '39.2.3', '38.5.0'];
  }
  let directories = fs.readdirSync(globalcheck_tests);
  const parser = new Parser(false, true);

  for (let dir of directories) {
    // test the globalCheck
    it('Testing ' + dir, async () => {
      const loader = new LoaderDirectory();
      await loader.load(path.join(globalcheck_tests, dir));

      let filenames = [...loader.list_files];

      //gets the check name and issues count
      let split = dir.split('_');
      let num_issues = +split.pop();
      split.pop();
      let check = split.join("_").toUpperCase();

      var issues = [];

      // just take the check of interest
      var testedCheck = globalChecker._constructed_checks.findIndex(gc => gc.id === check);
      var globalCheck = globalChecker._constructed_checks[testedCheck];

      // loads the dependencies for the current globalCheck
      let finder = await new Finder(globalCheck.depends.map(check => check.toLowerCase()), null, electronVersions);
      // run the checks required by the globalCheck in order to work
      for (let file of filenames) {
        const [type, data, content] = parser.parse(file, loader.load_buffer(file));
        let findings = await finder.find(file, data, type, content);
        if (findings.length > 0) issues = issues.concat(findings);
      }
      // test the globalCheck
      let result = await globalCheck.perform(issues);
      result.filter(r => {return r.id === globalCheck.id;}).length.should.equal(num_issues);
      await loader.stash();
    }).timeout(8000);
  }
});
