import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import fs from 'fs';
import path from 'path';
import { LoaderFile } from '../src/loader/index.js';
import { Parser } from '../src/parser/index.js';
import { Finder } from '../src/finder/index.js';

chaiShould();
await _i18n();

let check_tests = "test/checks/AtomicChecks";

describe('Finder', () => {
  let finder = new Finder(null, null, '4..99');

  // Load all test files
  let loader = new LoaderFile();
  let list = fs.readdirSync(check_tests);
  for (let file of list) {
    loader.load(path.join(check_tests, file));
  }
  let filenames = [...loader.list_files];

  // Parse all files and ...
  let parsers = [new Parser(false, true), new Parser(true, true), new Parser(true, false), new Parser(false, false)];
  for (let parser of parsers) {
    let testcases = new Map();

    for (let file of filenames) {
      const [type, data, content] = parser.parse(file, loader.load_buffer(file));
      let split = path.basename(file.substr(0, file.lastIndexOf('.'))).split('_');
      let num_issues = +split.pop();
      split.pop();
      let check = split.join("_").toUpperCase();

      if (!testcases.has(check)) {
        testcases.set(check, []);
      }
      testcases.get(check).push([file, type, data, num_issues, content]);
    }

    // For each ...
    for (let check of [...testcases.keys()]) {
      for (let [file, type, data, num_issues, content] of testcases.get(check)) {
        it('Finds ' + num_issues + ' issue(s) in ' + path.basename(file), async () => {
          let result = await finder.find(file, data, type, content);
          
          // Adjust visibility
          result = result.filter(i => !Object.hasOwn(i, 'visibility') || (!i.visibility.inlineDisabled && !i.visibility.globalCheckDisabled));
          
          result.filter(r => {return r.id === check;}).length.should.equal(num_issues);
        }).timeout(8000);
      }
    }
  }
});
