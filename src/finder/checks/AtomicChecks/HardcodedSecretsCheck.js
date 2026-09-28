import { sourceTypes } from '../../../parser/types.js';

// The hard-coded secret scan (src/secrets/scan.js) runs over every file that ships, binaries included, rather than
// through the AST. This entry gives it a check name, so -l HardcodedSecretsCheck runs it alone and -x leaves it out.
export default class HardcodedSecretsCheck {
  constructor() {
    this.id = "HARDCODED_SECRET";
    this.description = __("HARDCODED_SECRET");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://cwe.mitre.org/data/definitions/798.html";
  }

  match() {
    return null;
  }
}
