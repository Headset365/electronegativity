import { sourceTypes } from '../../../parser/types.js';

// The checks on a packaged app's executable (src/binary: asar integrity, code signing, exploit mitigations) read the
// binary rather than code. This entry gives them a check name, so -l PackagedBinaryCheck runs them alone and -x leaves
// them out.
export default class PackagedBinaryCheck {
  constructor() {
    this.id = "CODE_SIGNING";
    this.description = __("CODE_SIGNING");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/code-signing";
  }

  match() {
    return null;
  }
}
