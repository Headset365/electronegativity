import { sourceTypes } from '../../../parser/types.js';

// Shipped source maps are found by listing the package (src/production/sourcemaps.js), not through the AST. This entry
// gives the scan a check name, so -l SourceMapsCheck runs it alone and -x leaves it out.
export default class SourceMapsCheck {
  constructor() {
    this.id = "SOURCE_MAP_SHIPPED";
    this.description = __("SOURCE_MAP_SHIPPED");
    this.type = sourceTypes.JSON;
    this.shortenedURL = "https://developer.mozilla.org/en-US/docs/Glossary/Source_map";
  }

  match() {
    return null;
  }
}
