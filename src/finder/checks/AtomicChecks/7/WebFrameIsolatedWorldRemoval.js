import { sourceTypes } from '../../../../parser/types.js';
import { severity, confidence } from '../../../attributes.js';

export default class WebFrameIsolatedWorldRemoval {
  constructor() {
    this.id = "WEB_FRAME_ISOLATED_WORLD_REMOVAL";
    this.description = __("WEB_FRAME_ISOLATED_WORLD_REMOVAL");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/breaking-changes';
  }

  match(astNode, astHelper, scope){
    if (astNode.type !== 'CallExpression') return null;
    if (!astNode.callee.property || 
        (astNode.callee.property.name !== 'setIsolatedWorldContentSecurityPolicy' &&
        astNode.callee.property.name !== 'setIsolatedWorldHumanReadableName' &&
        astNode.callee.property.name !== 'setIsolatedWorldSecurityOrigin')) {
      return null;
    }
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false }];
  }
}