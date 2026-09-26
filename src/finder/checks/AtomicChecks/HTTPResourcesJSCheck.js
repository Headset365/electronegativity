import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class HTTPResourcesJavascriptCheck {
  constructor() {
    this.id = "HTTP_RESOURCES_JS_CHECK";
    this.description = __("HTTP_RESOURCES_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/HTTP_RESOURCES_JS_CHECK";
  }

  match(astNode, astHelper){
    if (astNode.type !== 'CallExpression') return null;
    if (!(astNode.callee.property && astNode.callee.property.name === "loadURL")) return null;

    switch (astNode.arguments[0].type) {
      case astHelper.StringLiteral:
        if (!astNode.arguments[0].value.trim().toUpperCase().startsWith("HTTP://"))
          return undefined;
        break;
      case "TemplateLiteral":
        if (astNode.arguments[0].type !== "TemplateLiteral" ||
            astNode.arguments[0].quasis[0].type !== "TemplateElement" ||
            !astNode.arguments[0].quasis[0].value.cooked.trim().toUpperCase().startsWith("HTTP://"))
          return undefined;
        break;
      default:
        return undefined;
    }

    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false }];
  }
}
