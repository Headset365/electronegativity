import { severity, confidence } from '../../attributes.js';

// http://127.0.0.1:37840/, http://localhost/, http://[::1]:8080
const isLoopback = (url) => /^http:\/\/(?:127(?:\.\d{1,3}){3}|localhost|\[::1\])(?::\d+)?(?:[/?#]|$)/i.test(url.trim());

export default class HTTPResourcesAndNodeIntegrationGlobalCheck {

  constructor() {
    this.id = "HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK";
    this.description = { INSECURE_INTEGRATION: __('HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK')};
    this.depends = ["HTTPResourcesJavascriptCheck","HTTPResourcesHTMLCheck","NodeIntegrationHTMLCheck", "NodeIntegrationJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#2-do-not-enable-nodejs-integration-for-remote-content";
  }

  async perform(issues) {
    var httpResourcesIssues = issues.filter(e => e.id === 'HTTP_RESOURCES_JS_CHECK' || e.id === "HTTP_RESOURCES_HTML_CHECK");
    var nodeIntegrationIssues = issues.filter(e => e.id === 'NODE_INTEGRATION_HTML_CHECK' || e.id === 'NODE_INTEGRATION_JS_CHECK');

    if (httpResourcesIssues.length > 0 && nodeIntegrationIssues.length > 0) {
      // the HTTP addresses loaded; the app's own local server (127.0.0.1, localhost) never crosses the network
      const urls = [...new Set(httpResourcesIssues.map(e => e.properties && e.properties.url).filter(url => typeof url === 'string'))];
      const loopbackOnly = urls.length > 0 && urls.every(isLoopback);
      issues.push({ file: "N/A", location: {line: 0, column: 0}, id: this.id,
        description: loopbackOnly ? `${this.description.INSECURE_INTEGRATION} (only the application's own local server is loaded over HTTP: ${urls.join(', ')})` : `${this.description.INSECURE_INTEGRATION}${urls.length ? ` (${urls.join(', ')})` : ''}`,
        properties: { urls, loopbackOnly }, shortenedURL: this.shortenedURL, severity: loopbackOnly ? severity.LOW : severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: true });
    }

    return issues;

  }
}
