export default class SandboxGlobalCheck {
  constructor() {
    this.id = "SANDBOX_GLOBAL_CHECK";
    this.description = __("SANDBOX_JS_CHECK_ENABLED_GLOBALLY");
    this.depends = ["SandboxJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/app#appenablesandbox";
  }

  async perform(issues) {
    // app.enableSandbox() overrides webPreferences.sandbox for every renderer
    if (issues.some(issue => issue.properties && issue.properties.sandboxedGlobally)) return [];
    return issues;
  }
}
