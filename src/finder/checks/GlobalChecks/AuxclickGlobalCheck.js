export default class AuxclickGlobalCheck {
  constructor() {
    this.id = "AUXCLICK_GLOBAL_CHECK";
    this.description = "Middle-click (auxclick) findings, dropped when setWindowOpenHandler controls new windows";
    this.depends = ["AuxclickJSCheck", "AuxclickHTMLCheck", "LimitNavigationJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/web-contents#contentssetwindowopenhandlerhandler";
  }

  async perform(issues) {
    // navigation findings belong to LimitNavigationGlobalCheck, only look at them here
    const auxclick = issues.filter(issue => issue.id === 'AUXCLICK_JS_CHECK' || issue.id === 'AUXCLICK_HTML_CHECK');
    // setWindowOpenHandler sees every window a renderer asks for, middle-clicks included
    const handled = issues.some(issue => issue.properties && issue.properties.event === 'setWindowOpenHandler');
    return handled ? [] : auxclick;
  }
}
