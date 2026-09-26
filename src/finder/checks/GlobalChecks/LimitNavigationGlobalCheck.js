import { severity, confidence } from '../../attributes.js';

export default class LimitNavigationGlobalCheck {

  constructor() {
    this.id = "LIMIT_NAVIGATION_GLOBAL_CHECK";
    this.description = {
      NONE_FOUND: __('LIMIT_NAVIGATION_GLOBAL_CHECK_NONE_FOUND'),
      NEW_WINDOW_MISSING: __('LIMIT_NAVIGATION_GLOBAL_CHECK_NEW_WINDOW_MISSING'),
      WILL_NAVIGATE_MISSING: __('LIMIT_NAVIGATION_GLOBAL_CHECK_WILL_NAVIGATE_MISSING')
    };
    this.depends = ["LimitNavigationJSCheck"];
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/LIMIT_NAVIGATION_GLOBAL_CHECK";
  }

  async perform(issues) {
    // will-frame-navigate (Electron 25+) also covers navigations of sub frames
    const willNavigateNavigations = issues.filter(e => e.properties.event === 'will-navigate' || e.properties.event === 'will-frame-navigate');
    // setWindowOpenHandler replaced the new-window event, removed in Electron 22
    const newWindowLimits = issues.filter(e => e.properties.event === 'new-window' || e.properties.event === 'setWindowOpenHandler');
    // handlers that are there but block nothing (or events that no longer fire) are reported as they are
    const removedEvents = issues.filter(e => e.properties.event === 'new-window-removed' || /-noop$/.test(e.properties.event));
    // handlers that block everything are fine and not worth listing
    const reviewable = issues.filter(issue => Array.isArray(issue.visibility.excludesGlobal) && !issue.visibility.excludesGlobal.includes(this.id) && issue.severity.value > severity.INFORMATIONAL.value);
    const missing = (description) => ({ file: "N/A", location: {line: 0, column: 0}, title: this.title, id: this.id, description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false });

    if (willNavigateNavigations.length === 0 && newWindowLimits.length === 0) { // no navigation limits, yikes!
      return [missing(this.description.NONE_FOUND), ...removedEvents];
    }

    const result = [...removedEvents];
    // both limits are needed: will-navigate covers in-place navigations, new-window/setWindowOpenHandler new windows
    if (willNavigateNavigations.length === 0) result.push(missing(this.description.WILL_NAVIGATE_MISSING));
    if (newWindowLimits.length === 0) result.push(missing(this.description.NEW_WINDOW_MISSING));

    // when both are there, the handlers are still worth a manual review unless the global check is explicitly disabled
    if (result.length === removedEvents.length) return [...result, ...reviewable.filter(i => !removedEvents.includes(i))];
    return result;
  }
}
