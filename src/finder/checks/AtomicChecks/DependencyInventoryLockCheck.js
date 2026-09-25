import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

// Collects the installed packages from lockfiles, for DependencyVulnerabilitiesGlobalCheck
export default class DependencyInventoryLockCheck {
  constructor() {
    this.id = "DEPENDENCY_INVENTORY_LOCK_CHECK";
    this.description = __("DEPENDENCY_INVENTORY_LOCK_CHECK");
    this.type = sourceTypes.LOCKFILE;
    this.shortenedURL = "https://osv.dev";
  }

  async match(data) {
    if (!data.packages || data.packages.length === 0) return null;
    return [{ line: 1, column: 0, id: this.id, description: `${this.description} (${data.packages.length})`, shortenedURL: this.shortenedURL,
      severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: false, properties: { packages: data.packages } }];
  }
}
