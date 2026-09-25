import AffinityGlobalCheck from './AffinityGlobalCheck.js';
import AvailableSecurityFixesGlobalCheck from './AvailableSecurityFixesGlobalCheck.js';
import CSPGlobalCheck from './CSPGlobalCheck.js';
import LimitNavigationGlobalCheck from './LimitNavigationGlobalCheck.js';
import PermissionRequestHandlerGlobalCheck from './PermissionRequestHandlerGlobalCheck.js';
import HTTPResourcesAndNodeIntegrationGlobalCheck from './HTTPResourcesAndNodeIntegrationGlobalCheck.js';

const GLOBAL_CHECKS = [
  AffinityGlobalCheck,
  AvailableSecurityFixesGlobalCheck,
  CSPGlobalCheck,
  LimitNavigationGlobalCheck,
  PermissionRequestHandlerGlobalCheck,
  HTTPResourcesAndNodeIntegrationGlobalCheck
];

export { GLOBAL_CHECKS };
