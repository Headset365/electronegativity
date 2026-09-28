import AffinityGlobalCheck from './AffinityGlobalCheck.js';
import AvailableSecurityFixesGlobalCheck from './AvailableSecurityFixesGlobalCheck.js';
import CSPGlobalCheck from './CSPGlobalCheck.js';
import LimitNavigationGlobalCheck from './LimitNavigationGlobalCheck.js';
import PermissionRequestHandlerGlobalCheck from './PermissionRequestHandlerGlobalCheck.js';
import HTTPResourcesAndNodeIntegrationGlobalCheck from './HTTPResourcesAndNodeIntegrationGlobalCheck.js';
import FusesGlobalCheck from './FusesGlobalCheck.js';
import WebviewGlobalCheck from './WebviewGlobalCheck.js';
import CertificatePinningGlobalCheck from './CertificatePinningGlobalCheck.js';
import SecureKeyboardEntryGlobalCheck from './SecureKeyboardEntryGlobalCheck.js';
import DependencyVulnerabilitiesGlobalCheck from './DependencyVulnerabilitiesGlobalCheck.js';
import UnsupportedVersionGlobalCheck from './UnsupportedVersionGlobalCheck.js';
import SandboxGlobalCheck from './SandboxGlobalCheck.js';
import AuxclickGlobalCheck from './AuxclickGlobalCheck.js';
import IframeSandboxGlobalCheck from './IframeSandboxGlobalCheck.js';
import EndOfLifeLibrariesGlobalCheck from './EndOfLifeLibrariesGlobalCheck.js';
import IpcChannelMapGlobalCheck from './IpcChannelMapGlobalCheck.js';
import { WindowSessionGlobalCheck, NavigationRedirectGlobalCheck, CSPDirectivesGlobalCheck } from './ConfigReviewGlobalChecks.js';

const GLOBAL_CHECKS = [
  AffinityGlobalCheck,
  AvailableSecurityFixesGlobalCheck,
  CSPGlobalCheck,
  LimitNavigationGlobalCheck,
  PermissionRequestHandlerGlobalCheck,
  HTTPResourcesAndNodeIntegrationGlobalCheck,
  FusesGlobalCheck,
  WebviewGlobalCheck,
  CertificatePinningGlobalCheck,
  SecureKeyboardEntryGlobalCheck,
  DependencyVulnerabilitiesGlobalCheck,
  UnsupportedVersionGlobalCheck,
  SandboxGlobalCheck,
  AuxclickGlobalCheck,
  IframeSandboxGlobalCheck,
  EndOfLifeLibrariesGlobalCheck,
  IpcChannelMapGlobalCheck,
  WindowSessionGlobalCheck,
  NavigationRedirectGlobalCheck,
  CSPDirectivesGlobalCheck
];

export { GLOBAL_CHECKS };
