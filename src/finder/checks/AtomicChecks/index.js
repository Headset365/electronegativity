import AffinityHTMLCheck from './AffinityHTMLCheck.js';
import AffinityJSCheck from './AffinityJSCheck.js';
import AllowPopupsHTMLCheck from './AllowPopupHTMLCheck.js';
import AuxclickHTMLCheck from './AuxclickHTMLCheck.js';
import AuxclickJSCheck from './AuxclickJSCheck.js';
import BlinkFeaturesHTMLCheck from './BlinkFeaturesHTMLCheck.js';
import BlinkFeaturesJSCheck from './BlinkFeaturesJSCheck.js';
import CertificateErrorEventJSCheck from './CertificateErrorEventJSCheck.js';
import CertificateVerifyProcJSCheck from './CertificateVerifyProcJSCheck.js';
import ContextIsolationJSCheck from './ContextIsolationJSCheck.js';
import CSPHTMLCheck from './CSPHTMLCheck.js';
import CSPJSCheck from './CSPJSCheck.js';
import CustomArgumentsJSCheck from './CustomArgumentsJSCheck.js';
import CustomArgumentsJSONCheck from './CustomArgumentsJSONCheck.js';
import DangerousFunctionsJSCheck from './DangerousFunctionsJSCheck.js';
import ElectronVersionJSONCheck from './ElectronVersionJSONCheck.js';
import ExperimentalFeaturesHTMLCheck from './ExperimentalFeaturesHTMLCheck.js';
import ExperimentalFeaturesJSCheck from './ExperimentalFeaturesJSCheck.js';
import HTTPResourcesHTMLCheck from './HTTPResourcesHTMLCheck.js';
import HTTPResourcesJSCheck from './HTTPResourcesJSCheck.js';
import InsecureContentHTMLCheck from './InsecureContentHTMLCheck.js';
import InsecureContentJSCheck from './InsecureContentJSCheck.js';
import LimitNavigationJSCheck from './LimitNavigationJSCheck.js';
import NodeIntegrationHTMLCheck from './NodeIntegrationHTMLCheck.js';
import NodeIntegrationJSCheck from './NodeIntegrationJSCheck.js';
import NodeIntegrationAttachEventJSCheck from './NodeIntegrationAttachEventJSCheck.js';
import OpenExternalJSCheck from './OpenExternalJSCheck.js';
import PermissionRequestHandlerJSCheck from './PermissionRequestHandlerJSCheck.js';
import RemoteModuleJSCheck from './RemoteModuleJSCheck.js';
import SandboxJSCheck from './SandboxJSCheck.js';
import SecurityWarningsDisabledJSCheck from './SecurityWarningsDisabledJSCheck.js';
import SecurityWarningsDisabledJSONCheck from './SecurityWarningsDisabledJSONCheck.js';
import PreloadJSCheck from './PreloadJSCheck.js';
import ProtocolHandlersJSCheck from './ProtocolHandlersJSCheck.js';
import WebSecurityHTMLCheck from './WebSecurityHTMLCheck.js';
import WebSecurityJSCheck from './WebSecurityJSCheck.js';
import ContextBridgeExposureJSCheck from './ContextBridgeExposureJSCheck.js';
import DevToolsJSCheck from './DevToolsJSCheck.js';
import FusesJSCheck from './FusesJSCheck.js';
import FusesJSONCheck from './FusesJSONCheck.js';
import IpcSenderValidationJSCheck from './IpcSenderValidationJSCheck.js';
import ProtocolPrivilegesJSCheck from './ProtocolPrivilegesJSCheck.js';
import WebviewTagJSCheck from './WebviewTagJSCheck.js';
import WindowOpenHandlerJSCheck from './WindowOpenHandlerJSCheck.js';

import NodeTlsRejectUnauthorizedJSCheck from './NodeTlsRejectUnauthorizedJSCheck.js';
import NodeTlsRejectUnauthorizedJSONCheck from './NodeTlsRejectUnauthorizedJSONCheck.js';
import { OpenPathJSCheck, ShowItemInFolderJSCheck, WriteShortcutJSCheck } from './ShellApiJSChecks.js';
import FileHandlerJSCheck from './FileHandlerJSCheck.js';
import DependencyInventoryLockCheck from './DependencyInventoryLockCheck.js';
import FileHandlerJSONCheck from './FileHandlerJSONCheck.js';
import { SecureKeyboardEntryJSCheck, SecureKeyboardEntryHTMLCheck } from './SecureKeyboardEntryChecks.js';
import { WebGLJSCheck, WebGLHTMLCheck, WebSQLJSCheck, WebSQLHTMLCheck } from './WebPreferenceFeatureChecks.js';

const CHECKS = [
  AffinityHTMLCheck,
  AffinityJSCheck,
  AllowPopupsHTMLCheck,
  AuxclickHTMLCheck,
  AuxclickJSCheck,
  BlinkFeaturesHTMLCheck,
  BlinkFeaturesJSCheck,
  CertificateErrorEventJSCheck,
  CertificateVerifyProcJSCheck,
  ContextIsolationJSCheck,
  CSPHTMLCheck,
  CSPJSCheck,
  CustomArgumentsJSCheck,
  CustomArgumentsJSONCheck,
  DangerousFunctionsJSCheck,
  ElectronVersionJSONCheck, 
  ExperimentalFeaturesJSCheck,
  ExperimentalFeaturesHTMLCheck,
  HTTPResourcesHTMLCheck,
  HTTPResourcesJSCheck,
  InsecureContentHTMLCheck,
  InsecureContentJSCheck,
  LimitNavigationJSCheck,
  NodeIntegrationHTMLCheck,
  NodeIntegrationJSCheck,
  NodeIntegrationAttachEventJSCheck,
  OpenExternalJSCheck,
  PermissionRequestHandlerJSCheck,
  RemoteModuleJSCheck,
  SandboxJSCheck,
  SecurityWarningsDisabledJSCheck,
  SecurityWarningsDisabledJSONCheck,
  PreloadJSCheck,
  ProtocolHandlersJSCheck,
  WebSecurityHTMLCheck,
  WebSecurityJSCheck,
  ContextBridgeExposureJSCheck,
  DevToolsJSCheck,
  FusesJSCheck,
  FusesJSONCheck,
  IpcSenderValidationJSCheck,
  ProtocolPrivilegesJSCheck,
  WebviewTagJSCheck,
  WindowOpenHandlerJSCheck,
  NodeTlsRejectUnauthorizedJSCheck,
  NodeTlsRejectUnauthorizedJSONCheck,
  OpenPathJSCheck,
  ShowItemInFolderJSCheck,
  WriteShortcutJSCheck,
  FileHandlerJSCheck,
  DependencyInventoryLockCheck,
  FileHandlerJSONCheck,
  SecureKeyboardEntryJSCheck,
  SecureKeyboardEntryHTMLCheck,
  WebGLJSCheck,
  WebGLHTMLCheck,
  WebSQLJSCheck,
  WebSQLHTMLCheck,
];

export { CHECKS };
