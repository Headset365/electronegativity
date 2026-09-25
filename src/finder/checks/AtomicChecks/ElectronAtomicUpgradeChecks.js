import BrowserWindowWebPreferences from './5/BrowserWindowWebPreferences.js';
import NativeWindowOpen from './5/NativeWindowOpen.js';
import PrivilegedSchemesRegistrationRemoval from './5/PrivilegedSchemesRegistrationRemoval.js';
import SetSpellCheckProviderDeprecation from './5/SetSpellCheckProviderDeprecation.js';
import WebFrameIsolatedWorldDeprecation from './5/WebFrameIsolatedWorldDeprecation.js';
import ContentTracingGetTraceBufferUsage from './6/ContentTracingGetTraceBufferUsage.js';
import EnableMixedSandboxDeprecation from './6/EnableMixedSandboxDeprecation.js';
import QuerySystemIdleStateDeprecation from './6/QuerySystemIdleStateDeprecation.js';
import QuerySystemIdleTimeDeprecation from './6/QuerySystemIdleTimeDeprecation.js';
import RequireElectronScreen from './6/RequireElectronScreen.js';
import RequireSandboxedRenderers from './6/RequireSandboxedRenderers.js';
import SetHighlightModeDeprecation from './6/SetHighlightModeDeprecation.js';
import SetNullMenuDeprecation from './6/SetNullMenuDeprecation.js';
import ClearAuthCache from './7/ClearAuthCache.js';
import ContentTracingGetTraceBufferUsageRemoval from './7/ContentTracingGetTraceBufferUsageRemoval.js';
import EnableMixedSandboxRemoval from './7/EnableMixedSandboxRemoval.js';
import QuerySystemIdleState from './7/QuerySystemIdleState.js';
import QuerySystemIdleTime from './7/QuerySystemIdleTime.js';
import SetHighlightModeRemoval from './7/SetHighlightModeRemoval.js';
import WebFrameIsolatedWorldRemoval from './7/WebFrameIsolatedWorldRemoval.js';
import WebKitDirectoryChange from './7/WebKitDirectoryChange.js';
import AllowRendererProcessReuse from './8/AllowRendererProcessReuse.js';
import GetColor from './8/GetColor.js';
import GetWebContents from './8/GetWebContents.js';
import IPCSend from './8/IPCSend.js';
import SetLayoutZoomLevelLimits from './8/SetLayoutZoomLevelLimits.js';
import VisibleOnFullScreen from './8/VisibleOnFullScreen.js';

const ELECTRON_ATOMIC_UPGRADE_CHECKS = {
  5: [
    BrowserWindowWebPreferences,
    NativeWindowOpen,
    PrivilegedSchemesRegistrationRemoval,
    SetSpellCheckProviderDeprecation,
    WebFrameIsolatedWorldDeprecation
  ],
  6: [
    ContentTracingGetTraceBufferUsage,
    EnableMixedSandboxDeprecation,
    QuerySystemIdleStateDeprecation,
    QuerySystemIdleTimeDeprecation,
    RequireElectronScreen,
    RequireSandboxedRenderers,
    SetNullMenuDeprecation,      
    SetHighlightModeDeprecation
  ],
  7: [
    ClearAuthCache,
    ContentTracingGetTraceBufferUsageRemoval,
    EnableMixedSandboxRemoval,
    QuerySystemIdleState,
    QuerySystemIdleTime,
    SetHighlightModeRemoval,
    WebFrameIsolatedWorldRemoval,
    WebKitDirectoryChange
  ],
  8: [
    AllowRendererProcessReuse,
    GetColor,
    GetWebContents,
    IPCSend,
    SetLayoutZoomLevelLimits,
    VisibleOnFullScreen
  ]
};

export { ELECTRON_ATOMIC_UPGRADE_CHECKS };
