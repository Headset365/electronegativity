module.exports = {
  appId: 'com.example.app',
  electronFuses: {
    runAsNode: false,
    enableCookieEncryption: true,
    enableNodeOptionsEnvironmentVariable: false,
    enableNodeCliInspectArguments: false,
    enableEmbeddedAsarIntegrityValidation: true,
    onlyLoadAppFromAsar: false,
    grantFileProtocolExtraPrivileges: false,
  },
};
