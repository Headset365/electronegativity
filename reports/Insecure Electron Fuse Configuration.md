---
Title: Insecure Electron Fuse Configuration
GeneratedBy: Electronegativity
Consequence: Low
Likelihood: Rare
---

# Insecure Electron Fuse Configuration

## Issue Description

Testing identified that the Electron fuses of vulnerable-app, security settings fixed in the executable when the application is packaged, leave hardening features disabled.

- **Node.js entry points enabled.** The application’s Electron fuses leave Node.js entry points enabled, such as `RunAsNode`, the `NODE_OPTIONS` environment variable or the `--inspect` debugging arguments.
- **Archive integrity not enforced.** The application’s Electron fuses do not enforce the integrity of the application archive (`app.asar`) or restrict loading code to it.
- **Cookie encryption or file protocol fuse insecure.** The application’s Electron fuses leave cookie encryption disabled, or grant extra privileges to content loaded over `file:` URLs.

## Affected

The following locations in vulnerable-app are affected:

- `package.json:1`
  - Node.js entry points enabled
  - Archive integrity not enforced
  - Cookie encryption or file protocol fuse insecure

## Implication

- **Node.js entry points enabled.** Someone able to start the application on the device, including malware running as the user, could use these entry points to run arbitrary code under the application’s identity and with any trust the application has been granted, for example by security software.
- **Archive integrity not enforced.** Someone able to modify the installation folder could change the application’s code without detection, and the modified code would run whenever a user starts the application.
- **Cookie encryption or file protocol fuse insecure.** Cookies, including session cookies, are stored unencrypted in the user’s profile, and `file:` content has more access than the application needs.

*Note:* These settings matter to someone who can run or modify the application on the device. They do not provide remote access on their own.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.
- Review the packaging configuration in `package.json` and the build scripts. This shows that no Electron fuse configuration is applied when the application is packaged, so `RunAsNode`, `NODE_OPTIONS`, `--inspect` and archive integrity remain at their insecure defaults.

## Recommendations

- Disable the `RunAsNode`, `EnableNodeOptionsEnvironmentVariable` and `EnableNodeCliInspectArguments` fuses when packaging the application. Verify the values with `npx @electron/fuses read --app <executable>`.
- Enable the `EnableEmbeddedAsarIntegrityValidation` and `OnlyLoadAppFromAsar` fuses when packaging the application. Verify that the application refuses to start with a modified test archive.
- Enable the `EnableCookieEncryption` fuse and disable `GrantFileProtocolExtraPrivileges` when packaging the application. Verify the values in the shipped executable.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
flipFuses(exe, { version: FuseVersion.V1, [FuseV1Options.RunAsNode]: false, [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, [FuseV1Options.EnableNodeCliInspectArguments]: false, [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true, [FuseV1Options.OnlyLoadAppFromAsar]: true, [FuseV1Options.EnableCookieEncryption]: true, [FuseV1Options.GrantFileProtocolExtraPrivileges]: false });
```

## References

- CWE-693: Protection Mechanism Failure

  https://cwe.mitre.org/data/definitions/693.html

- Electron documentation: Fuses

  https://www.electronjs.org/docs/latest/tutorial/fuses
