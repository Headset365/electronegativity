---
Title: Outdated Software Components
GeneratedBy: Electronegativity
Consequence: N/A
Likelihood: N/A
---

# Outdated Software Components

## Issue Description

Testing identified the use of outdated software components in vulnerable-app, including its Electron runtime (version 11.5.0; the latest release is 44.5.1). Vendors release updates and security patches to remediate known defects and vulnerabilities. Keeping every component on a supported, current release limits the exposure of the application and its users to compromise through publicly known weaknesses.

## Affected

Refer to the attached spreadsheet (`components.xlsx`) for a list of affected components.

## Implication

Vulnerabilities in outdated components are publicly documented, often together with working exploit techniques, which makes them an attractive and low-effort target. Components that are unsupported or end of life will not receive fixes for vulnerabilities discovered in future. In an Electron application the impact can be greater than on a website, because code that runs in an application window may be able to reach Node.js or operating system functionality.

It was observed that affected components in vulnerable-app were subject to publicly disclosed vulnerabilities, including:

- **Memory corruption** (electron 11.5.0): crafted content could crash the application or run code within its renderer process; where renderer isolation is weak, this can extend to the user’s computer.
- **Code and command injection** (electron 11.5.0): attacker-influenced input could be run as code or operating system commands with the privileges of the application, which can lead to compromise of the user’s computer and the data it holds.
- **Security control bypass** (electron 11.5.0): a protection the application relies on, such as an origin check, sandbox or permission control, could be bypassed, making other attacks possible.
- **Other injection** (electron 11.5.0): attacker-influenced input could be interpreted as part of a query, header or other protocol data, allowing requests or stored data to be manipulated.
- **Prototype pollution** (electron 11.5.0): attacker-controlled input could change the behaviour of objects throughout the application, which can bypass security checks or, combined with other flaws, lead to code execution.

*Note:* An application that uses a library or framework with a known security issue is not necessarily vulnerable to that issue. It may not use the vulnerable code, or an adversary may not be able to control how it is invoked.

*Note:* This issue was rated as Informational because the known vulnerabilities could not be exploited during the engagement. However, it could be indicative of weaknesses within the patch management process.

## Reproduction and Evidence

Refer to the Support status column and the advisory links for each identified component in the attached spreadsheet (`components.xlsx`).

## Recommendations

Upgrade or replace each affected component as described in the Recommended action column of the attached spreadsheet (`components.xlsx`):

- Upgrade the Electron runtime to a supported release, which also brings in the security fixes of its Chromium and Node.js versions.
- Upgrade components with known advisories to a release that includes the fixes, and outdated components to their latest release.
- Replace components that are end of life with maintained alternatives.
- Establish a patch management process that monitors components for new releases and security advisories, for example with automated dependency update pull requests or a dependency audit in the build pipeline, and applies security updates promptly.
- Rebuild the packaged application and confirm the versions it ships in the final build.

## References

- Refer to the attached spreadsheet (`components.xlsx`) for a list of affected components.

  Refer to the Latest version column for each component for the latest identified version. Follow vendor guidance when upgrading.

- CWE-1104: Use of Unmaintained Third Party Components

  https://cwe.mitre.org/data/definitions/1104.html
