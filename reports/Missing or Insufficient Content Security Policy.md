---
Title: Missing or Insufficient Content Security Policy
GeneratedBy: Electronegativity
Consequence: Medium
Likelihood: Likely
---

# Missing or Insufficient Content Security Policy

## Issue Description

Testing identified that the pages of vulnerable-app are not protected by an effective Content Security Policy (CSP), the browser mechanism that limits the scripts and other resources a page can load and run.

- **No Content Security Policy.** No Content Security Policy is applied to the application’s pages.

## Affected

The following locations in vulnerable-app are affected:

- vulnerable-app (application-wide) — No Content Security Policy

## Implication

- **No Content Security Policy.** Without a policy, the browser places no restrictions on the scripts and other resources that injected content can load and run, so an injection flaw has its full effect.

*Note:* A Content Security Policy is an additional layer of defence. Its absence does not create an injection flaw, but it increases the impact of one.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Review the configuration of vulnerable-app, which shows that no Content Security Policy is defined for the application’s pages.

## Recommendations

- Define a restrictive Content Security Policy for every page, for example `default-src 'self'; script-src 'self'; object-src 'none'`, delivered as a response header or meta tag. Verify the policy is applied in the packaged application and that legitimate content still loads.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
session.defaultSession.webRequest.onHeadersReceived((d, cb) => cb({ responseHeaders: { ...d.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"] } }));
```

## References

- CWE-693: Protection Mechanism Failure

  https://cwe.mitre.org/data/definitions/693.html

- Electron security checklist: 7. Define a content security policy

  https://www.electronjs.org/docs/latest/tutorial/security#7-define-a-content-security-policy
