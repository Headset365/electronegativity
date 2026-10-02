---
Title: Cross-Site Scripting in Content Rendering
GeneratedBy: Electronegativity
Consequence: Medium
Likelihood: Possible
---

# Cross-Site Scripting in Content Rendering

## Issue Description

Testing identified that vulnerable-app renders dynamic content as HTML in a way that could allow cross-site scripting (XSS). In an Electron application, script injected into a window can have access beyond the page itself, depending on the window’s configuration.

- **Dynamic content inserted as HTML.** The application inserts dynamic content into a page as HTML, for example through `innerHTML` or a rich-text editor, without sanitising it first.

## Affected

The following locations in vulnerable-app are affected:

- `src/preload.js:3` — Dynamic content inserted as HTML

## Implication

- **Dynamic content inserted as HTML.** If an attacker can influence that content, for example by saving it for another user to view, their markup and script would run in the viewer’s application window, with access to the user’s session and to any privileged functions available to the page.

*Note:* Exploitation requires an attacker to be able to supply the content that is rendered, for example by saving it for another user to view.

## Reproduction and Evidence

No instance of this issue was validated at runtime during testing. The locations identified through review of the application code are listed under Affected.

## Recommendations

- Render untrusted content as text. Where HTML formatting is required, sanitise it with a maintained library (such as DOMPurify) before insertion, allowing only the elements and attributes needed. Verify that a harmless script test is displayed as text.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
el.textContent = value;   // or el.innerHTML = DOMPurify.sanitize(value)
```

## References

- CWE-79: Improper Neutralization of Input During Web Page Generation

  https://cwe.mitre.org/data/definitions/79.html

- OWASP DOM based XSS Prevention Cheat Sheet

  https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

- Electron security checklist

  https://www.electronjs.org/docs/latest/tutorial/security
