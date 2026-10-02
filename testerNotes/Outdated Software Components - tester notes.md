<!-- Electronegativity tester notes: not part of the client report -->

# Outdated Software Components: tester notes

Working notes for the finding `Outdated Software Components.md`. They are not part of the client report.

## Rating basis

Consequence: N/A. Likelihood: N/A.

- Rated Informational: the known vulnerabilities of the listed components were not exploited during the engagement.

## Checks

- **AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK** (1 instance): The Electron version in use lacks published security fixes; some of them are exploitable by web content (see the advisories).
- **UNSUPPORTED_VERSION_GLOBAL_CHECK** (1 instance): This Electron version no longer receives security fixes, including for flaws exploitable by web content.
- **CHROMIUM_ADVISORIES** (1 instance): The browser engine inside the app misses security fixes; the renderer bugs among them are exploitable by any web content the app shows, and those in CISA's KEV list are exploited in the wild.

## Validation steps

## Recorded evidence (all instances)

- **AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK** at `package.json`
  - Validation: not run; static or artifact observation only
  - Advisory: GHSA-3c8v-cfp5-9885
  - Advisory: GHSA-3p22-ghq8-v749
  - Advisory: GHSA-4f78-qhmw-8j8m
  - Advisory: GHSA-4p4r-m79c-wq3v
  - Advisory: GHSA-532v-xpq5-8h95
  - Advisory: GHSA-5c9j-mhmv-5xgx
  - Advisory: GHSA-5rqw-r77c-jp79
  - Advisory: GHSA-6r2x-8pq8-9489
  - Advisory: GHSA-77xc-hjv8-ww97
  - Advisory: GHSA-7m48-wc93-9g85
  - Advisory: GHSA-7x97-j373-85x5
  - Advisory: GHSA-8337-3p73-46f4
  - Advisory: GHSA-9899-m83m-qhpj
  - Advisory: GHSA-9f4c-93c8-jc8g
  - Advisory: GHSA-9pf5-hg6p-4pwp
  - Advisory: GHSA-9qh4-3jw8-366w
  - Advisory: GHSA-9w97-2464-8783
  - Advisory: GHSA-9wfr-w7mm-pc7f
  - Advisory: GHSA-f2r8-jv7c-xqmp
  - Advisory: GHSA-f37v-82c4-4x64
  - Advisory: GHSA-f3pv-wv63-48x8
  - Advisory: GHSA-ff2p-hmqr-hxm4
  - Advisory: GHSA-gr2m-v5gq-v685
  - Advisory: GHSA-h7rp-cf8h-j98x
  - Advisory: GHSA-hq2x-r82h-9wj4
  - Advisory: GHSA-j84w-jfhq-vhvj
  - Advisory: GHSA-jfqx-fxh3-c62j
  - Advisory: GHSA-jjp3-mq3x-295m
  - Advisory: GHSA-jm7p-cc5g-qwxx
  - Advisory: GHSA-m55f-7gqj-fr98
  - Advisory: GHSA-mq8j-3h7h-p8g7
  - Advisory: GHSA-mwmh-mq4g-g6gr
  - Advisory: GHSA-p2jh-44qj-pf2v
  - Advisory: GHSA-p2rr-rvmm-c5fp
  - Advisory: GHSA-p7v2-p9m8-qqg7
  - Advisory: GHSA-pfmc-3mgc-p6fp
  - Advisory: GHSA-qqvq-6xgj-jw8g
  - Advisory: GHSA-r5p7-gp4j-qhrx
  - Advisory: GHSA-v3j7-r9gq-3gjw
  - Advisory: GHSA-v64r-4m7r-3mvq
  - Advisory: GHSA-v93f-fgjr-hjrj
  - Advisory: GHSA-vmqv-hx8q-j7mg
  - Advisory: GHSA-vv43-5jgx-7qv8
  - Advisory: GHSA-x8rc-wpg4-grpf
  - Advisory: GHSA-xj5x-m3f3-5x3h
  - Advisory: GHSA-xwr5-m59h-vwqr
  - Description: The Electron version in use is affected by published security advisories that are fixed in newer releases (46: GHSA-3c8v-cfp5-9885, GHSA-3p22-ghq8-v749, GHSA-4f78-qhmw-8j8m, GHSA-4p4r-m79c-wq3v, GHSA-532v-xpq5-8h95, ...)
- **UNSUPPORTED_VERSION_GLOBAL_CHECK** at `package.json`
  - Validation: not run; static or artifact observation only
  - Description: The Electron version in use is no longer supported and does not receive security fixes: Electron 11 (supported: 44, 43, 42)
- **CHROMIUM_ADVISORIES** at `Chromium 87.0.4280.141`
  - Validation: not run; static or artifact observation only
  - Description: The Chromium 87.0.4280.141 in this Electron version misses 4280 upstream security fixes (400 critical, 2013 high), 51 of them for vulnerabilities exploited in the wild (CISA KEV: CVE-2025-10585, CVE-2021-30633, CVE-2021-37973, CVE-2022-3075, CVE-2022-4135); 40 backported fixes are already subtracted. Upgrade Electron.

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 2 instances by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Open the components workbook and fix the links in its "Links to validate manually" column. How: [Check the components workbook](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-components-workbook).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
