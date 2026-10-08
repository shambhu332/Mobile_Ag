# MobileAg light console update

## Interface

A Djini-inspired light dashboard based on its public September 2026 screenshots, not an authenticated-dashboard clone. MobileAg retains its own branding and is not affiliated with Djini.

- Default Security Overview: APK/IPA upload, selected-job activity, candidate severity cards, scan identity, and workflow links.
- Consistent white surfaces, pale navigation, blue actions, forms and evidence panes across all eleven views.
- Responsive desktop/mobile layouts and keyboard navigation.
- APK upload opens scope review; IPA opens advanced static settings. Upload alone never starts testing or selects a device.
- Counts come from the selected scan. Missing data is unknown, not a security verdict.
- Local assets only; existing authorization and execution controls unchanged.

## Validation of the publication tree

The release was assembled from `fa9d443` plus the scoped UI/onboarding changes, separately from unrelated unfinished local security work. Those unrelated changes are not included in this publication.

- Full Python suite: **304 passed** (14,740 warnings, 80.17s); local JavaScript syntax, asset verification and wheel packaging passed.
- Console browser suite: 11 views at desktop and 320px, no overflow, no page exceptions, no external requests, zero automated axe violations in tested WCAG A/AA states. Synthetic upload verified to stage only.
- Existing product browser suite passed its authentication, CSP, keyboard, consent, provider-fallback and workflow checks.
- Browser evidence is preserved in `validation/`. Screenshots use synthetic data only. Chromium 155.0.8059.12; Python 3.14.7.
- No real device or paid model was exercised. Automated accessibility checks do not replace manual assistive-technology testing.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for portable setup, both browser commands and CI checks. GitHub Actions checks the pushed revision independently.

## Public visual references

- https://djini.ai/wp-content/uploads/2026/09/06-source-scan-entry.png
- https://djini.ai/wp-content/uploads/2026/09/07-scan-dialog.png
- https://djini.ai/wp-content/uploads/2026/09/09-results.png

No Djini assets or branding are loaded by the application.
