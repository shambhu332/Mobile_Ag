# Follow-up validation — 2026-10-05

This folder supersedes the earlier transformation evidence **only for the checks
recorded here**. Earlier artifacts remain intact. Package version stays 0.1.0;
identify builds using source and wheel hashes, not the version string alone.

## Implemented

- Split dashboard code into ordered local workflow scripts; shared workspace
  state remains explicit. Template/module-presence checks and installed-wheel
  checks cover their packaging. This is not a tenant isolation architecture.
- Preserve APKTool SDK/version metadata when it has been removed from decoded
  XML. Read only bounded, simple metadata scalars; never deserialize YAML objects.
- Apply target-SDK provider/cleartext defaults, preserving unknown values and
  inherited application permissions. Static provider defaults assume Android
  API 17+; older platform behavior is a separate validation boundary. See the
  [Android provider reference](https://developer.android.com/guide/topics/manifest/provider-element)
  and [application reference](https://developer.android.com/guide/topics/manifest/application-element).
- Generic exported-component exposure is now an INFO/UNVERIFIED review item,
  with no invented impact/CVSS. Public launcher exposure is not itself a bug.
- Device enumeration observes the current shell identity without `su` or root
  changes. Recognize virtual hardware; reject Android launch error output even
  when ADB exits zero. Cold launch wait remains bounded (15 seconds).
- Pytest collection is restricted to trusted `tests`, not uploaded/decompiled
  artifacts, build directories or dependency trees.
- CI gains installed-wheel and synthetic browser checks, including pinned local
  axe test tooling. Actual remote execution must be checked separately.

## Evidence boundaries

- `compiled-android.json`: actual APKTool 3.0.1 build + JADX 1.5.6/APKTool decode
  in production namespaces/cgroup, not mocked tool output. One permission-free
  compiled manifest/DEX fixture, version `1.0-synthetic`, target SDK35. Every
  candidate remains UNVERIFIED; launcher observation is informational.
- Static timing is a single-host smoke under substantial concurrent host load,
  not a production throughput measurement. Do not infer improvement from it.
- `browser-results.json`: synthetic SecretScanner candidate, eight fixture views,
  CSP/XSS negative control, exact clipboard, durable triage, responsive layout,
  keyboard connection focus/Tab/Enter and reduced-motion media preference.
  Automated axe results do not certify screen-reader/full-state accessibility.
- `genymotion-initial-timeout.json` and `genymotion-results.json`: selected Google
  Pixel UUID `b6581daf-86fa-4943-b977-007ac37eecca`, serial `127.0.0.1:6562`, Android9/API28,
  fingerprint `google/vbox86p/vbox86p:9/PI/771:userdebug/test-keys,p1`, existing root
  ADB shell. **Two bounded install commands timed out. Device acceptance failed.**
  First install subsequently appeared; its synthetic launcher was started with
  `Status: ok` (ThisTime11301ms, WaitTime13466ms), then uninstalled. The second
  harness handles post-timeout installation cleanup; a subsequent `pm path`
  confirmed no fixture remained. Emulator was returned to its original OFF
  state. No reset, root change, hooks, log clearing or unrelated-app inspection.
- `device-unsigned-fixture.apk` preserves the exact unsigned input used by device
  attempts; `synthetic.apk` is the later compiled static fixture. Per-attempt
  signed hashes are recorded. Ephemeral signing keys/passwords were destroyed
  with temporary directories; they are not published.
- `wheel-smoke.json`: installed outside source checkout; all 15 shipped scripts
  served, unauthenticated API denied. No device/cloud interaction.
- Both runtime and full-build npm audits now report zero advisories. A compatible
  lockfile update moves @parcel/watcher 2.5.1 to 2.6.0 and removes its
  micromatch/braces chain. Pinned runtime libraries are unchanged; the local
  asset rebuild and hash verification pass. Earlier warning snapshots are
  historical evidence, not current warnings. A clean audit is not exploit proof.

## Remaining acceptance / design work

Current unrooted-device validation, representative owned Android/iOS corpus,
human screen-reader/all-modal/error-state acceptance, realistic performance/soak
checks and CI success remain open until separately demonstrated. Backend router
extraction remains maintainability work. Remote multiuser hosting and credential
brokered cloud web scans remain unsupported, not UI-only fixes.

Reproduce using the opt-in scripts documented in the main README. Unit pytest
uses mocks for all device/provider operations; no `TESTING` authorization bypass
is present in production. Do not run device checks without exact explicit scope.
