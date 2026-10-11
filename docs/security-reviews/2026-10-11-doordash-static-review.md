# DoorDash Android APK review (static, incomplete)

**Assessment date:** 2026-10-11
**Artifact:** `com.dd.doordash` 15.277.2 (version code 15277029)
**APK SHA-256:** `33154ad5f0aabb771b6cfac41dac810d7626b9bcb1612e3e6323e1330f93388c`
**Scope:** The supplied APK only. No DoorDash API requests or runtime actions were performed.

## Outcome

No vulnerability was confirmed. One exported deep-link flow was followed as an investigation lead and the apparent client-side verification shortcut is gated by a server status check. Runtime behavior and backend authorization were not independently validated.

## Lead reviewed: student-verification callback

The manifest declares `PlanVerificationRedirectReceiverActivity` exported with `VIEW`/`BROWSABLE` filters for the `dd-dashpass` callback and the HTTPS DoorDash student-verification callback. Its `onCreate` forwards the incoming URI to the internal `PlanVerificationActivity`. That screen parses the `result_code` query value; `SUCCESS` enters `SheerIDStudentVerificationDelegate.processExternalVerificationResult`, which polls `PlanManager` and returns a verified result only when the response status is `CONSUMER_VERIFIED`.

**Assessment:** Forging `result_code=SUCCESS` appears insufficient by itself to satisfy the verification flow. An external launch may cause navigation or a status poll, but security impact is unproven. This is not reported as a vulnerability.

Review locations in the decompilation:

- `apktool/AndroidManifest.xml:266-273`
- `apktool-smali/smali_classes14/com/doordash/consumer/ui/plan/student/PlanVerificationRedirectReceiverActivity.smali:48-74`
- `jadx/sources/com/doordash/consumer/ui/plan/student/PlanVerificationActivity.java:293-315`
- `jadx/sources/com/doordash/consumer/ui/plan/student/c.java:64-95`
- `jadx/sources/com/doordash/consumer/ui/plan/planv2/verification/d.java:80-110`

These paths refer to the local, ignored analysis workspace; the APK and decompilation output are intentionally not committed.

## Coverage and limitations

- Artifact: 204,231,485 bytes; target SDK 35; min SDK 26.
- Apktool 3.0.1 decoded the manifest/resources and baksmali output for 15 DEX files.
- JADX 1.5.6 stopped at approximately 93% (66,750/71,062 classes) with decompilation/type-inference failures. Decompiled output is incomplete and lossy.
- Deep-link inventory is partial (56 filters; 555 reported combinations; truncated); domain verification and runtime resolution were not tested.
- Mobile_Ag's 128 MiB upload limit rejected this 204 MB APK; that limit was not bypassed. The focused analyzer's Tree-sitter backend segfaulted and used lexical fallback, so zero focused analyzer candidates is not evidence of absence.
- No connected devices were present during the initial check. A later inventory showed `127.0.0.1:6562`, an Android 9 x86 `userdebug/test-keys` root device. The APK was not installed or launched. This environment would not establish ordinary-app exploitability on a current unrooted device.

## Evidence retention

The full local review record is `output/doordash-static-2026-10-11/static-review.json` (ignored by Git). Its SHA-256 after the follow-up review is `9fab2dd7989de5473d9128836298adf8b47bcac6c11c9a4801babb75d5b2c1ca`. The original APK remains at `uploads/doordash.apk` and is also excluded from Git.
