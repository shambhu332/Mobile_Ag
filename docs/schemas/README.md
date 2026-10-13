# Vendored report schemas

- `mobileag/data/sarif-schema-2.1.0.json` is the OASIS SARIF 2.1.0 JSON Schema
  vendored for offline importer validation. Upstream source:
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>
- SHA-256: `ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25`.
- The SARIF schema uses JSON Schema draft-07 and only local `$ref` references.
  Import validation never fetches a schema or resolves external references at
  runtime. Keep this checksum test and update it only with a reviewed schema
  version/source change.
- `mobileag-report-v1.schema.json` describes MobileAg's report envelope; it is
  separate from the SARIF interchange schema.
- `android-app-bundle-inventory-v1.schema.json` defines the output of the local
  `inventory-aab` command. It is input accounting only: module manifests are
  counted, but protobuf manifest decoding, APK generation, device split
  selection and security analysis are not performed.
- `sast-evaluation-output-v5.schema.json` defines the local instance-evaluator
  output, including optional corpus-supplied unsupported-construct labels.
  Such labels do not measure all unsupported constructs in analyzer or APK
  inputs; the automatic coverage state remains explicitly not measured.
- `mobsf-import-v1.schema.json` defines MobileAg's separate output projection
  for a bounded subset of MobSF Android static JSON. It is not an official
  MobSF input schema and does not imply support for every MobSF version.

Full schema conformance does not make producer data trustworthy. The importer
still applies stricter size/run/result/resource limits, safe-path policy,
deduplication, secret redaction, and UNVERIFIED trust labels.
