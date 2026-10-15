# Pinned SBOM validation schemas

These fixtures preserve the upstream schema inputs and JSON references used by
the SBOM regression suite. Tests verify SHA-256 before use and validate offline;
CI does not fetch schema documents from mutable remote content.

| File | Upstream source | SHA-256 | License / attribution |
|---|---|---|---|
| `cyclonedx-1.5/bom-1.5.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json` | `2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480` | CycloneDX, Apache License 2.0 (schema comment) |
| `cyclonedx-1.5/spdx.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json` | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` | CycloneDX schema suite, Apache License 2.0 |
| `cyclonedx-1.5/jsf-0.82.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` | JSF comment attributes Apache License 2.0; upstream author attribution retained |
| `cyclonedx-1.5/bom-1.5.xsd` | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.xsd` | `0b1678d5ae893bd1736843f3c050a26910de9a8107acb337f628900728de6a53` | CycloneDX, Apache License 2.0 (upstream header) |
| `cyclonedx-1.5/spdx.xsd` | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.xsd` | `cce0672755fac029279801a0244112345e493ec6e6e1b91f496c286753c11ef4` | CycloneDX SPDX extension schema, Apache License 2.0 (upstream source) |
| `spdx-2.3.schema.json` | `https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json` | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` | SPDX specification attribution; Creative Commons Attribution 3.0 Unported, https://creativecommons.org/licenses/by/3.0/ |

CycloneDX schemas were retrieved on 2026-10-15 from upstream `master` paths
and are content-pinned by the hashes above; SPDX JSON Schema is from immutable
`v2.3`. The CycloneDX XSD imports SPDX by an HTTP URL; the test resolver maps
only that exact import to the pinned local `spdx.xsd`, with network access
disabled. These fixtures are test inputs, not MobileAg runtime data. Updating
them requires reviewing upstream version, license and hashes together.
