## ARM64 Spec Tryout

This directory holds source-controlled artifacts derived from Arm's official A64 ISA XML bundle.

Current contents:

- `generated/a64_subset.json`: compact machine-readable summary for the current supported subset
- `generated/a64_subset.rs`: Rust table form of the same subset, including decode-match and field-extraction helpers

Generation:

```bash
make arm64-spec-gen
```

This uses the Rust `specgen/` CLI. The legacy Python generator remains available
for parity checks:

```bash
make arm64-spec-gen-py
```

By default the generator reads from:

```text
./tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03
```

You can override the source bundle path with:

```bash
make arm64-spec-gen ARM64_ISA_XML_DIR=/path/to/ISA_A64_xml_A_profile-2026-03
```

Notes:

- The checked-in artifacts are intentionally narrow and are not yet wired into the kernel translator.
- The intended next use is as generated decode/field tables for the future shared translation core.
- The current subset is biased toward the instruction families already used in the userspace harness.
