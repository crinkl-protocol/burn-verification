# Crinkl Burn Verification

`@crnkl/burn-verification` is the independent verifier for
`GmvPriceAggregateV1` evidence and its `GmvDaySealCandidateV4` binding.

The package evaluates one aggregate against resolved evidence hashes and an
already-authenticated validator-registry view. It does not authenticate the
registry authority, select a committee, establish GMV finality, authorize
consumption, mutate points, or settle value.

## Install

Pin an audited Git commit:

```json
{
  "dependencies": {
    "@crnkl/burn-verification": "https://codeload.github.com/crinkl-protocol/crinkl-burn-verification/tar.gz/<commit>"
  }
}
```

## Verify

```bash
pnpm install --frozen-lockfile
pnpm verify
```

The production-shaped fixture contains public signed material only and pins the
five-contributor, five-selected-validator boundary.

The development-time cross-repository gate compares the package source with an
exact adopted-protocol ref and an exact public-specification ref:

```bash
pnpm verify:protocol-parity -- \
  --protocol-repo /path/to/crinkl-protocol \
  --protocol-ref origin/main \
  --spec-repo /path/to/crinkl-protocol-spec \
  --spec-ref origin/main
```

The gate reads Git objects from those repositories. It does not add either
repository as a package or runtime dependency.

## Source authority

The verifier implements the adopted GMV price-evidence contract in
`crinkl-protocol`. `protocol-provenance.json` pins the adopted protocol and the
draft public-specification revisions exercised by the parity gate. The verifier
implementation was extracted from `crinkl-proof-validator@3c9baa47`.
Independent verifier for Crinkl GMV price aggregates and candidate bindings.
