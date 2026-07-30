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

## Source authority

The verifier implements the adopted GMV price-evidence contract in
`crinkl-protocol`. Source provenance is
`crinkl-proof-validator@3c9baa47`, including the strict contributor-count bound
and its validation order.
Independent verifier for Crinkl GMV price aggregates and candidate bindings.
