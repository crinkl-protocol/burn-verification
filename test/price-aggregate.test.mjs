import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  GMV_PRICE_AGGREGATE_REASONS_V1,
  gmvPriceAggregateArtifactContentV1,
  gmvPriceAggregateForCandidateV4VerdictV1,
  gmvPriceAggregateVerdictV1,
  hashGmvPriceAggregateV1,
  verifyGmvPriceAggregateForCandidateV4,
  verifyGmvPriceAggregateV1
} from "../dist/index.js";

// Real production sealing-transport subset (public material only): the signed
// price aggregate, the signed validator registry snapshot, the signed committee
// assignment, and the network authority public key. This fixture pins the
// producer-side (validator) GmvPriceAggregateV1 semantics: the validator
// verifier MUST accept the aggregate exactly as it was sealed in production.
// The transport is stored
// base64-encoded so controlled devnet seat names inside the signed material
// stay off the plaintext release surface; decoding yields the exact signed
// bytes.
const fixturePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
  "real-sealing-transport-gmv-price.json.b64"
);
const fixture = JSON.parse(
  Buffer.from(readFileSync(fixturePath, "utf8"), "base64").toString("utf8")
);

function authenticatedRegistry() {
  const registry = fixture.priceAuthorityEvidence.registry;
  const committee = fixture.priceAggregate.committee;
  return {
    registrySequence: committee.registrySequence,
    registryHash: committee.registryHash,
    keys: registry.validators.flatMap((validator) =>
      validator.signingKeys.map((key) => {
        const der = createPublicKey(key.publicKeyPem).export({
          format: "der",
          type: "spki"
        });
        return {
          validatorId: validator.validatorId,
          keyId: key.signingKeyId,
          publicKey: Buffer.from(der).subarray(-32).toString("base64"),
          active: validator.status === "active" && key.status === "active"
        };
      })
    )
  };
}

test("real production sealing transport supplies the authenticated registry view boundary", () => {
  const registry = authenticatedRegistry();
  const committee = fixture.priceAggregate.committee;
  assert.equal(registry.registrySequence, committee.registrySequence);
  assert.equal(registry.registryHash, committee.registryHash);
  assert.ok(registry.keys.length >= committee.selectedValidatorIds.length);
});

test("validator verifier accepts the real production GmvPriceAggregateV1", () => {
  const aggregate = fixture.priceAggregate;
  // The stored aggregateHash must reproduce from the canonical unsigned bytes.
  assert.equal(hashGmvPriceAggregateV1(aggregate), aggregate.aggregateHash);

  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
  const verified = verifyGmvPriceAggregateV1({
    aggregate,
    resolvedArtifactContentHash: artifact.contentHash,
    resolvedSampleSetRoot: fixture.resolvedPriceSampleSetRoot,
    registry: authenticatedRegistry(),
    expectedCanonicalArtifactByteLength: artifact.byteLength
  });
  assert.equal(verified.aggregateHash, aggregate.aggregateHash);
  assert.equal(verified.requiredSignatures, aggregate.committee.requiredSignatures);
  assert.equal(verified.validDistinctSignatureCount, aggregate.signatures.length);
  assert.ok(verified.validDistinctSignatureCount >= verified.requiredSignatures);
});

test("validator verifier rejects one active public key under distinct signer identities", () => {
  const aggregate = structuredClone(fixture.priceAggregate);
  const first = aggregate.signatures[0];
  const second = aggregate.signatures[1];
  aggregate.signatures[1] = {
    ...second,
    publicKey: first.publicKey,
    signature: first.signature
  };
  const baseRegistry = authenticatedRegistry();
  const registry = {
    ...baseRegistry,
    keys: baseRegistry.keys.map((key) =>
      key.validatorId === second.validatorId && key.keyId === second.keyId
        ? { ...key, publicKey: first.publicKey }
        : key
    )
  };
  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);

  assert.throws(
    () =>
      verifyGmvPriceAggregateV1({
        aggregate,
        resolvedArtifactContentHash: artifact.contentHash,
        resolvedSampleSetRoot: fixture.resolvedPriceSampleSetRoot,
        registry,
        expectedCanonicalArtifactByteLength: artifact.byteLength
      }),
    /DUPLICATE_SIGNING_KEY/u
  );
});

// Sample-contributor bound. `contributingValidatorCount` names validators drawn
// from the selected committee, so it may equal the committee size and may not
// exceed it. The vectors below drive the bound from the real production
// transport: the sealed aggregate sits exactly on the accepting boundary, and
// every inflated variant is rejected by reason string, not merely rejected.

function verifyWithContributorCount(contributingValidatorCount, overrides = {}) {
  const aggregate = structuredClone(fixture.priceAggregate);
  aggregate.sampleCommitment.contributingValidatorCount = contributingValidatorCount;
  if (overrides.validSampleCount !== undefined) {
    aggregate.sampleCommitment.validSampleCount = overrides.validSampleCount;
  }
  if (overrides.publishedAt !== undefined) {
    aggregate.publishedAt = overrides.publishedAt;
  }
  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
  return gmvPriceAggregateVerdictV1({
    aggregate,
    resolvedArtifactContentHash: artifact.contentHash,
    resolvedSampleSetRoot:
      overrides.resolvedSampleSetRoot ?? fixture.resolvedPriceSampleSetRoot,
    registry: authenticatedRegistry(),
    expectedCanonicalArtifactByteLength: artifact.byteLength
  });
}

// A V4 price projection bound to the aggregate under test. Only price-bearing
// fields carry meaning here; the remaining candidate keys satisfy the exact-key
// projection parse.
function candidateForAggregate(aggregate, artifact) {
  const evidence = {
    aggregateArtifact: {
      artifactType: "GmvPriceAggregateV1",
      artifactVersion: "1",
      contentHash: artifact.contentHash,
      byteLength: artifact.byteLength
    },
    aggregateHash: aggregate.aggregateHash,
    sourceProfileHash: aggregate.source.sourceProfileHash,
    aggregationPolicyHash: aggregate.aggregation.aggregationPolicyHash,
    sampleSetRoot: aggregate.sampleCommitment.sampleSetRoot,
    registrySequence: aggregate.committee.registrySequence,
    registryHash: aggregate.committee.registryHash,
    assignmentId: aggregate.committee.assignmentId,
    assignmentHash: aggregate.committee.assignmentHash,
    windowStart: aggregate.window.windowStart,
    windowEndExclusive: aggregate.window.windowEndExclusive,
    publishedAt: aggregate.publishedAt,
    priceMicroUsdPerToken: aggregate.aggregation.priceMicroUsdPerToken
  };
  return {
    domain: "crinkl:gmv-day:seal-candidate:v4",
    schemaVersion: 4,
    protocolVersion: "1.0.0-rc.1",
    dayId: "gmv-day-price-bound-vector",
    identity: {
      networkId: aggregate.networkId,
      consumerProgramId: "consumer-program",
      poolStateId: "pool-state",
      utcDate: "2026-07-28"
    },
    window: {
      windowStart: "2026-07-27T22:12:07.000Z",
      windowEnd: aggregate.window.windowStart,
      epochWindowSeconds: 86400,
      sealCutoff: aggregate.window.windowEndExclusive,
      correctionHorizonSeconds: 3600
    },
    verifiedToken: {},
    witness: {},
    aggregate: {},
    artifacts: {},
    v3: {
      domain: "crinkl:gmv-day:seal-candidate:v3",
      epochCommitmentHash: aggregate.committee.registryHash,
      windowDay: "2026-07-28",
      gmvCents: 0,
      settledRevenueCents: 0,
      spendHeadSetRoot: aggregate.sampleCommitment.sampleSetRoot,
      ruleSetHash: aggregate.aggregation.aggregationPolicyHash,
      prevEpochHash: aggregate.committee.assignmentHash,
      expectedABeforeCents: 0,
      expectedBCurveBefore: 0,
      crinklElectingCount: 0,
      usdPerReceiptCents: 10,
      policyHash: aggregate.aggregation.aggregationPolicyHash,
      epochWindowSeconds: 86400,
      priceMicroUsdPerToken: aggregate.aggregation.priceMicroUsdPerToken,
      electionRoot: aggregate.sampleCommitment.sampleSetRoot
    },
    priceEvidence: evidence,
    policies: {},
    consumer: {},
    expectedPreState: {},
    artifactVersions: {
      verifiedGmvToken: "VerifiedGmvTokenV1/1",
      dayWitnessManifest: "GmvDayWitnessManifestV1/1",
      burnStatement: "GmvBurnStatementV1/1",
      epochCommitment: "GmvEpochCommitmentV1/1",
      gmvPriceAggregate: "GmvPriceAggregateV1/1",
      lifecycle: "GmvDayLifecycleV1/1"
    }
  };
}

function verifyCandidateWithContributorCount(contributingValidatorCount) {
  const aggregate = structuredClone(fixture.priceAggregate);
  aggregate.sampleCommitment.contributingValidatorCount = contributingValidatorCount;
  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
  return gmvPriceAggregateForCandidateV4VerdictV1({
    aggregate,
    candidate: candidateForAggregate(aggregate, artifact),
    resolvedArtifactContentHash: artifact.contentHash,
    resolvedSampleSetRoot: fixture.resolvedPriceSampleSetRoot,
    registry: authenticatedRegistry()
  });
}

test("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE is in the closed reason vocabulary", () => {
  assert.ok(
    GMV_PRICE_AGGREGATE_REASONS_V1.includes("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE")
  );
  // Order in the vocabulary is the normative check order: the bound sits
  // between the publication-window check and the sample-floor check.
  assert.equal(
    GMV_PRICE_AGGREGATE_REASONS_V1.indexOf("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE"),
    GMV_PRICE_AGGREGATE_REASONS_V1.indexOf("PUBLICATION_WINDOW_INVALID") + 1
  );
  assert.equal(
    GMV_PRICE_AGGREGATE_REASONS_V1.indexOf("SAMPLE_FLOOR_UNSATISFIED"),
    GMV_PRICE_AGGREGATE_REASONS_V1.indexOf("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE") + 1
  );
});

test("contributor count equal to committee size is accepted", () => {
  const aggregate = fixture.priceAggregate;
  // The real sealed aggregate sits exactly on the boundary, so the accepting
  // case below is production evidence and not a constructed one.
  assert.equal(
    aggregate.sampleCommitment.contributingValidatorCount,
    aggregate.committee.selectedValidatorIds.length
  );
  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
  const verified = verifyGmvPriceAggregateV1({
    aggregate,
    resolvedArtifactContentHash: artifact.contentHash,
    resolvedSampleSetRoot: fixture.resolvedPriceSampleSetRoot,
    registry: authenticatedRegistry(),
    expectedCanonicalArtifactByteLength: artifact.byteLength
  });
  assert.equal(verified.aggregateHash, aggregate.aggregateHash);
});

test("contributor count one above committee size is rejected", () => {
  const committeeSize = fixture.priceAggregate.committee.selectedValidatorIds.length;
  const verdict = verifyWithContributorCount(committeeSize + 1);
  assert.equal(verdict.accepted, false);
  assert.equal(verdict.failureCode, "GMV_PRICE_AGGREGATE_INVALID");
  assert.equal(verdict.failureReason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");
});

test("a large inflated contributor count is rejected", () => {
  const committeeSize = fixture.priceAggregate.committee.selectedValidatorIds.length;
  for (const inflated of [committeeSize * 10, 1024, Number.MAX_SAFE_INTEGER]) {
    const verdict = verifyWithContributorCount(inflated);
    assert.equal(verdict.accepted, false);
    assert.equal(verdict.failureReason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");
  }
});

test("the bound is non-strict at the committee size", () => {
  // Equality must fall through to later checks rather than trip the bound.
  // Breaking the sample-set root isolates that fall-through: the reported
  // reason is the later check, proving the comparison is strictly greater-than.
  const committeeSize = fixture.priceAggregate.committee.selectedValidatorIds.length;
  const verdict = verifyWithContributorCount(committeeSize, {
    resolvedSampleSetRoot: `sha256:${"11".repeat(32)}`
  });
  assert.equal(verdict.accepted, false);
  assert.equal(verdict.failureReason, "SAMPLE_ROOT_MISMATCH");
});

test("publication-window validation precedes the bound", () => {
  const aggregate = fixture.priceAggregate;
  const committeeSize = aggregate.committee.selectedValidatorIds.length;
  // A publication timestamp inside the observation window is earlier than
  // `windowEndExclusive`, so it violates the publication window while leaving
  // the observation bounds and the finalized-slot bounds intact.
  const publishedBeforeWindowEnd = aggregate.window.windowStart;

  // Publication window alone, contributor count within the bound.
  const publicationOnly = verifyWithContributorCount(committeeSize, {
    publishedAt: publishedBeforeWindowEnd
  });
  assert.equal(publicationOnly.accepted, false);
  assert.equal(publicationOnly.failureReason, "PUBLICATION_WINDOW_INVALID");

  // Contributor bound alone, publication window intact.
  const boundOnly = verifyWithContributorCount(committeeSize + 1);
  assert.equal(boundOnly.accepted, false);
  assert.equal(boundOnly.failureReason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");

  // Both violated at once: the publication window is reported because it is
  // checked first. This pins the bound below publication validation, so the
  // bound may not absorb a publication-window failure.
  const multiplyInvalid = verifyWithContributorCount(committeeSize + 1, {
    publishedAt: publishedBeforeWindowEnd
  });
  assert.equal(multiplyInvalid.accepted, false);
  assert.equal(multiplyInvalid.failureCode, "GMV_PRICE_AGGREGATE_INVALID");
  assert.equal(multiplyInvalid.failureReason, "PUBLICATION_WINDOW_INVALID");
});

test("the bound precedes the sample-floor and sample-root checks", () => {
  const committeeSize = fixture.priceAggregate.committee.selectedValidatorIds.length;
  // Sample floor alone, contributor count within the bound.
  const floorOnly = verifyWithContributorCount(committeeSize, { validSampleCount: 1 });
  assert.equal(floorOnly.accepted, false);
  assert.equal(floorOnly.failureReason, "SAMPLE_FLOOR_UNSATISFIED");

  // Sample root alone, contributor count within the bound.
  const rootOnly = verifyWithContributorCount(committeeSize, {
    resolvedSampleSetRoot: `sha256:${"22".repeat(32)}`
  });
  assert.equal(rootOnly.accepted, false);
  assert.equal(rootOnly.failureReason, "SAMPLE_ROOT_MISMATCH");

  // All three violated at once: the bound is reported because it is checked
  // first.
  const multiplyInvalid = verifyWithContributorCount(committeeSize + 1, {
    validSampleCount: 1,
    resolvedSampleSetRoot: `sha256:${"33".repeat(32)}`
  });
  assert.equal(multiplyInvalid.accepted, false);
  assert.equal(multiplyInvalid.failureReason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");
});

test("the candidate-V4 entry point carries the same bound", () => {
  const committeeSize = fixture.priceAggregate.committee.selectedValidatorIds.length;
  const accepted = verifyCandidateWithContributorCount(committeeSize);
  assert.equal(accepted.accepted, true);

  const rejected = verifyCandidateWithContributorCount(committeeSize + 1);
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.failureCode, "GMV_PRICE_AGGREGATE_INVALID");
  assert.equal(rejected.failureReason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");

  // The throwing candidate-V4 entry point surfaces the same reason.
  const aggregate = structuredClone(fixture.priceAggregate);
  aggregate.sampleCommitment.contributingValidatorCount = committeeSize + 1;
  const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
  assert.throws(
    () =>
      verifyGmvPriceAggregateForCandidateV4({
        aggregate,
        candidate: candidateForAggregate(aggregate, artifact),
        resolvedArtifactContentHash: artifact.contentHash,
        resolvedSampleSetRoot: fixture.resolvedPriceSampleSetRoot,
        registry: authenticatedRegistry()
      }),
    (error) =>
      error.name === "GmvPriceAggregateErrorV1" &&
      error.reason === "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE"
  );
});
