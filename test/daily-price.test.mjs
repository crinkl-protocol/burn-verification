import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import {
  hashGmvDailyPriceAggregationPolicyV1, hashGmvRewardDayPriceDutyV1,
  hashGmvPriceAggregateV1, verifyGmvDailyPriceV1, verifyGmvDailyPriceCommitteeSelectionEvidenceV1,
  GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1
} from "../dist/index.js";
import { canonicalize } from "../dist/canonical.js";

const hash = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const domainHash = (domain, value) => hash(`${domain}\0${canonicalize(value)}`);
const fixture = JSON.parse(Buffer.from(readFileSync(new URL("../fixtures/real-sealing-transport-gmv-price.json.b64", import.meta.url), "utf8"), "base64"));
const keypairs = ["validator-a", "validator-b", "validator-c", "validator-d", "validator-e"].map((id) => ({
  id, ...generateKeyPairSync("ed25519")
}));

function inputForDailyPrice() {
  const policy = {
    aggregationPolicyHash: hash("placeholder"), minimumSamplesPerContributor: 4,
    maximumPublicationDelaySeconds: 300, minimumPoolTvlMicroUsd: "1000000", toleranceBps: 100,
    dailyWindowStartOffsetSeconds: -3600, dailyWindowEndOffsetSeconds: 0
  };
  policy.aggregationPolicyHash = hashGmvDailyPriceAggregationPolicyV1(policy);
  const duty = {
    domain: "crinkl:gmv:reward-day-price-duty:v1", schemaVersion: 1, protocolVersion: "1.0.0-rc.1",
    networkId: fixture.priceAggregate.networkId, rewardWindowDay: Date.parse("2026-10-09T00:00:00.000Z") / 86400000,
    sourceProfileHash: fixture.priceAggregate.source.sourceProfileHash,
    aggregationPolicyHash: policy.aggregationPolicyHash,
    windowStart: "2026-10-08T23:00:00.000Z", windowEndExclusive: "2026-10-09T00:00:00.000Z"
  };
  const dutyHash = hashGmvRewardDayPriceDutyV1(duty);
  const signedAtUnixMs = Date.parse("2026-10-09T00:00:30.000Z");
  const registrySnapshot = { networkId: duty.networkId, registrySequence: 1,
    validators: keypairs.map((key) => ({ validatorId: key.id, status: "active", activatedAtUnixMs: 0,
      signingKeys: [{ signingKeyId: "key-1", status: "active", publicKeyPem: key.publicKey.export({ format: "pem", type: "spki" }).toString() }] })) };
  const registryHash = hash(canonicalize(registrySnapshot));
  const boundary = { pointsLedgerMutation: false, selectionWeightMutation: false, claimable: false,
    productionPayoutAuthority: false, stakingAuthority: false, slashingAuthority: false,
    productionGovernanceAuthority: false, productionChainState: false, devnetOnly: true };
  const workerStatusEnvelopes = keypairs.map((key) => {
    const status = { version: "CrinklGmvSelectedValidatorWorkerStatusV1", networkId: duty.networkId,
      validatorId: key.id, updatedAtUnixMs: signedAtUnixMs, capabilities: [...GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1,
        "gmv_price_aggregate_request_v2", "gmv_price_committee_selection_evidence_v2", "gmv_price_aggregate_request_v3"], ...boundary };
    const resultHash = hash(canonicalize(status));
    const unsigned = { version: "ValidatorSignatureV1", domain: "crinkl.validator.signature.v1", validatorId: key.id,
      signingKeyId: "key-1", proofId: `gmv-selected-validator-worker-status:${key.id}:${Math.floor(signedAtUnixMs / 60000)}`,
      statementType: "QUALIFIED_GMV_BURN_EPOCH_V1", assignmentId: "gmv_selected_validator_worker_status_v1",
      policyHash: registryHash, registrySnapshotHash: registryHash, resultHash, signedAtUnixMs };
    const validatorSignature = { ...unsigned, signature: `ed25519:${sign(null,
      Buffer.from(canonicalize({ ...unsigned, version: "ValidatorSignaturePreimageV1" })), key.privateKey).toString("base64")}` };
    const envelope = { version: "CrinklGmvSelectedValidatorWorkerStatusEnvelopeV1", networkId: duty.networkId,
      validatorId: key.id, status, resultHash, validatorSignature, ...boundary };
    return { validatorId: key.id, envelopeHash: hash(canonicalize(envelope)), envelope };
  });
  const committeeSelectionEvidence = { version: "GmvDailyPriceCommitteeSelectionEvidenceV1", networkId: duty.networkId,
    priceDutyHash: dutyHash, selectedAtUnixMs: signedAtUnixMs, registrySequence: 1, registryHash,
    requiredCapabilities: [...GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1], capabilityMaxAgeSeconds: 1800, minimumCommitteeSize: 5,
    eligibleValidatorIds: keypairs.map((key) => key.id), selectedValidatorIds: keypairs.map((key) => key.id),
    requiredSignatures: 4, exclusions: [], workerStatusEnvelopes };
  const selectionHash = hash(canonicalize(committeeSelectionEvidence));
  const assignment = { assignmentId: `gmv-price-day:${dutyHash.slice(7)}:${selectionHash.slice(7)}`,
    assignmentHash: hash("authority-authenticated historical assignment"), selectedValidatorIds: keypairs.map((key) => key.id), signedAtUnixMs };
  const registry = { registrySequence: 1, registryHash,
    keys: keypairs.map((key) => ({ validatorId: key.id, keyId: "key-1", active: true,
      publicKey: key.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") })) };
  const reports = keypairs.slice(0, 4).map((key, index) => {
    const unsigned = {
      version: "GmvPriceCommitteeObservationReportV1", domain: "crinkl:gmv:price-observation-report:v1", schemaVersion: 1,
      networkId: duty.networkId, validatorId: key.id, keyId: "key-1", sourceProfileHash: duty.sourceProfileHash,
      aggregationPolicyHash: duty.aggregationPolicyHash, assignmentId: assignment.assignmentId, assignmentHash: assignment.assignmentHash,
      windowStart: duty.windowStart, windowEndExclusive: duty.windowEndExclusive,
      firstObservedAt: "2026-10-08T23:00:01.000Z", lastObservedAt: "2026-10-08T23:59:59.000Z",
      firstFinalizedSlot: 100, lastFinalizedSlot: 200, validSampleCount: 4,
      observedTwapMicroUsd: 100000 + index, latestEntryHash: hash(`entry-${index}`)
    };
    const reportHash = domainHash("CRINKL_GMV_PRICE_OBSERVATION_REPORT_V1", unsigned);
    return { ...unsigned, reportHash, signatureAlgorithm: "Ed25519",
      signedDigestRule: "SIGN_RAW_32_BYTE_PRICE_OBSERVATION_REPORT_HASH", publicKey: registry.keys[index].publicKey,
      signature: sign(null, Buffer.from(reportHash.slice(7), "hex"), key.privateKey).toString("base64") };
  });
  const observationSet = { domain: "crinkl:gmv:price-observation-set:v1", schemaVersion: 1,
    networkId: duty.networkId, sourceProfileHash: duty.sourceProfileHash, aggregationPolicyHash: duty.aggregationPolicyHash,
    assignmentId: assignment.assignmentId, assignmentHash: assignment.assignmentHash,
    windowStart: duty.windowStart, windowEndExclusive: duty.windowEndExclusive, reports };
  const aggregate = structuredClone(fixture.priceAggregate);
  aggregate.networkId = duty.networkId;
  aggregate.window = { windowStart: duty.windowStart, windowEndExclusive: duty.windowEndExclusive,
    firstObservedAt: reports[0].firstObservedAt, lastObservedAt: reports[0].lastObservedAt,
    firstFinalizedSlot: 100, lastFinalizedSlot: 200, chainCommitment: "finalized" };
  aggregate.sampleCommitment = { observationSet: { artifactType: "GmvPriceObservationSetV1", artifactVersion: "1",
    contentHash: hash(canonicalize(observationSet)), byteLength: Buffer.byteLength(canonicalize(observationSet)) },
    sampleSetRoot: domainHash("CRINKL_GMV_PRICE_OBSERVATION_SET_ROOT_V1", reports.map((report) => report.reportHash)),
    sampleSetRootRule: "GMV_PRICE_SAMPLE_SET_ROOT_V1", validSampleCount: 16, contributingValidatorCount: 4 };
  const { dailyWindowStartOffsetSeconds: _s, dailyWindowEndOffsetSeconds: _e, ...aggregationPolicy } = policy;
  aggregate.aggregation = { rule: "MEDIAN_OF_SIGNED_VALIDATOR_TWAP_V1", ...aggregationPolicy, priceMicroUsdPerToken: 100001 };
  const { signedAtUnixMs: _a, ...assignmentFields } = assignment;
  aggregate.committee = { registrySequence: 1, registryHash: registry.registryHash, ...assignmentFields,
    quorumRule: "bft_strict_supermajority_v1", requiredSignatures: 4 };
  aggregate.publishedAt = "2026-10-09T00:01:00.000Z";
  resign(aggregate);
  return { priceDuty: duty, aggregate, observationSet, committeeSelectionEvidenceHash: selectionHash,
    committeeSelectionEvidence, authenticatedCommittee: { registry, registrySnapshot, assignment }, expected: {
      networkId: duty.networkId, rewardWindowDay: duty.rewardWindowDay, sourceProfileHash: duty.sourceProfileHash, policy },
    expectedPriceMicroUsdPerToken: 100001 };
}
function resign(aggregate) {
  aggregate.aggregateHash = hashGmvPriceAggregateV1(aggregate);
  aggregate.signatures = keypairs.slice(0, 4).map((key) => ({ validatorId: key.id,
    signerRole: "PRICE_AGGREGATE_SIGNER", keyId: "key-1",
    publicKey: key.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
    signatureAlgorithm: "Ed25519", signedDigestRule: "SIGN_RAW_32_BYTE_AGGREGATE_HASH",
    signature: sign(null, Buffer.from(aggregate.aggregateHash.slice(7), "hex"), key.privateKey).toString("base64") }));
}
test("daily price verifies signed committee evidence and independent observation bytes", () => {
  const input = inputForDailyPrice(), verified = verifyGmvDailyPriceV1(input);
  assert.equal(verified.priceDutyHash, hashGmvRewardDayPriceDutyV1(input.priceDuty));
  assert.equal(verified.aggregate.aggregation.priceMicroUsdPerToken, 100001);
  assert.equal(verified.validDistinctSignatureCount, 4);
});
for (const delta of [-1, 1]) test(`daily consumption rejects a ${delta} micro-USD difference`, () => {
  const input = inputForDailyPrice(); input.expectedPriceMicroUsdPerToken += delta;
  assert.throws(() => verifyGmvDailyPriceV1(input), /PRICE_VALUE_MISMATCH/);
});
const mutations = [
  ["wrong independently expected day", (i) => { i.expected.rewardWindowDay++; }, "DUTY_BINDING_MISMATCH"],
  ["wrong expected network", (i) => { i.expected.networkId = "other-network"; }, "DUTY_BINDING_MISMATCH"],
  ["wrong expected source", (i) => { i.expected.sourceProfileHash = hash("other-source"); }, "DUTY_BINDING_MISMATCH"],
  ["tampered policy timing", (i) => { i.expected.policy.dailyWindowStartOffsetSeconds++; }, "POLICY_HASH_MISMATCH"],
  ["wrong authenticated policy", (i) => { i.expected.policy.minimumPoolTvlMicroUsd = "2000000";
    i.expected.policy.aggregationPolicyHash = hashGmvDailyPriceAggregationPolicyV1(i.expected.policy); }, "DUTY_BINDING_MISMATCH"],
  ["changed duty window", (i) => { i.priceDuty.windowStart = "2026-10-08T23:00:01.000Z"; }, "DUTY_WINDOW_MISMATCH"],
  ["legacy statement-bound assignment", (i) => { i.authenticatedCommittee.assignment.assignmentId = "gmv-price:legacy"; }, "ASSIGNMENT_DUTY_MISMATCH"],
  ["same day replacement selection", (i) => { i.committeeSelectionEvidenceHash = hash("replacement-selection"); }, "SELECTION_EVIDENCE_INVALID"],
  ["same day replacement aggregate assignment", (i) => { i.aggregate.committee.assignmentHash = hash("replacement-assignment"); resign(i.aggregate); }, "AGGREGATE_DUTY_MISMATCH"],
  ["duplicate active registry key", (i) => { i.authenticatedCommittee.registry.keys[1].publicKey = i.authenticatedCommittee.registry.keys[0].publicKey; }, "DUPLICATE_SIGNING_KEY"],
  ["insufficient aggregate signatures", (i) => { i.aggregate.signatures.pop(); }, "SIGNATURE_QUORUM_UNSATISFIED"],
  ["invalid aggregate signature", (i) => { i.aggregate.signatures[0].signature = Buffer.alloc(64).toString("base64"); }, "SIGNATURE_INVALID"],
  ["tampered observation report", (i) => { i.observationSet.reports[0].observedTwapMicroUsd++; }, "OBSERVATION_SIGNATURE_INVALID"],
  ["tampered aggregate median signed by quorum", (i) => { i.aggregate.aggregation.priceMicroUsdPerToken++; resign(i.aggregate); }, "OBSERVATION_SET_COMMITMENT_MISMATCH"],
  ["tampered aggregate slot bounds signed by quorum", (i) => { i.aggregate.window.lastFinalizedSlot++; resign(i.aggregate); }, "OBSERVATION_SET_COMMITMENT_MISMATCH"],
  ["publication outside authenticated delay", (i) => { i.aggregate.publishedAt = "2026-10-09T00:05:01.000Z"; resign(i.aggregate); }, "PUBLICATION_WINDOW_INVALID"],
  ["unexpected duty field", (i) => { i.priceDuty.price = 100001; }, "SCHEMA_INVALID"],
  ["missing authenticated context", (i) => { delete i.authenticatedCommittee; }, "SCHEMA_INVALID"],
  ["missing observation bytes", (i) => { delete i.observationSet; }, "SCHEMA_INVALID"],
  ["copied self-declared sample root", (i) => { i.observationSet = { sampleSetRoot: i.aggregate.sampleCommitment.sampleSetRoot }; }, "OBSERVATION_SET_INVALID"]
];
for (const [name, mutate, reason] of mutations) test(`daily verifier rejects ${name}`, () => {
  const input = inputForDailyPrice(); mutate(input);
  assert.throws(() => verifyGmvDailyPriceV1(input), new RegExp(reason));
});
for (const malformed of [null, {}, [], "day", -1]) test(`daily verifier rejects malformed duty ${JSON.stringify(malformed)}`, () => {
  const input = inputForDailyPrice(); input.priceDuty = malformed;
  assert.throws(() => verifyGmvDailyPriceV1(input), /SCHEMA_INVALID/);
});

function selectionInput(input) {
  return { evidence: input.committeeSelectionEvidence, evidenceHash: input.committeeSelectionEvidenceHash,
    priceDutyHash: hashGmvRewardDayPriceDutyV1(input.priceDuty),
    authenticatedRegistrySnapshot: input.authenticatedCommittee.registrySnapshot,
    authenticatedRegistry: input.authenticatedCommittee.registry,
    authenticatedAssignmentSignedAtUnixMs: input.authenticatedCommittee.assignment.signedAtUnixMs };
}
function rehashSelection(input) {
  input.committeeSelectionEvidenceHash = hash(canonicalize(input.committeeSelectionEvidence));
}
const selectionMutations = [
  ["mixed selected roster order", (i) => { i.committeeSelectionEvidence.selectedValidatorIds.reverse(); }, "SELECTION_EVIDENCE_MISMATCH"],
  ["missing worker evidence", (i) => { i.committeeSelectionEvidence.workerStatusEnvelopes.pop(); }, "SELECTION_QUORUM_UNAVAILABLE"],
  ["duplicated worker identity", (i) => { i.committeeSelectionEvidence.workerStatusEnvelopes[1] = i.committeeSelectionEvidence.workerStatusEnvelopes[0]; }, "SELECTION_EVIDENCE_INVALID"],
  ["forged worker signature", (i) => { const entry = i.committeeSelectionEvidence.workerStatusEnvelopes[0];
    entry.envelope.validatorSignature.signature = `ed25519:${Buffer.alloc(64).toString("base64")}`;
    entry.envelopeHash = hash(canonicalize(entry.envelope)); }, "SELECTION_QUORUM_UNAVAILABLE"],
  ["weakened required capabilities", (i) => { i.committeeSelectionEvidence.requiredCapabilities.pop(); }, "SELECTION_EVIDENCE_INVALID"],
  ["weakened committee floor", (i) => { i.committeeSelectionEvidence.minimumCommitteeSize = 1; }, "SELECTION_EVIDENCE_INVALID"],
  ["stale historical selection", (i) => { i.authenticatedCommittee.assignment.signedAtUnixMs += 1800001; }, "SELECTION_EVIDENCE_INVALID"],
  ["selection beyond allowed future skew", (i) => { i.committeeSelectionEvidence.selectedAtUnixMs += 60001; }, "SELECTION_EVIDENCE_INVALID"],
  ["replacement registry bytes", (i) => { i.authenticatedCommittee.registrySnapshot.networkId = "self-signed-replacement"; }, "SELECTION_EVIDENCE_INVALID"],
  ["changed duty hash", (i) => { i.committeeSelectionEvidence.priceDutyHash = hash("another-duty"); }, "SELECTION_EVIDENCE_INVALID"]
];
for (const [name, mutate, reason] of selectionMutations) test(`daily selection replay rejects ${name}`, () => {
  const input = inputForDailyPrice(); mutate(input); rehashSelection(input);
  assert.throws(() => verifyGmvDailyPriceCommitteeSelectionEvidenceV1(selectionInput(input)), new RegExp(reason));
});

// Reference source is supplied explicitly for extraction parity; package tests
// remain portable without a checkout of the validator implementation.
if (process.env.CRINKL_PRICE_SELECTION_REFERENCE) test("daily selection preserves validator V2 capable-pool replay semantics", async () => {
  const reference = await import(pathToFileURL(process.env.CRINKL_PRICE_SELECTION_REFERENCE).href);
  const input = inputForDailyPrice(), daily = verifyGmvDailyPriceCommitteeSelectionEvidenceV1(selectionInput(input));
  const evidence = input.committeeSelectionEvidence;
  const source = reference.resolveGmvPriceCommitteeSelectionV2({ registry: input.authenticatedCommittee.registrySnapshot,
    nowUnixMs: evidence.selectedAtUnixMs, capabilityMaxAgeSeconds: 1800,
    readWorkerStatusEnvelope: (id) => evidence.workerStatusEnvelopes.find((entry) => entry.validatorId === id).envelope });
  assert.deepEqual(daily.selectedValidatorIds, source.validatorIds);
  assert.equal(daily.requiredSignatures, source.requiredSignatures);
  assert.deepEqual(evidence.eligibleValidatorIds, source.eligibleValidatorIds);
  assert.deepEqual(evidence.exclusions, source.exclusions);
  assert.deepEqual(evidence.workerStatusEnvelopes, source.workerStatusEnvelopes);
  for (const entry of evidence.workerStatusEnvelopes) {
    const result = reference.verifyPriceCommitteeWorkerStatusEnvelopeV1({ envelope: entry.envelope,
      validatorId: entry.validatorId, registry: input.authenticatedCommittee.registrySnapshot,
      nowUnixMs: evidence.selectedAtUnixMs, capabilityMaxAgeSeconds: 1800 });
    assert.equal(result.ok, true);
  }
});
