/** Daily price evidence binds an authority-authenticated committee to one reward day. */
import { createPublicKey } from "node:crypto";
import {
  asRecord, assertExactKeys, asNonNegativeInteger, asPositiveInteger,
  asSha256Digest, asString, canonicalize, hashCanonicalValue, sha256Hex,
  type CanonicalValue
} from "./canonical.js";
import {
  gmvPriceAggregateArtifactContentV1, verifyGmvPriceAggregateV1,
  verifyRawEd25519PriceSignatureV1,
  type GmvPriceAggregateRegistryViewV1, type VerifiedGmvPriceAggregateV1
} from "./priceAggregateV1.js";

export interface GmvDailyPriceAggregationPolicyV1 {
  readonly aggregationPolicyHash: string;
  readonly minimumSamplesPerContributor: number;
  readonly maximumPublicationDelaySeconds: number;
  readonly minimumPoolTvlMicroUsd: string;
  /** Formation policy only; the daily price must be consumed exactly. */
  readonly toleranceBps: number;
  readonly dailyWindowStartOffsetSeconds: number;
  readonly dailyWindowEndOffsetSeconds: number;
}
export interface GmvRewardDayPriceDutyV1 {
  readonly domain: "crinkl:gmv:reward-day-price-duty:v1";
  readonly schemaVersion: 1;
  readonly protocolVersion: "1.0.0-rc.1";
  readonly networkId: string;
  readonly rewardWindowDay: number;
  readonly sourceProfileHash: string;
  readonly aggregationPolicyHash: string;
  readonly windowStart: string;
  readonly windowEndExclusive: string;
}

export interface VerifyGmvDailyPriceInputV1 {
  readonly priceDuty: unknown;
  readonly aggregate: unknown;
  /** Independently fetched observation-set bytes, never the candidate's claimed root. */
  readonly observationSet: unknown;
  readonly committeeSelectionEvidenceHash: string;
  readonly committeeSelectionEvidence: unknown;
  /**
   * Outputs of pinned-authority authentication of the historical registry,
   * assignment and daily selection evidence. This pure verifier does not
   * authenticate the network root. Wrappers must authenticate these before
   * calling, using their own authority pin, not an incoming artifact's key.
   */
  readonly authenticatedCommittee: {
    readonly registry: GmvPriceAggregateRegistryViewV1;
    readonly registrySnapshot: unknown;
    readonly assignment: {
      readonly assignmentId: string;
      readonly assignmentHash: string;
      readonly selectedValidatorIds: readonly string[];
      readonly signedAtUnixMs: number;
    };
  };
  /** Independently authenticated active profile/policy, never derived from priceDuty. */
  readonly expected: {
    readonly networkId: string;
    readonly rewardWindowDay: number;
    readonly sourceProfileHash: string;
    readonly policy: GmvDailyPriceAggregationPolicyV1;
  };
  readonly expectedPriceMicroUsdPerToken?: number;
}
export interface VerifiedGmvDailyPriceV1 extends VerifiedGmvPriceAggregateV1 {
  readonly priceDuty: GmvRewardDayPriceDutyV1;
  readonly priceDutyHash: string;
  readonly committeeSelectionEvidenceHash: string;
}
export class GmvDailyPriceErrorV1 extends Error {
  readonly code = "GMV_DAILY_PRICE_INVALID";
  constructor(readonly reason: string) {
    super(`GMV_DAILY_PRICE_INVALID:${reason}`);
    this.name = "GmvDailyPriceErrorV1";
  }
}
function reject(reason: string): never { throw new GmvDailyPriceErrorV1(reason); }
function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const record = asRecord(value, "daily price evidence");
  assertExactKeys(record, fields, "daily price evidence");
  return record;
}
const digest = (domain: string, value: unknown): string =>
  `sha256:${sha256Hex(`${domain}\u0000${canonicalize(value as CanonicalValue)}`)}`;

export const GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1 = [
  "gmv_price_aggregate_v1", "gmv_daily_price_formation_request_v1"
] as const;
const canonicalHash = (value: unknown) => `sha256:${hashCanonicalValue(value as CanonicalValue)}`;
const codeUnitCompare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const statusFields = new Set([
  "version", "networkId", "validatorId", "softwareVersion", "sourceCommit", "status", "detail",
  "proofId", "resultHash", "publicHashes", "capabilities", "committeeExecutionProfiles", "failure",
  "diagnostic", "pointsLedgerMutation", "selectionWeightMutation", "claimable",
  "productionPayoutAuthority", "stakingAuthority", "slashingAuthority", "productionGovernanceAuthority",
  "productionChainState", "devnetOnly", "updatedAtUnixMs", "runDir", "pid",
  "consecutiveFailedTicks", "lastSuccessfulTickAtUnixMs", "lastTickFailureAtUnixMs"
]);
const envelopeFields = new Set(["version", "networkId", "validatorId", "status", "resultHash", "validatorSignature",
  "pointsLedgerMutation", "selectionWeightMutation", "claimable", "productionPayoutAuthority", "stakingAuthority",
  "slashingAuthority", "productionGovernanceAuthority", "productionChainState", "devnetOnly"]);
function boundaryInvalid(value: Record<string, unknown>): boolean {
  return ["pointsLedgerMutation", "selectionWeightMutation", "claimable", "productionPayoutAuthority",
    "stakingAuthority", "slashingAuthority", "productionGovernanceAuthority", "productionChainState"]
    .some((field) => value[field] === true) || value.devnetOnly !== true;
}
interface RegistryValidator {
  readonly validatorId: string; readonly status: string; readonly activatedAtUnixMs: number;
  readonly removedAtUnixMs?: number;
  readonly signingKeys: readonly { readonly signingKeyId: string; readonly status: string; readonly publicKeyPem: string }[];
}
function verifyDailyWorkerStatus(envelopeInput: unknown, validatorId: string, registry: Record<string, unknown>,
  registryHash: string, validators: readonly RegistryValidator[], selectedAt: number): string | undefined {
  try {
    const envelope = asRecord(envelopeInput, "worker envelope");
    if (Object.keys(envelope).some((field) => !envelopeFields.has(field)) ||
        envelope.version !== "CrinklGmvSelectedValidatorWorkerStatusEnvelopeV1" ||
        envelope.networkId !== registry.networkId || envelope.validatorId !== validatorId || boundaryInvalid(envelope)) throw new Error();
    const status = asRecord(envelope.status, "worker status");
    if (Object.keys(status).some((field) => !statusFields.has(field)) ||
        status.version !== "CrinklGmvSelectedValidatorWorkerStatusV1" || status.networkId !== registry.networkId ||
        status.validatorId !== validatorId || boundaryInvalid(status) || !Number.isSafeInteger(status.updatedAtUnixMs) ||
        !Array.isArray(status.capabilities) || status.capabilities.some((cap) => typeof cap !== "string")) throw new Error();
    const signature = asRecord(envelope.validatorSignature, "worker signature");
    const required = ["version", "domain", "validatorId", "signingKeyId", "proofId", "statementType", "assignmentId",
      "policyHash", "registrySnapshotHash", "resultHash", "signedAtUnixMs", "signature"];
    const optional = ["proofPackageHash", "decision", "publicArtifactHash"];
    if (required.some((field) => !Object.hasOwn(signature, field)) ||
        Object.keys(signature).some((field) => !required.includes(field) && !optional.includes(field)) ||
        signature.version !== "ValidatorSignatureV1" || signature.domain !== "crinkl.validator.signature.v1" ||
        !Number.isSafeInteger(signature.signedAtUnixMs) || typeof signature.signature !== "string") throw new Error();
    const signedAt = Number(signature.signedAtUnixMs), resultHash = canonicalHash(status);
    if (envelope.resultHash !== resultHash || signature.resultHash !== resultHash || signature.validatorId !== validatorId ||
        signature.proofId !== `gmv-selected-validator-worker-status:${validatorId}:${Math.floor(signedAt / 60000)}` ||
        signature.statementType !== "QUALIFIED_GMV_BURN_EPOCH_V1" ||
        signature.assignmentId !== "gmv_selected_validator_worker_status_v1" || signature.policyHash !== registryHash ||
        signature.registrySnapshotHash !== registryHash || signedAt !== status.updatedAtUnixMs || signedAt > selectedAt + 60000)
      throw new Error();
    if (selectedAt - signedAt > 1800000) return "status_stale";
    const validator = validators.find((entry) => entry.validatorId === validatorId);
    const key = validator?.signingKeys.find((entry) => entry.signingKeyId === signature.signingKeyId && entry.status === "active");
    if (validator?.status !== "active" || !Number.isSafeInteger(validator.activatedAtUnixMs) ||
        signedAt < validator.activatedAtUnixMs || (validator.removedAtUnixMs !== undefined && signedAt >= validator.removedAtUnixMs) ||
        key === undefined || !signature.signature.startsWith("ed25519:")) throw new Error();
    const { signature: _signature, ...preimage } = signature;
    const publicKey = Buffer.from(createPublicKey(key.publicKeyPem).export({ format: "der", type: "spki" })).subarray(-32).toString("base64");
    if (!verifyRawEd25519PriceSignatureV1(publicKey, signature.signature.slice(8),
        Buffer.from(canonicalize({ ...preimage, version: "ValidatorSignaturePreimageV1" } as CanonicalValue), "utf8"))) throw new Error();
    if (!GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1.every((cap) => (status.capabilities as unknown[]).includes(cap)))
      return "capability_not_advertised";
    return undefined;
  } catch { return "status_evidence_invalid"; }
}
/**
 * Worker-envelope checks, capable-pool selection and code-unit ordering are
 * extracted from crinkl-proof-validator 3542863ca3cb41103414202247c87523dc274e2d,
 * bin/lib/gmv-price-committee-selection.mjs V2. The daily identity binds its
 * own duty and capability family; the five-seat floor, 1800-second age,
 * 60-second skew and signed-status eligibility retain that source's rules.
 */
export function verifyGmvDailyPriceCommitteeSelectionEvidenceV1(input: {
  readonly evidence: unknown; readonly evidenceHash: string; readonly priceDutyHash: string;
  readonly authenticatedRegistrySnapshot: unknown; readonly authenticatedRegistry: GmvPriceAggregateRegistryViewV1;
  readonly authenticatedAssignmentSignedAtUnixMs: number;
}): { readonly evidenceHash: string; readonly selectedValidatorIds: readonly string[]; readonly requiredSignatures: number } {
  try {
    const evidence = exact(input.evidence, ["version", "networkId", "priceDutyHash", "selectedAtUnixMs", "registrySequence",
      "registryHash", "requiredCapabilities", "capabilityMaxAgeSeconds", "minimumCommitteeSize", "eligibleValidatorIds",
      "selectedValidatorIds", "requiredSignatures", "exclusions", "workerStatusEnvelopes"]);
    const registry = asRecord(input.authenticatedRegistrySnapshot, "authenticated registry snapshot");
    const registryHash = canonicalHash(registry);
    const selectedAt = asNonNegativeInteger(evidence.selectedAtUnixMs, "selectedAtUnixMs");
    const replayAt = asNonNegativeInteger(input.authenticatedAssignmentSignedAtUnixMs, "authenticated assignment time");
    if (registryHash !== input.authenticatedRegistry.registryHash || registry.registrySequence !== input.authenticatedRegistry.registrySequence ||
        evidence.version !== "GmvDailyPriceCommitteeSelectionEvidenceV1" || evidence.networkId !== registry.networkId ||
        evidence.priceDutyHash !== asSha256Digest(input.priceDutyHash, "priceDutyHash") ||
        evidence.registryHash !== registryHash || evidence.registrySequence !== registry.registrySequence ||
        canonicalize(evidence.requiredCapabilities as CanonicalValue) !== canonicalize(GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1) ||
        evidence.capabilityMaxAgeSeconds !== 1800 || evidence.minimumCommitteeSize !== 5 ||
        selectedAt > replayAt + 60000 || replayAt - selectedAt > 1800000 ||
        canonicalHash(evidence) !== asSha256Digest(input.evidenceHash, "selection evidence hash") ||
        Buffer.byteLength(canonicalize(evidence as CanonicalValue)) > 512 * 1024 || !Array.isArray(registry.validators) ||
        !Array.isArray(evidence.workerStatusEnvelopes) || evidence.workerStatusEnvelopes.length > registry.validators.length)
      reject("SELECTION_EVIDENCE_INVALID");
    const validators = registry.validators as RegistryValidator[];
    const eligible = validators.filter((entry) => entry && entry.status === "active" && typeof entry.validatorId === "string" &&
      entry.validatorId.length > 0 && Array.isArray(entry.signingKeys) && entry.signingKeys.some((key) => key && key.status === "active"))
      .map((entry) => entry.validatorId).sort(codeUnitCompare);
    if (new Set(eligible).size !== eligible.length) reject("SELECTION_EVIDENCE_INVALID");
    const envelopes = new Map<string, Record<string, unknown>>();
    for (const raw of evidence.workerStatusEnvelopes) {
      const entry = exact(raw, ["validatorId", "envelopeHash", "envelope"]);
      const id = asString(entry.validatorId, "envelope validatorId");
      if (!/^[a-zA-Z0-9._:-]+$/u.test(id) || envelopes.has(id) || entry.envelopeHash !== canonicalHash(entry.envelope))
        reject("SELECTION_EVIDENCE_INVALID");
      envelopes.set(id, entry);
    }
    const selected: string[] = [], exclusions: { validatorId: string; reason: string }[] = [];
    const replayedEnvelopes: Record<string, unknown>[] = [];
    for (const id of eligible) {
      const entry = envelopes.get(id);
      if (entry === undefined) { exclusions.push({ validatorId: id, reason: "no_status_evidence" }); continue; }
      replayedEnvelopes.push(entry);
      const reason = verifyDailyWorkerStatus(entry.envelope, id, registry, registryHash, validators, selectedAt);
      if (reason === undefined) selected.push(id); else exclusions.push({ validatorId: id, reason });
    }
    if (selected.length < 5) reject("SELECTION_QUORUM_UNAVAILABLE");
    const requiredSignatures = Math.floor(selected.length * 2 / 3) + 1;
    if (canonicalize(eligible) !== canonicalize(evidence.eligibleValidatorIds as CanonicalValue) ||
        canonicalize(selected) !== canonicalize(evidence.selectedValidatorIds as CanonicalValue) ||
        requiredSignatures !== evidence.requiredSignatures ||
        canonicalize(exclusions) !== canonicalize(evidence.exclusions as CanonicalValue) ||
        canonicalize(replayedEnvelopes as CanonicalValue) !== canonicalize(evidence.workerStatusEnvelopes as CanonicalValue))
      reject("SELECTION_EVIDENCE_MISMATCH");
    return { evidenceHash: input.evidenceHash, selectedValidatorIds: selected, requiredSignatures };
  } catch (error) {
    if (error instanceof GmvDailyPriceErrorV1) throw error;
    return reject("SELECTION_EVIDENCE_INVALID");
  }
}
function timestamp(value: unknown): string {
  const parsed = asString(value, "timestamp");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(parsed) ||
      !Number.isFinite(Date.parse(parsed)) || new Date(parsed).toISOString() !== parsed) reject("SCHEMA_INVALID");
  return parsed;
}
function offset(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) ||
      Math.abs(value) > 86400) reject("POLICY_INVALID");
  return value;
}
function policyPreimage(input: unknown) {
  const policy = exact(input, ["aggregationPolicyHash", "minimumSamplesPerContributor",
    "maximumPublicationDelaySeconds", "minimumPoolTvlMicroUsd", "toleranceBps",
    "dailyWindowStartOffsetSeconds", "dailyWindowEndOffsetSeconds"]);
  const start = offset(policy.dailyWindowStartOffsetSeconds);
  const end = offset(policy.dailyWindowEndOffsetSeconds);
  const tvl = asString(policy.minimumPoolTvlMicroUsd, "minimumPoolTvlMicroUsd");
  if (start >= end || !/^(0|[1-9][0-9]*)$/u.test(tvl)) reject("POLICY_INVALID");
  return {
    minimumSamplesPerContributor: asPositiveInteger(policy.minimumSamplesPerContributor, "minimumSamplesPerContributor"),
    maximumPublicationDelaySeconds: asPositiveInteger(policy.maximumPublicationDelaySeconds, "maximumPublicationDelaySeconds"),
    minimumPoolTvlMicroUsd: tvl,
    toleranceBps: asNonNegativeInteger(policy.toleranceBps, "toleranceBps"),
    dailyWindowStartOffsetSeconds: start, dailyWindowEndOffsetSeconds: end
  };
}
export function hashGmvDailyPriceAggregationPolicyV1(policy: GmvDailyPriceAggregationPolicyV1): string {
  return digest("CRINKL_GMV_DAILY_PRICE_AGGREGATION_POLICY_V1", policyPreimage(policy));
}
export function parseGmvRewardDayPriceDutyV1(input: unknown): GmvRewardDayPriceDutyV1 {
  try {
    const value = exact(input, ["domain", "schemaVersion", "protocolVersion", "networkId",
      "rewardWindowDay", "sourceProfileHash", "aggregationPolicyHash", "windowStart", "windowEndExclusive"]);
    if (value.domain !== "crinkl:gmv:reward-day-price-duty:v1" || value.schemaVersion !== 1 ||
        value.protocolVersion !== "1.0.0-rc.1") reject("SCHEMA_INVALID");
    const networkId = asString(value.networkId, "networkId");
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u.test(networkId)) reject("SCHEMA_INVALID");
    const windowStart = timestamp(value.windowStart);
    const windowEndExclusive = timestamp(value.windowEndExclusive);
    if (Date.parse(windowStart) >= Date.parse(windowEndExclusive)) reject("SCHEMA_INVALID");
    return { domain: "crinkl:gmv:reward-day-price-duty:v1", schemaVersion: 1,
      protocolVersion: "1.0.0-rc.1", networkId,
      rewardWindowDay: asNonNegativeInteger(value.rewardWindowDay, "rewardWindowDay"),
      sourceProfileHash: asSha256Digest(value.sourceProfileHash, "sourceProfileHash"),
      aggregationPolicyHash: asSha256Digest(value.aggregationPolicyHash, "aggregationPolicyHash"),
      windowStart, windowEndExclusive };
  } catch (error) {
    if (error instanceof GmvDailyPriceErrorV1) throw error;
    return reject("SCHEMA_INVALID");
  }
}
export function hashGmvRewardDayPriceDutyV1(input: unknown): string {
  return digest("CRINKL_GMV_REWARD_DAY_PRICE_DUTY_V1", parseGmvRewardDayPriceDutyV1(input));
}
function reproduceObservationSet(input: VerifyGmvDailyPriceInputV1, verified: VerifiedGmvPriceAggregateV1): void {
  const aggregate = verified.aggregate;
  const set = exact(input.observationSet, ["domain", "schemaVersion", "networkId", "sourceProfileHash",
    "aggregationPolicyHash", "assignmentId", "assignmentHash", "windowStart", "windowEndExclusive", "reports"]);
  if (set.domain !== "crinkl:gmv:price-observation-set:v1" || set.schemaVersion !== 1 ||
      !Array.isArray(set.reports) || set.reports.length > 1024) reject("OBSERVATION_SET_INVALID");
  for (const field of ["networkId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId",
    "assignmentHash", "windowStart", "windowEndExclusive"] as const) {
    const expected = field === "networkId" ? aggregate.networkId :
      field === "sourceProfileHash" ? aggregate.source.sourceProfileHash :
      field === "aggregationPolicyHash" ? aggregate.aggregation.aggregationPolicyHash :
      field === "assignmentId" ? aggregate.committee.assignmentId :
      field === "assignmentHash" ? aggregate.committee.assignmentHash : aggregate.window[field];
    if (set[field] !== expected) reject("OBSERVATION_SET_BINDING_MISMATCH");
  }
  const reports = set.reports.map((raw) => exact(raw, ["version", "domain", "schemaVersion", "networkId",
    "validatorId", "keyId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId", "assignmentHash",
    "windowStart", "windowEndExclusive", "firstObservedAt", "lastObservedAt", "firstFinalizedSlot",
    "lastFinalizedSlot", "validSampleCount", "observedTwapMicroUsd", "latestEntryHash", "reportHash",
    "signatureAlgorithm", "signedDigestRule", "publicKey", "signature"]));
  const reportHashes: string[] = [], prices: number[] = [];
  let sampleCount = 0;
  const firstObservations: string[] = [], lastObservations: string[] = [];
  const firstSlots: number[] = [], lastSlots: number[] = [];
  for (const [index, report] of reports.entries()) {
    const id = asString(report.validatorId, "validatorId");
    if (index > 0 && Buffer.compare(Buffer.from(String(reports[index - 1]!.validatorId)), Buffer.from(id)) >= 0)
      reject("OBSERVATION_SIGNERS_INVALID");
    if (!aggregate.committee.selectedValidatorIds.includes(id)) reject("OBSERVATION_SIGNERS_INVALID");
    if (report.version !== "GmvPriceCommitteeObservationReportV1" ||
        report.domain !== "crinkl:gmv:price-observation-report:v1" || report.schemaVersion !== 1 ||
        report.signatureAlgorithm !== "Ed25519" ||
        report.signedDigestRule !== "SIGN_RAW_32_BYTE_PRICE_OBSERVATION_REPORT_HASH") reject("OBSERVATION_REPORT_INVALID");
    for (const field of ["networkId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId",
      "assignmentHash", "windowStart", "windowEndExclusive"] as const)
      if (report[field] !== set[field]) reject("OBSERVATION_REPORT_BINDING_MISMATCH");
    const first = Date.parse(timestamp(report.firstObservedAt)), last = Date.parse(timestamp(report.lastObservedAt));
    if (!(Date.parse(aggregate.window.windowStart) <= first && first <= last && last < Date.parse(aggregate.window.windowEndExclusive)))
      reject("OBSERVATION_REPORT_INVALID");
    const firstSlot = asNonNegativeInteger(report.firstFinalizedSlot, "firstFinalizedSlot");
    const lastSlot = asNonNegativeInteger(report.lastFinalizedSlot, "lastFinalizedSlot");
    if (firstSlot > lastSlot) reject("OBSERVATION_REPORT_INVALID");
    firstObservations.push(String(report.firstObservedAt)); lastObservations.push(String(report.lastObservedAt));
    firstSlots.push(firstSlot); lastSlots.push(lastSlot);
    const count = asPositiveInteger(report.validSampleCount, "validSampleCount");
    if (count < aggregate.aggregation.minimumSamplesPerContributor) reject("OBSERVATION_REPORT_INVALID");
    sampleCount += count;
    prices.push(asPositiveInteger(report.observedTwapMicroUsd, "observedTwapMicroUsd"));
    asSha256Digest(report.latestEntryHash, "latestEntryHash");
    const { reportHash, signatureAlgorithm: _a, signedDigestRule: _r, publicKey, signature, ...unsigned } = report;
    const reproducedHash = digest("CRINKL_GMV_PRICE_OBSERVATION_REPORT_V1", unsigned);
    const key = input.authenticatedCommittee.registry.keys.find((entry) => entry.active &&
      entry.validatorId === id && entry.keyId === report.keyId);
    if (reportHash !== reproducedHash || key?.publicKey !== publicKey || typeof signature !== "string" ||
        !/^[A-Za-z0-9+/]{86}==$/u.test(signature) || Buffer.from(signature, "base64").toString("base64") !== signature ||
        !verifyRawEd25519PriceSignatureV1(String(publicKey), signature, Buffer.from(reproducedHash.slice(7), "hex")))
      reject("OBSERVATION_SIGNATURE_INVALID");
    reportHashes.push(reproducedHash);
  }
  const bytes = canonicalize(set as CanonicalValue);
  prices.sort((a, b) => a - b);
  if (reports.length < verified.requiredSignatures || reports.length !== aggregate.sampleCommitment.contributingValidatorCount ||
      !Number.isSafeInteger(sampleCount) || sampleCount !== aggregate.sampleCommitment.validSampleCount ||
      prices[Math.floor((prices.length - 1) / 2)] !== aggregate.aggregation.priceMicroUsdPerToken ||
      firstObservations.sort()[0] !== aggregate.window.firstObservedAt ||
      lastObservations.sort().at(-1) !== aggregate.window.lastObservedAt ||
      Math.min(...firstSlots) !== aggregate.window.firstFinalizedSlot ||
      Math.max(...lastSlots) !== aggregate.window.lastFinalizedSlot ||
      `sha256:${hashCanonicalValue(set as CanonicalValue)}` !== aggregate.sampleCommitment.observationSet.contentHash ||
      Buffer.byteLength(bytes) !== aggregate.sampleCommitment.observationSet.byteLength ||
      digest("CRINKL_GMV_PRICE_OBSERVATION_SET_ROOT_V1", reportHashes) !== aggregate.sampleCommitment.sampleSetRoot)
    reject("OBSERVATION_SET_COMMITMENT_MISMATCH");
}
export function verifyGmvDailyPriceV1(input: VerifyGmvDailyPriceInputV1): VerifiedGmvDailyPriceV1 {
  try {
    const duty = parseGmvRewardDayPriceDutyV1(input.priceDuty), expected = input.expected;
    const policy = policyPreimage(expected.policy);
    if (hashGmvDailyPriceAggregationPolicyV1(expected.policy) !== expected.policy.aggregationPolicyHash)
      reject("POLICY_HASH_MISMATCH");
    const day = asNonNegativeInteger(expected.rewardWindowDay, "expected.rewardWindowDay");
    const dayStart = day * 86400 * 1000;
    if (!Number.isSafeInteger(dayStart)) reject("DAY_INVALID");
    if (duty.rewardWindowDay !== day || duty.networkId !== expected.networkId ||
        duty.sourceProfileHash !== asSha256Digest(expected.sourceProfileHash, "expected.sourceProfileHash") ||
        duty.aggregationPolicyHash !== expected.policy.aggregationPolicyHash) reject("DUTY_BINDING_MISMATCH");
    if (Date.parse(duty.windowStart) !== dayStart + policy.dailyWindowStartOffsetSeconds * 1000 ||
        Date.parse(duty.windowEndExclusive) !== dayStart + policy.dailyWindowEndOffsetSeconds * 1000)
      reject("DUTY_WINDOW_MISMATCH");
    const dutyHash = hashGmvRewardDayPriceDutyV1(duty);
    const selectionHash = asSha256Digest(input.committeeSelectionEvidenceHash, "committeeSelectionEvidenceHash");
    const assignment = input.authenticatedCommittee.assignment;
    const selection = verifyGmvDailyPriceCommitteeSelectionEvidenceV1({ evidence: input.committeeSelectionEvidence,
      evidenceHash: selectionHash, priceDutyHash: dutyHash,
      authenticatedRegistrySnapshot: input.authenticatedCommittee.registrySnapshot,
      authenticatedRegistry: input.authenticatedCommittee.registry,
      authenticatedAssignmentSignedAtUnixMs: assignment.signedAtUnixMs });
    if (canonicalize(selection.selectedValidatorIds) !== canonicalize(assignment.selectedValidatorIds))
      reject("ASSIGNMENT_SELECTION_MISMATCH");
    if (assignment.assignmentId !== `gmv-price-day:${dutyHash.slice(7)}:${selectionHash.slice(7)}`)
      reject("ASSIGNMENT_DUTY_MISMATCH");
    asSha256Digest(assignment.assignmentHash, "authenticated assignmentHash");
    const set = asRecord(input.observationSet, "observationSet");
    if (!Array.isArray(set.reports)) reject("OBSERVATION_SET_INVALID");
    const sampleRoot = digest("CRINKL_GMV_PRICE_OBSERVATION_SET_ROOT_V1", set.reports.map((entry) =>
      asSha256Digest(asRecord(entry, "report").reportHash, "reportHash")));
    const artifact = gmvPriceAggregateArtifactContentV1(input.aggregate as never);
    const verified = verifyGmvPriceAggregateV1({ aggregate: input.aggregate,
      resolvedArtifactContentHash: artifact.contentHash, resolvedSampleSetRoot: sampleRoot,
      registry: input.authenticatedCommittee.registry });
    const aggregate = verified.aggregate;
    if (assignment.signedAtUnixMs > Date.parse(aggregate.publishedAt)) reject("ASSIGNMENT_TIME_MISMATCH");
    if (aggregate.networkId !== duty.networkId || aggregate.source.sourceProfileHash !== duty.sourceProfileHash ||
        aggregate.aggregation.aggregationPolicyHash !== duty.aggregationPolicyHash ||
        aggregate.window.windowStart !== duty.windowStart || aggregate.window.windowEndExclusive !== duty.windowEndExclusive ||
        aggregate.committee.assignmentId !== assignment.assignmentId || aggregate.committee.assignmentHash !== assignment.assignmentHash ||
        canonicalize(aggregate.committee.selectedValidatorIds) !== canonicalize(assignment.selectedValidatorIds))
      reject("AGGREGATE_DUTY_MISMATCH");
    for (const field of ["minimumSamplesPerContributor", "maximumPublicationDelaySeconds", "minimumPoolTvlMicroUsd", "toleranceBps"] as const)
      if (aggregate.aggregation[field] !== policy[field]) reject("AGGREGATE_POLICY_MISMATCH");
    reproduceObservationSet(input, verified);
    if (input.expectedPriceMicroUsdPerToken !== undefined &&
        asPositiveInteger(input.expectedPriceMicroUsdPerToken, "expectedPriceMicroUsdPerToken") !== aggregate.aggregation.priceMicroUsdPerToken)
      reject("PRICE_VALUE_MISMATCH");
    return { ...verified, priceDuty: duty, priceDutyHash: dutyHash, committeeSelectionEvidenceHash: selectionHash };
  } catch (error) {
    if (error instanceof GmvDailyPriceErrorV1 || (error instanceof Error && error.name === "GmvPriceAggregateErrorV1")) throw error;
    return reject("SCHEMA_INVALID");
  }
}
