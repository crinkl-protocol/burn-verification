/**
 * Pure verifier for the private-protocol GmvPriceAggregateV1 object.
 *
 * Source: crinkl-protocol protocol/GMV_PRICE_EVIDENCE.md,
 * protocol/schemas/gmv_price_aggregate_v1.schema.json, and the
 * gmv.priceAggregateV1 conformance vector. Price evidence has no lifecycle,
 * proof-finality, consumption, points, or settlement authority.
 */
import { createHash, createPublicKey, verify as verifyCryptoSignature } from "node:crypto";
import { asNonNegativeInteger, asPositiveInteger, asRecord, asSha256Digest, assertExactKeys, asString, asStringLiteral, canonicalize } from "./canonical.js";
export const GMV_PRICE_AGGREGATE_DOMAIN_V1 = "crinkl:gmv:price-aggregate:v1";
export const GMV_PRICE_AGGREGATE_HASH_DOMAIN_V1 = "CRINKL_GMV_PRICE_AGGREGATE_V1";
export const GMV_PRICE_AGGREGATE_CAPABILITY_V1 = "GMV_PRICE_AGGREGATE_V1";
export const GMV_PRICE_AGGREGATE_SEMANTIC_CODES_V1 = [
    "GMV_PRICE_AGGREGATE_INVALID",
    "GMV_PRICE_AGGREGATE_BINDING_MISMATCH",
    "GMV_PRICE_VALUE_MISMATCH"
];
export const GMV_PRICE_OPERATIONAL_CODES_V1 = [
    "GMV_PRICE_LOCAL_INPUT_UNAVAILABLE",
    "GMV_PRICE_AGGREGATE_QUORUM_UNAVAILABLE",
    "GMV_PRICE_EVIDENCE_UNAVAILABLE"
];
export const GMV_PRICE_AGGREGATE_REASONS_V1 = [
    "AGGREGATE_SCHEMA_INVALID",
    "SELECTED_VALIDATORS_NON_CANONICAL",
    "STRICT_BFT_THRESHOLD_MISMATCH",
    "OBSERVATION_WINDOW_INVALID",
    "FINALIZED_SLOT_BOUNDS_INVALID",
    "PUBLICATION_WINDOW_INVALID",
    "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE",
    "SAMPLE_FLOOR_UNSATISFIED",
    "SAMPLE_ROOT_MISMATCH",
    "AGGREGATE_HASH_MISMATCH",
    "ARTIFACT_CONTENT_HASH_MISMATCH",
    "ARTIFACT_BYTE_LENGTH_MISMATCH",
    "REGISTRY_BINDING_MISMATCH",
    "SIGNATURE_ORDER_INVALID",
    "DUPLICATE_SIGNER",
    "UNSELECTED_SIGNER",
    "DUPLICATE_SIGNING_KEY",
    "SIGNING_KEY_NOT_ACTIVE",
    "SIGNATURE_INVALID",
    "SIGNATURE_QUORUM_UNSATISFIED",
    "CANDIDATE_V4_PROJECTION_INVALID",
    "CANDIDATE_ARTIFACT_BINDING_MISMATCH",
    "CANDIDATE_AGGREGATE_HASH_MISMATCH",
    "CANDIDATE_NETWORK_MISMATCH",
    "CANDIDATE_SOURCE_PROFILE_MISMATCH",
    "CANDIDATE_AGGREGATION_POLICY_MISMATCH",
    "CANDIDATE_SAMPLE_ROOT_MISMATCH",
    "CANDIDATE_REGISTRY_MISMATCH",
    "CANDIDATE_ASSIGNMENT_MISMATCH",
    "CANDIDATE_WINDOW_MISMATCH",
    "CANDIDATE_PUBLICATION_MISMATCH",
    "CANDIDATE_PRICE_VALUE_MISMATCH",
    "CANDIDATE_PRICE_WINDOW_ORDER_MISMATCH",
    "ATTEMPT_PRICE_CAPABILITY_MISSING",
    "CANDIDATE_PRICE_AFTER_ATTEMPT_START",
    "CANDIDATE_PRICE_STALE_FOR_ATTEMPT"
];
export class GmvPriceAggregateErrorV1 extends Error {
    code;
    reason;
    constructor(code, reason) {
        super(`${code}:${reason}`);
        this.name = "GmvPriceAggregateErrorV1";
        this.code = code;
        this.reason = reason;
    }
}
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;
const BASE58_KEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const BASE64_PUBLIC_KEY = /^[A-Za-z0-9+/]{43}=$/u;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const ED25519_RAW_SPKI_DER_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function fail(reason, code = "GMV_PRICE_AGGREGATE_INVALID") {
    throw new GmvPriceAggregateErrorV1(code, reason);
}
function exact(value, keys) {
    try {
        const record = asRecord(value, "GmvPriceAggregateV1");
        assertExactKeys(record, keys, "GmvPriceAggregateV1");
        return record;
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function candidateExact(value, keys) {
    try {
        const record = asRecord(value, "GmvDaySealCandidateV4");
        assertExactKeys(record, keys, "GmvDaySealCandidateV4");
        return record;
    }
    catch {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
function literal(value, allowed) {
    try {
        return asStringLiteral(value, allowed, "GmvPriceAggregateV1");
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function string(value, maximumLength) {
    try {
        const parsed = asString(value, "GmvPriceAggregateV1");
        if ((maximumLength !== undefined && parsed.length > maximumLength) ||
            [...parsed].some((character) => character.codePointAt(0) > 0x7f)) {
            return fail("AGGREGATE_SCHEMA_INVALID");
        }
        return parsed;
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function identifier(value) {
    const parsed = string(value, 160);
    if (!IDENTIFIER.test(parsed)) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return parsed;
}
function hash(value) {
    try {
        return asSha256Digest(value, "GmvPriceAggregateV1");
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function resolvedHash(value, reason) {
    try {
        return asSha256Digest(value, "resolved evidence hash");
    }
    catch {
        return fail(reason);
    }
}
function nonnegative(value) {
    try {
        return asNonNegativeInteger(value, "GmvPriceAggregateV1");
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function positive(value) {
    try {
        return asPositiveInteger(value, "GmvPriceAggregateV1");
    }
    catch {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
}
function boundedInteger(value, minimum, maximum) {
    const parsed = nonnegative(value);
    if (parsed < minimum || parsed > maximum) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return parsed;
}
function timestamp(value, candidate = false) {
    let parsed;
    try {
        parsed = asString(value, "timestamp");
    }
    catch {
        return candidate
            ? fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH")
            : fail("AGGREGATE_SCHEMA_INVALID");
    }
    const milliseconds = Date.parse(parsed);
    if (!TIMESTAMP.test(parsed) ||
        !Number.isFinite(milliseconds) ||
        new Date(milliseconds).toISOString() !== parsed) {
        return candidate
            ? fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH")
            : fail("AGGREGATE_SCHEMA_INVALID");
    }
    return parsed;
}
function canonicalBase64(value, pattern, bytes) {
    const parsed = string(value);
    const decoded = Buffer.from(parsed, "base64");
    if (!pattern.test(parsed) || decoded.byteLength !== bytes || decoded.toString("base64") !== parsed) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return parsed;
}
function parseSource(value) {
    const source = exact(value, [
        "sourceType",
        "chainId",
        "programId",
        "poolId",
        "baseMintId",
        "quoteMintId",
        "baseDecimals",
        "quoteDecimals",
        "poolLayoutRef",
        "sourceProfileHash",
        "priceUnit"
    ]);
    const programId = string(source.programId);
    const poolId = string(source.poolId);
    const baseMintId = string(source.baseMintId);
    const quoteMintId = string(source.quoteMintId);
    if (![programId, poolId, baseMintId, quoteMintId].every((entry) => BASE58_KEY.test(entry))) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return {
        sourceType: literal(source.sourceType, ["SOLANA_AMM_POOL_RESERVES"]),
        chainId: identifier(source.chainId),
        programId,
        poolId,
        baseMintId,
        quoteMintId,
        baseDecimals: boundedInteger(source.baseDecimals, 0, 18),
        quoteDecimals: boundedInteger(source.quoteDecimals, 0, 18),
        poolLayoutRef: string(source.poolLayoutRef, 200),
        sourceProfileHash: hash(source.sourceProfileHash),
        priceUnit: literal(source.priceUnit, ["MICRO_USD_PER_BASE_TOKEN"])
    };
}
function parseWindow(value) {
    const window = exact(value, [
        "windowStart",
        "windowEndExclusive",
        "firstObservedAt",
        "lastObservedAt",
        "firstFinalizedSlot",
        "lastFinalizedSlot",
        "chainCommitment"
    ]);
    return {
        windowStart: timestamp(window.windowStart),
        windowEndExclusive: timestamp(window.windowEndExclusive),
        firstObservedAt: timestamp(window.firstObservedAt),
        lastObservedAt: timestamp(window.lastObservedAt),
        firstFinalizedSlot: nonnegative(window.firstFinalizedSlot),
        lastFinalizedSlot: nonnegative(window.lastFinalizedSlot),
        chainCommitment: literal(window.chainCommitment, ["finalized"])
    };
}
function parseSampleCommitment(value) {
    const commitment = exact(value, [
        "observationSet",
        "sampleSetRoot",
        "sampleSetRootRule",
        "validSampleCount",
        "contributingValidatorCount"
    ]);
    const observationSet = exact(commitment.observationSet, [
        "artifactType",
        "artifactVersion",
        "contentHash",
        "byteLength"
    ]);
    return {
        observationSet: {
            artifactType: literal(observationSet.artifactType, ["GmvPriceObservationSetV1"]),
            artifactVersion: literal(observationSet.artifactVersion, ["1"]),
            contentHash: hash(observationSet.contentHash),
            byteLength: positive(observationSet.byteLength)
        },
        sampleSetRoot: hash(commitment.sampleSetRoot),
        sampleSetRootRule: literal(commitment.sampleSetRootRule, ["GMV_PRICE_SAMPLE_SET_ROOT_V1"]),
        validSampleCount: positive(commitment.validSampleCount),
        contributingValidatorCount: positive(commitment.contributingValidatorCount)
    };
}
function parseAggregation(value) {
    const record = asRecord(value, "GmvPriceAggregateV1.aggregation");
    const hasTolerancePolicy = Object.hasOwn(record, "minimumPoolTvlMicroUsd") ||
        Object.hasOwn(record, "toleranceBps");
    if (hasTolerancePolicy &&
        (!Object.hasOwn(record, "minimumPoolTvlMicroUsd") ||
            !Object.hasOwn(record, "toleranceBps"))) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    const aggregation = exact(value, [
        "rule",
        "aggregationPolicyHash",
        "minimumSamplesPerContributor",
        "maximumPublicationDelaySeconds",
        ...(hasTolerancePolicy
            ? ["minimumPoolTvlMicroUsd", "toleranceBps"]
            : []),
        "priceMicroUsdPerToken"
    ]);
    const minimumPoolTvlMicroUsd = hasTolerancePolicy
        ? string(aggregation.minimumPoolTvlMicroUsd)
        : undefined;
    if (minimumPoolTvlMicroUsd !== undefined &&
        !/^[1-9][0-9]*$/u.test(minimumPoolTvlMicroUsd)) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return {
        rule: literal(aggregation.rule, ["MEDIAN_OF_SIGNED_VALIDATOR_TWAP_V1"]),
        aggregationPolicyHash: hash(aggregation.aggregationPolicyHash),
        minimumSamplesPerContributor: positive(aggregation.minimumSamplesPerContributor),
        maximumPublicationDelaySeconds: positive(aggregation.maximumPublicationDelaySeconds),
        ...(minimumPoolTvlMicroUsd === undefined
            ? {}
            : {
                minimumPoolTvlMicroUsd,
                toleranceBps: boundedInteger(aggregation.toleranceBps, 0, 10_000)
            }),
        priceMicroUsdPerToken: positive(aggregation.priceMicroUsdPerToken)
    };
}
function parseCommittee(value) {
    const committee = exact(value, [
        "registrySequence",
        "registryHash",
        "assignmentId",
        "assignmentHash",
        "selectedValidatorIds",
        "quorumRule",
        "requiredSignatures"
    ]);
    if (!Array.isArray(committee.selectedValidatorIds) ||
        committee.selectedValidatorIds.length < 1 ||
        committee.selectedValidatorIds.length > 1024) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return {
        registrySequence: nonnegative(committee.registrySequence),
        registryHash: hash(committee.registryHash),
        assignmentId: identifier(committee.assignmentId),
        assignmentHash: hash(committee.assignmentHash),
        selectedValidatorIds: committee.selectedValidatorIds.map((entry) => identifier(entry)),
        quorumRule: literal(committee.quorumRule, ["bft_strict_supermajority_v1"]),
        requiredSignatures: positive(committee.requiredSignatures)
    };
}
function parseAuthorityBoundary(value) {
    const boundary = exact(value, [
        "claim",
        "gmvProofFinality",
        "lifecycleTransition",
        "consumptionAuthorization",
        "pointsMutation",
        "settlement"
    ]);
    if (boundary.gmvProofFinality !== false ||
        boundary.lifecycleTransition !== false ||
        boundary.consumptionAuthorization !== false ||
        boundary.pointsMutation !== false ||
        boundary.settlement !== false) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return {
        claim: literal(boundary.claim, ["PRICE_EVIDENCE_ONLY"]),
        gmvProofFinality: false,
        lifecycleTransition: false,
        consumptionAuthorization: false,
        pointsMutation: false,
        settlement: false
    };
}
function parseSignature(value) {
    const signature = exact(value, [
        "validatorId",
        "signerRole",
        "keyId",
        "publicKey",
        "signatureAlgorithm",
        "signedDigestRule",
        "signature"
    ]);
    return {
        validatorId: identifier(signature.validatorId),
        signerRole: literal(signature.signerRole, ["PRICE_AGGREGATE_SIGNER"]),
        keyId: identifier(signature.keyId),
        publicKey: canonicalBase64(signature.publicKey, BASE64_PUBLIC_KEY, 32),
        signatureAlgorithm: literal(signature.signatureAlgorithm, ["Ed25519"]),
        signedDigestRule: literal(signature.signedDigestRule, ["SIGN_RAW_32_BYTE_AGGREGATE_HASH"]),
        signature: canonicalBase64(signature.signature, BASE64_SIGNATURE, 64)
    };
}
export function parseGmvPriceAggregateV1(input) {
    const aggregate = exact(input, [
        "domain",
        "schemaVersion",
        "protocolVersion",
        "networkId",
        "source",
        "window",
        "sampleCommitment",
        "aggregation",
        "committee",
        "publishedAt",
        "authorityBoundary",
        "aggregateHash",
        "signatures"
    ]);
    if (!Array.isArray(aggregate.signatures) || aggregate.signatures.length < 1 || aggregate.signatures.length > 1024) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    if (aggregate.schemaVersion !== 1) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    const parsed = {
        domain: literal(aggregate.domain, [GMV_PRICE_AGGREGATE_DOMAIN_V1]),
        schemaVersion: 1,
        protocolVersion: literal(aggregate.protocolVersion, ["1.0.0-rc.1"]),
        networkId: identifier(aggregate.networkId),
        source: parseSource(aggregate.source),
        window: parseWindow(aggregate.window),
        sampleCommitment: parseSampleCommitment(aggregate.sampleCommitment),
        aggregation: parseAggregation(aggregate.aggregation),
        committee: parseCommittee(aggregate.committee),
        publishedAt: timestamp(aggregate.publishedAt),
        authorityBoundary: parseAuthorityBoundary(aggregate.authorityBoundary),
        aggregateHash: hash(aggregate.aggregateHash),
        signatures: aggregate.signatures.map((entry) => parseSignature(entry))
    };
    canonicalize(parsed);
    return parsed;
}
export function gmvPriceAggregateUnsignedCanonicalValueV1(aggregate) {
    const { aggregateHash: _aggregateHash, signatures: _signatures, ...unsigned } = aggregate;
    return unsigned;
}
export function hashGmvPriceAggregateV1(aggregateInput) {
    const aggregate = parseGmvPriceAggregateV1(aggregateInput);
    const preimage = Buffer.concat([
        Buffer.from(GMV_PRICE_AGGREGATE_HASH_DOMAIN_V1, "ascii"),
        Buffer.from([0]),
        Buffer.from(canonicalize(gmvPriceAggregateUnsignedCanonicalValueV1(aggregate)), "utf8")
    ]);
    return `sha256:${createHash("sha256").update(preimage).digest("hex")}`;
}
export function gmvPriceAggregateArtifactContentV1(aggregateInput) {
    const aggregate = parseGmvPriceAggregateV1(aggregateInput);
    const canonicalBytes = Buffer.from(canonicalize(aggregate), "utf8");
    return {
        canonicalBytes: new Uint8Array(canonicalBytes),
        contentHash: `sha256:${createHash("sha256").update(canonicalBytes).digest("hex")}`,
        byteLength: canonicalBytes.byteLength
    };
}
export function strictBftPriceAggregateThresholdV1(selectedValidatorCount) {
    if (!Number.isSafeInteger(selectedValidatorCount) || selectedValidatorCount < 1 || selectedValidatorCount > 1024) {
        return fail("AGGREGATE_SCHEMA_INVALID");
    }
    return Math.floor((2 * selectedValidatorCount) / 3) + 1;
}
function compareUtf8(left, right) {
    return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
function isStrictlyOrderedDistinct(values) {
    return values.every((value, index) => index === 0 || compareUtf8(values[index - 1], value) < 0);
}
/** Raw digest signature primitive shared by the aggregate and daily observation verifier. */
export function verifyRawEd25519PriceSignatureV1(publicKey, signature, digest) {
    try {
        const key = createPublicKey({
            key: Buffer.concat([ED25519_RAW_SPKI_DER_PREFIX, Buffer.from(publicKey, "base64")]),
            format: "der",
            type: "spki"
        });
        return verifyCryptoSignature(null, digest, key, Buffer.from(signature, "base64"));
    }
    catch {
        return false;
    }
}
export function verifyGmvPriceAggregateV1(input) {
    const aggregate = parseGmvPriceAggregateV1(input.aggregate);
    const selected = aggregate.committee.selectedValidatorIds;
    if (!isStrictlyOrderedDistinct(selected)) {
        return fail("SELECTED_VALIDATORS_NON_CANONICAL");
    }
    const required = strictBftPriceAggregateThresholdV1(selected.length);
    if (aggregate.committee.requiredSignatures !== required) {
        return fail("STRICT_BFT_THRESHOLD_MISMATCH");
    }
    const windowStart = Date.parse(aggregate.window.windowStart);
    const windowEnd = Date.parse(aggregate.window.windowEndExclusive);
    const firstObserved = Date.parse(aggregate.window.firstObservedAt);
    const lastObserved = Date.parse(aggregate.window.lastObservedAt);
    const publishedAt = Date.parse(aggregate.publishedAt);
    if (!(windowStart <= firstObserved && firstObserved <= lastObserved && lastObserved < windowEnd)) {
        return fail("OBSERVATION_WINDOW_INVALID");
    }
    if (aggregate.window.firstFinalizedSlot > aggregate.window.lastFinalizedSlot) {
        return fail("FINALIZED_SLOT_BOUNDS_INVALID");
    }
    const maximumPublicationDelayMs = aggregate.aggregation.maximumPublicationDelaySeconds * 1000;
    if (!Number.isSafeInteger(maximumPublicationDelayMs) ||
        !(windowEnd <= publishedAt && publishedAt <= windowEnd + maximumPublicationDelayMs)) {
        return fail("PUBLICATION_WINDOW_INVALID");
    }
    // Sample contributors are drawn from the selected committee, so the
    // contributing count is bounded by the committee size. The bound keeps the
    // declared contribution breadth an auditable property of the committee this
    // aggregate names rather than a self-asserted number.
    if (aggregate.sampleCommitment.contributingValidatorCount > selected.length) {
        return fail("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");
    }
    const minimumSamples = aggregate.sampleCommitment.contributingValidatorCount *
        aggregate.aggregation.minimumSamplesPerContributor;
    if (!Number.isSafeInteger(minimumSamples) ||
        aggregate.sampleCommitment.validSampleCount < minimumSamples) {
        return fail("SAMPLE_FLOOR_UNSATISFIED");
    }
    if (aggregate.sampleCommitment.sampleSetRoot !==
        resolvedHash(input.resolvedSampleSetRoot, "SAMPLE_ROOT_MISMATCH")) {
        return fail("SAMPLE_ROOT_MISMATCH");
    }
    const computedAggregateHash = hashGmvPriceAggregateV1(aggregate);
    if (aggregate.aggregateHash !== computedAggregateHash) {
        return fail("AGGREGATE_HASH_MISMATCH");
    }
    const artifact = gmvPriceAggregateArtifactContentV1(aggregate);
    if (artifact.contentHash !==
        resolvedHash(input.resolvedArtifactContentHash, "ARTIFACT_CONTENT_HASH_MISMATCH")) {
        return fail("ARTIFACT_CONTENT_HASH_MISMATCH");
    }
    if (input.expectedCanonicalArtifactByteLength !== undefined &&
        (!Number.isSafeInteger(input.expectedCanonicalArtifactByteLength) ||
            input.expectedCanonicalArtifactByteLength <= 0 ||
            artifact.byteLength !== input.expectedCanonicalArtifactByteLength)) {
        return fail("ARTIFACT_BYTE_LENGTH_MISMATCH");
    }
    if (input.registry.registrySequence !== aggregate.committee.registrySequence ||
        input.registry.registryHash !== aggregate.committee.registryHash) {
        return fail("REGISTRY_BINDING_MISMATCH");
    }
    const signerIds = aggregate.signatures.map((entry) => entry.validatorId);
    if (!isStrictlyOrderedDistinct(signerIds)) {
        return fail(new Set(signerIds).size === signerIds.length
            ? "SIGNATURE_ORDER_INVALID"
            : "DUPLICATE_SIGNER");
    }
    const registryIdentities = new Set();
    const registryKeyIdentities = new Set();
    const activePublicKeys = new Set();
    const activeKeys = new Map();
    for (const key of input.registry.keys) {
        if (!IDENTIFIER.test(key.validatorId) ||
            !IDENTIFIER.test(key.keyId) ||
            !BASE64_PUBLIC_KEY.test(key.publicKey) ||
            Buffer.from(key.publicKey, "base64").byteLength !== 32 ||
            Buffer.from(key.publicKey, "base64").toString("base64") !== key.publicKey) {
            return fail("REGISTRY_BINDING_MISMATCH");
        }
        const identity = `${key.validatorId}\u0000${key.keyId}`;
        const keyIdentity = `${key.keyId}\u0000${key.publicKey}`;
        if (registryIdentities.has(identity) ||
            registryKeyIdentities.has(keyIdentity) ||
            (key.active && activePublicKeys.has(key.publicKey))) {
            return fail("DUPLICATE_SIGNING_KEY");
        }
        registryIdentities.add(identity);
        registryKeyIdentities.add(keyIdentity);
        if (key.active) {
            activePublicKeys.add(key.publicKey);
        }
        activeKeys.set(identity, key);
    }
    const selectedSet = new Set(selected);
    const signingKeyIdentities = new Set();
    const signingPublicKeys = new Set();
    const digest = Buffer.from(computedAggregateHash.slice("sha256:".length), "hex");
    for (const signature of aggregate.signatures) {
        if (!selectedSet.has(signature.validatorId)) {
            return fail("UNSELECTED_SIGNER");
        }
        const identity = `${signature.validatorId}\u0000${signature.keyId}`;
        const keyIdentity = `${signature.keyId}\u0000${signature.publicKey}`;
        if (signingKeyIdentities.has(keyIdentity) || signingPublicKeys.has(signature.publicKey)) {
            return fail("DUPLICATE_SIGNING_KEY");
        }
        signingKeyIdentities.add(keyIdentity);
        signingPublicKeys.add(signature.publicKey);
        const registered = activeKeys.get(identity);
        if (registered === undefined ||
            registered.active !== true ||
            registered.publicKey !== signature.publicKey) {
            return fail("SIGNING_KEY_NOT_ACTIVE");
        }
        if (!verifyRawEd25519PriceSignatureV1(signature.publicKey, signature.signature, digest)) {
            return fail("SIGNATURE_INVALID");
        }
    }
    if (aggregate.signatures.length < required) {
        return fail("SIGNATURE_QUORUM_UNSATISFIED");
    }
    return {
        aggregate,
        aggregateHash: computedAggregateHash,
        artifactContentHash: artifact.contentHash,
        canonicalArtifactByteLength: artifact.byteLength,
        validDistinctSignatureCount: aggregate.signatures.length,
        requiredSignatures: required
    };
}
function candidateString(value) {
    try {
        return asString(value, "GmvDaySealCandidateV4");
    }
    catch {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
function candidateIdentifier(value) {
    const parsed = candidateString(value);
    if (!IDENTIFIER.test(parsed)) {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    return parsed;
}
function candidateHash(value) {
    try {
        return asSha256Digest(value, "GmvDaySealCandidateV4");
    }
    catch {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
function candidatePositive(value) {
    try {
        return asPositiveInteger(value, "GmvDaySealCandidateV4");
    }
    catch {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
function candidateNonnegative(value) {
    try {
        return asNonNegativeInteger(value, "GmvDaySealCandidateV4");
    }
    catch {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
/**
 * Extract the complete V4 price projection while rejecting unknown fields on
 * every price-bearing object. Base candidate semantics remain the existing
 * sealed-day verifier's responsibility until its V4 dispatch slice.
 */
export function parseGmvPriceCandidateProjectionV4(candidateInput) {
    const candidate = candidateExact(candidateInput, [
        "domain",
        "schemaVersion",
        "protocolVersion",
        "dayId",
        "identity",
        "window",
        "verifiedToken",
        "witness",
        "aggregate",
        "artifacts",
        "v3",
        "priceEvidence",
        "policies",
        "consumer",
        "expectedPreState",
        "artifactVersions"
    ]);
    if (candidate.domain !== "crinkl:gmv-day:seal-candidate:v4" ||
        candidate.schemaVersion !== 4 ||
        candidate.protocolVersion !== "1.0.0-rc.1") {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    const identity = candidateExact(candidate.identity, [
        "networkId",
        "consumerProgramId",
        "poolStateId",
        "utcDate"
    ]);
    const window = candidateExact(candidate.window, [
        "windowStart",
        "windowEnd",
        "epochWindowSeconds",
        "sealCutoff",
        "correctionHorizonSeconds"
    ]);
    const v3 = candidateExact(candidate.v3, [
        "domain",
        "epochCommitmentHash",
        "windowDay",
        "gmvCents",
        "settledRevenueCents",
        "spendHeadSetRoot",
        "ruleSetHash",
        "prevEpochHash",
        "expectedABeforeCents",
        "expectedBCurveBefore",
        "crinklElectingCount",
        "usdPerReceiptCents",
        "policyHash",
        "epochWindowSeconds",
        "priceMicroUsdPerToken",
        "electionRoot"
    ]);
    const versions = candidateExact(candidate.artifactVersions, [
        "verifiedGmvToken",
        "dayWitnessManifest",
        "burnStatement",
        "epochCommitment",
        "gmvPriceAggregate",
        "lifecycle"
    ]);
    if (versions.gmvPriceAggregate !== "GmvPriceAggregateV1/1") {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    const evidence = candidateExact(candidate.priceEvidence, [
        "aggregateArtifact",
        "aggregateHash",
        "sourceProfileHash",
        "aggregationPolicyHash",
        "sampleSetRoot",
        "registrySequence",
        "registryHash",
        "assignmentId",
        "assignmentHash",
        "windowStart",
        "windowEndExclusive",
        "publishedAt",
        "priceMicroUsdPerToken"
    ]);
    const artifact = candidateExact(evidence.aggregateArtifact, [
        "artifactType",
        "artifactVersion",
        "contentHash",
        "byteLength"
    ]);
    if (artifact.artifactType !== "GmvPriceAggregateV1" || artifact.artifactVersion !== "1") {
        return fail("CANDIDATE_V4_PROJECTION_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    return {
        networkId: candidateIdentifier(identity.networkId),
        dayWindowEnd: timestamp(window.windowEnd, true),
        sealCutoff: timestamp(window.sealCutoff, true),
        priceMicroUsdPerToken: candidatePositive(v3.priceMicroUsdPerToken),
        gmvPriceAggregateVersion: "GmvPriceAggregateV1/1",
        priceEvidence: {
            aggregateArtifact: {
                artifactType: "GmvPriceAggregateV1",
                artifactVersion: "1",
                contentHash: candidateHash(artifact.contentHash),
                byteLength: candidatePositive(artifact.byteLength)
            },
            aggregateHash: candidateHash(evidence.aggregateHash),
            sourceProfileHash: candidateHash(evidence.sourceProfileHash),
            aggregationPolicyHash: candidateHash(evidence.aggregationPolicyHash),
            sampleSetRoot: candidateHash(evidence.sampleSetRoot),
            registrySequence: candidateNonnegative(evidence.registrySequence),
            registryHash: candidateHash(evidence.registryHash),
            assignmentId: candidateIdentifier(evidence.assignmentId),
            assignmentHash: candidateHash(evidence.assignmentHash),
            windowStart: timestamp(evidence.windowStart, true),
            windowEndExclusive: timestamp(evidence.windowEndExclusive, true),
            publishedAt: timestamp(evidence.publishedAt, true),
            priceMicroUsdPerToken: candidatePositive(evidence.priceMicroUsdPerToken)
        }
    };
}
function verifyCandidateProjection(candidate, verified, resolvedArtifactContentHash) {
    const aggregate = verified.aggregate;
    const evidence = candidate.priceEvidence;
    if (evidence.aggregateArtifact.contentHash !== resolvedArtifactContentHash ||
        resolvedArtifactContentHash !== verified.artifactContentHash ||
        evidence.aggregateArtifact.byteLength !== verified.canonicalArtifactByteLength) {
        return fail("CANDIDATE_ARTIFACT_BINDING_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.aggregateHash !== verified.aggregateHash) {
        return fail("CANDIDATE_AGGREGATE_HASH_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (candidate.networkId !== aggregate.networkId) {
        return fail("CANDIDATE_NETWORK_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.sourceProfileHash !== aggregate.source.sourceProfileHash) {
        return fail("CANDIDATE_SOURCE_PROFILE_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.aggregationPolicyHash !== aggregate.aggregation.aggregationPolicyHash) {
        return fail("CANDIDATE_AGGREGATION_POLICY_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.sampleSetRoot !== aggregate.sampleCommitment.sampleSetRoot) {
        return fail("CANDIDATE_SAMPLE_ROOT_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.registrySequence !== aggregate.committee.registrySequence ||
        evidence.registryHash !== aggregate.committee.registryHash) {
        return fail("CANDIDATE_REGISTRY_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.assignmentId !== aggregate.committee.assignmentId ||
        evidence.assignmentHash !== aggregate.committee.assignmentHash) {
        return fail("CANDIDATE_ASSIGNMENT_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.windowStart !== aggregate.window.windowStart ||
        evidence.windowEndExclusive !== aggregate.window.windowEndExclusive) {
        return fail("CANDIDATE_WINDOW_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.publishedAt !== aggregate.publishedAt) {
        return fail("CANDIDATE_PUBLICATION_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (evidence.priceMicroUsdPerToken !== aggregate.aggregation.priceMicroUsdPerToken) {
        return fail("CANDIDATE_PRICE_VALUE_MISMATCH", "GMV_PRICE_VALUE_MISMATCH");
    }
    if (candidate.priceMicroUsdPerToken !== aggregate.aggregation.priceMicroUsdPerToken) {
        return fail("CANDIDATE_PRICE_VALUE_MISMATCH", "GMV_PRICE_VALUE_MISMATCH");
    }
    if (Date.parse(aggregate.window.windowStart) < Date.parse(candidate.dayWindowEnd)) {
        return fail("CANDIDATE_PRICE_WINDOW_ORDER_MISMATCH", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
export function assertGmvPriceAggregateAttemptCapabilityV4(attemptInput) {
    let attempt;
    try {
        attempt = asRecord(attemptInput, "GmvDaySealingAttemptV1");
    }
    catch {
        return fail("ATTEMPT_PRICE_CAPABILITY_MISSING", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (!Array.isArray(attempt.requiredEvidenceCapabilities) ||
        !attempt.requiredEvidenceCapabilities.includes(GMV_PRICE_AGGREGATE_CAPABILITY_V1)) {
        return fail("ATTEMPT_PRICE_CAPABILITY_MISSING", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
function assertGmvPriceAggregateAttemptFreshnessV4(attemptInput, aggregate) {
    const attempt = asRecord(attemptInput, "GmvDaySealingAttemptV1");
    const attemptStartedAt = Date.parse(timestamp(attempt.startedAt, true));
    const publishedAt = Date.parse(aggregate.publishedAt);
    const maximumAgeMs = aggregate.aggregation.maximumPublicationDelaySeconds * 1000;
    if (publishedAt > attemptStartedAt) {
        return fail("CANDIDATE_PRICE_AFTER_ATTEMPT_START", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
    if (!Number.isSafeInteger(maximumAgeMs) ||
        attemptStartedAt - publishedAt > maximumAgeMs) {
        return fail("CANDIDATE_PRICE_STALE_FOR_ATTEMPT", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH");
    }
}
export function verifyGmvPriceAggregateForCandidateV4(input) {
    const candidate = parseGmvPriceCandidateProjectionV4(input.candidate);
    const verified = verifyGmvPriceAggregateV1({
        aggregate: input.aggregate,
        resolvedArtifactContentHash: input.resolvedArtifactContentHash,
        resolvedSampleSetRoot: input.resolvedSampleSetRoot,
        registry: input.registry,
        expectedCanonicalArtifactByteLength: candidate.priceEvidence.aggregateArtifact.byteLength
    });
    verifyCandidateProjection(candidate, verified, input.resolvedArtifactContentHash);
    if (input.attempt !== undefined) {
        assertGmvPriceAggregateAttemptCapabilityV4(input.attempt);
        assertGmvPriceAggregateAttemptFreshnessV4(input.attempt, verified.aggregate);
    }
    return verified;
}
export function gmvPriceOperationalNoVoteV1(code) {
    if (!GMV_PRICE_OPERATIONAL_CODES_V1.includes(code)) {
        throw new Error("unsupported GMV price operational code");
    }
    return {
        classification: "OPERATIONAL",
        code,
        proofVote: "NONE"
    };
}
//# sourceMappingURL=priceAggregateV1.js.map