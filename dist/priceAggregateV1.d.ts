import { type CanonicalValue } from "./canonical.js";
export declare const GMV_PRICE_AGGREGATE_DOMAIN_V1 = "crinkl:gmv:price-aggregate:v1";
export declare const GMV_PRICE_AGGREGATE_HASH_DOMAIN_V1 = "CRINKL_GMV_PRICE_AGGREGATE_V1";
export declare const GMV_PRICE_AGGREGATE_CAPABILITY_V1 = "GMV_PRICE_AGGREGATE_V1";
export declare const GMV_PRICE_AGGREGATE_SEMANTIC_CODES_V1: readonly ["GMV_PRICE_AGGREGATE_INVALID", "GMV_PRICE_AGGREGATE_BINDING_MISMATCH", "GMV_PRICE_VALUE_MISMATCH"];
export type GmvPriceAggregateSemanticCodeV1 = (typeof GMV_PRICE_AGGREGATE_SEMANTIC_CODES_V1)[number];
export declare const GMV_PRICE_OPERATIONAL_CODES_V1: readonly ["GMV_PRICE_LOCAL_INPUT_UNAVAILABLE", "GMV_PRICE_AGGREGATE_QUORUM_UNAVAILABLE", "GMV_PRICE_EVIDENCE_UNAVAILABLE"];
export type GmvPriceOperationalCodeV1 = (typeof GMV_PRICE_OPERATIONAL_CODES_V1)[number];
export declare const GMV_PRICE_AGGREGATE_REASONS_V1: readonly ["AGGREGATE_SCHEMA_INVALID", "SELECTED_VALIDATORS_NON_CANONICAL", "STRICT_BFT_THRESHOLD_MISMATCH", "OBSERVATION_WINDOW_INVALID", "FINALIZED_SLOT_BOUNDS_INVALID", "PUBLICATION_WINDOW_INVALID", "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE", "SAMPLE_FLOOR_UNSATISFIED", "SAMPLE_ROOT_MISMATCH", "AGGREGATE_HASH_MISMATCH", "ARTIFACT_CONTENT_HASH_MISMATCH", "ARTIFACT_BYTE_LENGTH_MISMATCH", "REGISTRY_BINDING_MISMATCH", "SIGNATURE_ORDER_INVALID", "DUPLICATE_SIGNER", "UNSELECTED_SIGNER", "DUPLICATE_SIGNING_KEY", "SIGNING_KEY_NOT_ACTIVE", "SIGNATURE_INVALID", "SIGNATURE_QUORUM_UNSATISFIED", "CANDIDATE_V4_PROJECTION_INVALID", "CANDIDATE_ARTIFACT_BINDING_MISMATCH", "CANDIDATE_AGGREGATE_HASH_MISMATCH", "CANDIDATE_NETWORK_MISMATCH", "CANDIDATE_SOURCE_PROFILE_MISMATCH", "CANDIDATE_AGGREGATION_POLICY_MISMATCH", "CANDIDATE_SAMPLE_ROOT_MISMATCH", "CANDIDATE_REGISTRY_MISMATCH", "CANDIDATE_ASSIGNMENT_MISMATCH", "CANDIDATE_WINDOW_MISMATCH", "CANDIDATE_PUBLICATION_MISMATCH", "CANDIDATE_PRICE_VALUE_MISMATCH", "CANDIDATE_PRICE_WINDOW_ORDER_MISMATCH", "ATTEMPT_PRICE_CAPABILITY_MISSING", "CANDIDATE_PRICE_AFTER_ATTEMPT_START", "CANDIDATE_PRICE_STALE_FOR_ATTEMPT"];
export type GmvPriceAggregateReasonV1 = (typeof GMV_PRICE_AGGREGATE_REASONS_V1)[number];
export interface GmvPriceAggregateSignatureV1 {
    readonly validatorId: string;
    readonly signerRole: "PRICE_AGGREGATE_SIGNER";
    readonly keyId: string;
    readonly publicKey: string;
    readonly signatureAlgorithm: "Ed25519";
    readonly signedDigestRule: "SIGN_RAW_32_BYTE_AGGREGATE_HASH";
    readonly signature: string;
}
export interface GmvPriceAggregateV1 {
    readonly domain: typeof GMV_PRICE_AGGREGATE_DOMAIN_V1;
    readonly schemaVersion: 1;
    readonly protocolVersion: "1.0.0-rc.1";
    readonly networkId: string;
    readonly source: {
        readonly sourceType: "SOLANA_AMM_POOL_RESERVES";
        readonly chainId: string;
        readonly programId: string;
        readonly poolId: string;
        readonly baseMintId: string;
        readonly quoteMintId: string;
        readonly baseDecimals: number;
        readonly quoteDecimals: number;
        readonly poolLayoutRef: string;
        readonly sourceProfileHash: string;
        readonly priceUnit: "MICRO_USD_PER_BASE_TOKEN";
    };
    readonly window: {
        readonly windowStart: string;
        readonly windowEndExclusive: string;
        readonly firstObservedAt: string;
        readonly lastObservedAt: string;
        readonly firstFinalizedSlot: number;
        readonly lastFinalizedSlot: number;
        readonly chainCommitment: "finalized";
    };
    readonly sampleCommitment: {
        readonly observationSet: {
            readonly artifactType: "GmvPriceObservationSetV1";
            readonly artifactVersion: "1";
            readonly contentHash: string;
            readonly byteLength: number;
        };
        readonly sampleSetRoot: string;
        readonly sampleSetRootRule: "GMV_PRICE_SAMPLE_SET_ROOT_V1";
        readonly validSampleCount: number;
        readonly contributingValidatorCount: number;
    };
    readonly aggregation: {
        readonly rule: "MEDIAN_OF_SIGNED_VALIDATOR_TWAP_V1";
        readonly aggregationPolicyHash: string;
        readonly minimumSamplesPerContributor: number;
        readonly maximumPublicationDelaySeconds: number;
        readonly minimumPoolTvlMicroUsd?: string;
        readonly toleranceBps?: number;
        readonly priceMicroUsdPerToken: number;
    };
    readonly committee: {
        readonly registrySequence: number;
        readonly registryHash: string;
        readonly assignmentId: string;
        readonly assignmentHash: string;
        readonly selectedValidatorIds: readonly string[];
        readonly quorumRule: "bft_strict_supermajority_v1";
        readonly requiredSignatures: number;
    };
    readonly publishedAt: string;
    readonly authorityBoundary: {
        readonly claim: "PRICE_EVIDENCE_ONLY";
        readonly gmvProofFinality: false;
        readonly lifecycleTransition: false;
        readonly consumptionAuthorization: false;
        readonly pointsMutation: false;
        readonly settlement: false;
    };
    readonly aggregateHash: string;
    readonly signatures: readonly GmvPriceAggregateSignatureV1[];
}
/**
 * A verified view of the exact signed registry named by the aggregate.
 * Callers derive this view only after authenticating the registry snapshot.
 * It is an in-memory verifier input, not a protocol wire object.
 */
export interface GmvPriceAggregateRegistryViewV1 {
    readonly registrySequence: number;
    readonly registryHash: string;
    readonly keys: readonly {
        readonly validatorId: string;
        readonly keyId: string;
        readonly publicKey: string;
        readonly active: boolean;
    }[];
}
export interface VerifyGmvPriceAggregateInputV1 {
    readonly aggregate: unknown;
    readonly resolvedArtifactContentHash: string;
    readonly resolvedSampleSetRoot: string;
    readonly registry: GmvPriceAggregateRegistryViewV1;
    readonly expectedCanonicalArtifactByteLength?: number;
}
export interface VerifiedGmvPriceAggregateV1 {
    readonly aggregate: GmvPriceAggregateV1;
    readonly aggregateHash: string;
    readonly artifactContentHash: string;
    readonly canonicalArtifactByteLength: number;
    readonly validDistinctSignatureCount: number;
    readonly requiredSignatures: number;
}
export interface GmvPriceOperationalNoVoteV1 {
    readonly classification: "OPERATIONAL";
    readonly code: GmvPriceOperationalCodeV1;
    readonly proofVote: "NONE";
}
export interface GmvPriceCandidateProjectionV4 {
    readonly networkId: string;
    readonly dayWindowEnd: string;
    readonly sealCutoff: string;
    readonly priceMicroUsdPerToken: number;
    readonly gmvPriceAggregateVersion: "GmvPriceAggregateV1/1";
    readonly priceEvidence: {
        readonly aggregateArtifact: {
            readonly artifactType: "GmvPriceAggregateV1";
            readonly artifactVersion: "1";
            readonly contentHash: string;
            readonly byteLength: number;
        };
        readonly aggregateHash: string;
        readonly sourceProfileHash: string;
        readonly aggregationPolicyHash: string;
        readonly sampleSetRoot: string;
        readonly registrySequence: number;
        readonly registryHash: string;
        readonly assignmentId: string;
        readonly assignmentHash: string;
        readonly windowStart: string;
        readonly windowEndExclusive: string;
        readonly publishedAt: string;
        readonly priceMicroUsdPerToken: number;
    };
}
export interface VerifyGmvPriceAggregateForCandidateV4InputV1 extends Omit<VerifyGmvPriceAggregateInputV1, "resolvedArtifactContentHash"> {
    readonly candidate: unknown;
    readonly resolvedArtifactContentHash: string;
    readonly attempt?: unknown;
}
export declare class GmvPriceAggregateErrorV1 extends Error {
    readonly code: GmvPriceAggregateSemanticCodeV1;
    readonly reason: GmvPriceAggregateReasonV1;
    constructor(code: GmvPriceAggregateSemanticCodeV1, reason: GmvPriceAggregateReasonV1);
}
export declare function parseGmvPriceAggregateV1(input: unknown): GmvPriceAggregateV1;
export declare function gmvPriceAggregateUnsignedCanonicalValueV1(aggregate: GmvPriceAggregateV1): CanonicalValue;
export declare function hashGmvPriceAggregateV1(aggregateInput: unknown): string;
export declare function gmvPriceAggregateArtifactContentV1(aggregateInput: unknown): {
    readonly canonicalBytes: Uint8Array;
    readonly contentHash: string;
    readonly byteLength: number;
};
export declare function strictBftPriceAggregateThresholdV1(selectedValidatorCount: number): number;
export declare function verifyGmvPriceAggregateV1(input: VerifyGmvPriceAggregateInputV1): VerifiedGmvPriceAggregateV1;
/**
 * Extract the complete V4 price projection while rejecting unknown fields on
 * every price-bearing object. Base candidate semantics remain the existing
 * sealed-day verifier's responsibility until its V4 dispatch slice.
 */
export declare function parseGmvPriceCandidateProjectionV4(candidateInput: unknown): GmvPriceCandidateProjectionV4;
export declare function assertGmvPriceAggregateAttemptCapabilityV4(attemptInput: unknown): void;
export declare function verifyGmvPriceAggregateForCandidateV4(input: VerifyGmvPriceAggregateForCandidateV4InputV1): VerifiedGmvPriceAggregateV1;
export declare function gmvPriceOperationalNoVoteV1(code: GmvPriceOperationalCodeV1): GmvPriceOperationalNoVoteV1;
//# sourceMappingURL=priceAggregateV1.d.ts.map