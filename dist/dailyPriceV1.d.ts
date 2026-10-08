import { type GmvPriceAggregateRegistryViewV1, type VerifiedGmvPriceAggregateV1 } from "./priceAggregateV1.js";
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
export declare class GmvDailyPriceErrorV1 extends Error {
    readonly reason: string;
    readonly code = "GMV_DAILY_PRICE_INVALID";
    constructor(reason: string);
}
export declare const GMV_DAILY_PRICE_REQUIRED_CAPABILITIES_V1: readonly ["gmv_price_aggregate_v1", "gmv_daily_price_formation_request_v1"];
/**
 * Worker-envelope checks, capable-pool selection and code-unit ordering are
 * extracted from crinkl-proof-validator 3542863ca3cb41103414202247c87523dc274e2d,
 * bin/lib/gmv-price-committee-selection.mjs V2. The daily identity binds its
 * own duty and capability family; the five-seat floor, 1800-second age,
 * 60-second skew and signed-status eligibility retain that source's rules.
 */
export declare function verifyGmvDailyPriceCommitteeSelectionEvidenceV1(input: {
    readonly evidence: unknown;
    readonly evidenceHash: string;
    readonly priceDutyHash: string;
    readonly authenticatedRegistrySnapshot: unknown;
    readonly authenticatedRegistry: GmvPriceAggregateRegistryViewV1;
    readonly authenticatedAssignmentSignedAtUnixMs: number;
}): {
    readonly evidenceHash: string;
    readonly selectedValidatorIds: readonly string[];
    readonly requiredSignatures: number;
};
export declare function hashGmvDailyPriceAggregationPolicyV1(policy: GmvDailyPriceAggregationPolicyV1): string;
export declare function parseGmvRewardDayPriceDutyV1(input: unknown): GmvRewardDayPriceDutyV1;
export declare function hashGmvRewardDayPriceDutyV1(input: unknown): string;
export declare function verifyGmvDailyPriceV1(input: VerifyGmvDailyPriceInputV1): VerifiedGmvDailyPriceV1;
//# sourceMappingURL=dailyPriceV1.d.ts.map