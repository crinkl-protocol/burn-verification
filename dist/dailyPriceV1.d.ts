import { type GmvPriceAggregateRegistryViewV1, type VerifiedGmvPriceAggregateV1 } from "./priceAggregateV1.js";
export interface AuthenticatedGmvHistoricalPriceCommitteeV1 {
    readonly registry: GmvPriceAggregateRegistryViewV1;
    readonly registrySnapshot: unknown;
    readonly assignment: {
        readonly assignmentId: string;
        readonly assignmentHash: string;
        readonly selectedValidatorIds: readonly string[];
        readonly signedAtUnixMs: number;
    };
}
export declare class GmvHistoricalPriceErrorV1 extends Error {
    readonly reason: string;
    readonly code = "GMV_HISTORICAL_PRICE_INVALID";
    constructor(reason: string);
}
export interface GmvHistoricalPriceSelectionV1 {
    readonly rule: "GMV_DAY_OR_PREVIOUS_DAY_V1";
    readonly gmvWindowDay: number;
    readonly priceWindowDay: number;
    readonly registryNetworkId: string;
    readonly aggregateArtifactContentHash: string;
    readonly aggregateHash: string;
    /** A bounded lookup observation, not a proof of global price absence. */
    readonly primaryLookup: {
        readonly status: "AVAILABLE" | "UNAVAILABLE";
        readonly observedAt: string;
        readonly reason: "DIRECT_PRICE" | "NOT_FOUND" | "TRANSPORT_UNAVAILABLE";
    };
}
export interface VerifyGmvHistoricalPriceInputV1 {
    readonly aggregate: unknown;
    readonly observationSet: unknown;
    readonly committeeSelectionEvidence: unknown;
    readonly committeeSelectionEvidenceHash: string;
    /** Pinned-root authenticated historical registry and original assignment. */
    readonly authenticatedCommittee: AuthenticatedGmvHistoricalPriceCommitteeV1;
    readonly priceSelection: unknown;
    /**
     * Context bound by the accepted profile and candidate/GMV-day artifact pin.
     * Wrappers enforce pin immutability and authenticate the network root.
     * The chain-price network and validator-registry network have distinct pins.
     */
    readonly expected: {
        readonly gmvWindowDay: number;
        readonly priceNetworkId: string;
        readonly registryNetworkId: string;
        readonly source: unknown;
        readonly aggregationPolicyHash: string;
        readonly aggregateArtifactContentHash: string;
        readonly aggregateHash: string;
        readonly priceMicroUsdPerToken: number;
    };
}
export interface VerifiedGmvHistoricalPriceV1 extends VerifiedGmvPriceAggregateV1 {
    readonly fixingWindowDay: number;
    readonly priceSelection: GmvHistoricalPriceSelectionV1;
    readonly originalStatementHash: string;
    readonly committeeSelectionEvidenceHash: string;
}
export declare function parseGmvHistoricalPriceSelectionV1(input: unknown): GmvHistoricalPriceSelectionV1;
/**
 * An existing aggregate's signed publication and observation-window-end dates
 * identify its fixing day. The original signed assignment and V1/V2 worker
 * selection retain their statement binding; the consuming burn does not
 * redefine it. Selection replay follows the V1 locale or V2 code-unit order
 * in crinkl-proof-validator 3542863ca3cb41103414202247c87523dc274e2d,
 * bin/lib/gmv-price-committee-selection.mjs.
 */
export declare function verifyGmvHistoricalPriceV1(input: VerifyGmvHistoricalPriceInputV1): VerifiedGmvHistoricalPriceV1;
//# sourceMappingURL=dailyPriceV1.d.ts.map