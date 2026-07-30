/**
 * Verdict-shaped entry points for relying verifiers.
 *
 * A relying verifier (for example, the platform seal-admission verifier)
 * supplies the aggregate, the resolved evidence hashes, and a registry view it
 * has already authenticated from signed registry/assignment evidence, and
 * receives a structured verdict instead of a thrown error. The verdict carries
 * exactly the canonical validator failure codes and reasons; no additional
 * classification is introduced.
 */
import { type GmvPriceAggregateReasonV1, type GmvPriceAggregateSemanticCodeV1, type VerifiedGmvPriceAggregateV1, type VerifyGmvPriceAggregateForCandidateV4InputV1, type VerifyGmvPriceAggregateInputV1 } from "./priceAggregateV1.js";
export interface GmvPriceAggregateAcceptedVerdictV1 {
    readonly accepted: true;
    readonly verified: VerifiedGmvPriceAggregateV1;
}
export interface GmvPriceAggregateRejectedVerdictV1 {
    readonly accepted: false;
    readonly failureCode: GmvPriceAggregateSemanticCodeV1;
    readonly failureReason: GmvPriceAggregateReasonV1;
}
export type GmvPriceAggregateVerdictV1 = GmvPriceAggregateAcceptedVerdictV1 | GmvPriceAggregateRejectedVerdictV1;
export declare function gmvPriceAggregateVerdictV1(input: VerifyGmvPriceAggregateInputV1): GmvPriceAggregateVerdictV1;
export declare function gmvPriceAggregateForCandidateV4VerdictV1(input: VerifyGmvPriceAggregateForCandidateV4InputV1): GmvPriceAggregateVerdictV1;
//# sourceMappingURL=verdict.d.ts.map