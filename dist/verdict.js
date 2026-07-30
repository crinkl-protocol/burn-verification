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
import { GmvPriceAggregateErrorV1, verifyGmvPriceAggregateForCandidateV4, verifyGmvPriceAggregateV1 } from "./priceAggregateV1.js";
function toVerdict(run) {
    try {
        return { accepted: true, verified: run() };
    }
    catch (error) {
        if (error instanceof GmvPriceAggregateErrorV1) {
            return {
                accepted: false,
                failureCode: error.code,
                failureReason: error.reason
            };
        }
        throw error;
    }
}
export function gmvPriceAggregateVerdictV1(input) {
    return toVerdict(() => verifyGmvPriceAggregateV1(input));
}
export function gmvPriceAggregateForCandidateV4VerdictV1(input) {
    return toVerdict(() => verifyGmvPriceAggregateForCandidateV4(input));
}
//# sourceMappingURL=verdict.js.map