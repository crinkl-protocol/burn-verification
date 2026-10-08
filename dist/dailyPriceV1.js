/** Historical price evidence binds an authenticated committee fixing to one GMV day. */
import { createPublicKey } from "node:crypto";
import { asRecord, assertExactKeys, asNonNegativeInteger, asPositiveInteger, asSha256Digest, asString, canonicalize, hashCanonicalValue, sha256Hex } from "./canonical.js";
import { verifyGmvPriceAggregateV1, verifyRawEd25519PriceSignatureV1 } from "./priceAggregateV1.js";
export class GmvHistoricalPriceErrorV1 extends Error {
    reason;
    code = "GMV_HISTORICAL_PRICE_INVALID";
    constructor(reason) {
        super(`GMV_HISTORICAL_PRICE_INVALID:${reason}`);
        this.reason = reason;
        this.name = "GmvHistoricalPriceErrorV1";
    }
}
function reject(reason) { throw new GmvHistoricalPriceErrorV1(reason); }
function exact(value, fields) {
    const record = asRecord(value, "historical price evidence");
    assertExactKeys(record, fields, "historical price evidence");
    return record;
}
const digest = (domain, value) => `sha256:${sha256Hex(`${domain}\u0000${canonicalize(value)}`)}`;
const canonicalHash = (value) => `sha256:${hashCanonicalValue(value)}`;
const codeUnitCompare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
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
function boundaryInvalid(value) {
    return ["pointsLedgerMutation", "selectionWeightMutation", "claimable", "productionPayoutAuthority",
        "stakingAuthority", "slashingAuthority", "productionGovernanceAuthority", "productionChainState"]
        .some((field) => value[field] === true) || value.devnetOnly !== true;
}
function verifyHistoricalWorkerStatus(envelopeInput, validatorId, registry, registryHash, validators, selectedAt, requiredCapabilities) {
    try {
        const envelope = asRecord(envelopeInput, "worker envelope");
        if (Object.keys(envelope).some((field) => !envelopeFields.has(field)) ||
            envelope.version !== "CrinklGmvSelectedValidatorWorkerStatusEnvelopeV1" ||
            envelope.networkId !== registry.networkId || envelope.validatorId !== validatorId || boundaryInvalid(envelope))
            throw new Error();
        const status = asRecord(envelope.status, "worker status");
        if (Object.keys(status).some((field) => !statusFields.has(field)) ||
            status.version !== "CrinklGmvSelectedValidatorWorkerStatusV1" || status.networkId !== registry.networkId ||
            status.validatorId !== validatorId || boundaryInvalid(status) || !Number.isSafeInteger(status.updatedAtUnixMs) ||
            !Array.isArray(status.capabilities) || status.capabilities.some((cap) => typeof cap !== "string"))
            throw new Error();
        const signature = asRecord(envelope.validatorSignature, "worker signature");
        const required = ["version", "domain", "validatorId", "signingKeyId", "proofId", "statementType", "assignmentId",
            "policyHash", "registrySnapshotHash", "resultHash", "signedAtUnixMs", "signature"];
        const optional = ["proofPackageHash", "decision", "publicArtifactHash"];
        if (required.some((field) => !Object.hasOwn(signature, field)) ||
            Object.keys(signature).some((field) => !required.includes(field) && !optional.includes(field)) ||
            signature.version !== "ValidatorSignatureV1" || signature.domain !== "crinkl.validator.signature.v1" ||
            !Number.isSafeInteger(signature.signedAtUnixMs) || typeof signature.signature !== "string")
            throw new Error();
        const signedAt = Number(signature.signedAtUnixMs), resultHash = canonicalHash(status);
        if (envelope.resultHash !== resultHash || signature.resultHash !== resultHash || signature.validatorId !== validatorId ||
            signature.proofId !== `gmv-selected-validator-worker-status:${validatorId}:${Math.floor(signedAt / 60000)}` ||
            signature.statementType !== "QUALIFIED_GMV_BURN_EPOCH_V1" ||
            signature.assignmentId !== "gmv_selected_validator_worker_status_v1" || signature.policyHash !== registryHash ||
            signature.registrySnapshotHash !== registryHash || signedAt !== status.updatedAtUnixMs || signedAt > selectedAt + 60000)
            throw new Error();
        if (selectedAt - signedAt > 1800000)
            return "status_stale";
        const validator = validators.find((entry) => entry.validatorId === validatorId);
        const key = validator?.signingKeys.find((entry) => entry.signingKeyId === signature.signingKeyId && entry.status === "active");
        if (validator?.status !== "active" || !Number.isSafeInteger(validator.activatedAtUnixMs) ||
            signedAt < validator.activatedAtUnixMs || (validator.removedAtUnixMs !== undefined && signedAt >= validator.removedAtUnixMs) ||
            key === undefined || !signature.signature.startsWith("ed25519:"))
            throw new Error();
        const { signature: _signature, ...preimage } = signature;
        const publicKey = Buffer.from(createPublicKey(key.publicKeyPem).export({ format: "der", type: "spki" })).subarray(-32).toString("base64");
        if (!verifyRawEd25519PriceSignatureV1(publicKey, signature.signature.slice(8), Buffer.from(canonicalize({ ...preimage, version: "ValidatorSignaturePreimageV1" }), "utf8")))
            throw new Error();
        if (!requiredCapabilities.every((cap) => status.capabilities.includes(cap)))
            return "capability_not_advertised";
        return undefined;
    }
    catch {
        return "status_evidence_invalid";
    }
}
function verifyPriceCommitteeSelection(input, format) {
    try {
        const evidence = exact(input.evidence, ["version", "networkId", format.subjectField, "selectedAtUnixMs", "registrySequence",
            "registryHash", "requiredCapabilities", "capabilityMaxAgeSeconds", "minimumCommitteeSize", "eligibleValidatorIds",
            "selectedValidatorIds", "requiredSignatures", "exclusions", "workerStatusEnvelopes"]);
        const registry = asRecord(input.authenticatedRegistrySnapshot, "authenticated registry snapshot");
        const registryHash = canonicalHash(registry);
        const selectedAt = asNonNegativeInteger(evidence.selectedAtUnixMs, "selectedAtUnixMs");
        const replayAt = asNonNegativeInteger(input.authenticatedAssignmentSignedAtUnixMs, "authenticated assignment time");
        if (registryHash !== input.authenticatedRegistry.registryHash || registry.registrySequence !== input.authenticatedRegistry.registrySequence ||
            evidence.version !== format.version || evidence.networkId !== registry.networkId ||
            evidence[format.subjectField] !== asSha256Digest(input.subjectHash, "selection subject hash") ||
            evidence.registryHash !== registryHash || evidence.registrySequence !== registry.registrySequence ||
            canonicalize(evidence.requiredCapabilities) !== canonicalize(format.requiredCapabilities) ||
            evidence.capabilityMaxAgeSeconds !== 1800 || evidence.minimumCommitteeSize !== 5 ||
            selectedAt > replayAt + 60000 || replayAt - selectedAt > 1800000 ||
            canonicalHash(evidence) !== asSha256Digest(input.evidenceHash, "selection evidence hash") ||
            Buffer.byteLength(canonicalize(evidence)) > 512 * 1024 || !Array.isArray(registry.validators) ||
            !Array.isArray(evidence.workerStatusEnvelopes) || evidence.workerStatusEnvelopes.length > registry.validators.length)
            reject("SELECTION_EVIDENCE_INVALID");
        const validators = registry.validators;
        const eligible = validators.filter((entry) => entry && entry.status === "active" && typeof entry.validatorId === "string" &&
            entry.validatorId.length > 0 && Array.isArray(entry.signingKeys) && entry.signingKeys.some((key) => key && key.status === "active"))
            .map((entry) => entry.validatorId).sort(format.compare);
        if (new Set(eligible).size !== eligible.length)
            reject("SELECTION_EVIDENCE_INVALID");
        const envelopes = new Map();
        for (const raw of evidence.workerStatusEnvelopes) {
            const entry = exact(raw, ["validatorId", "envelopeHash", "envelope"]);
            const id = asString(entry.validatorId, "envelope validatorId");
            if (!/^[a-zA-Z0-9._:-]+$/u.test(id) || envelopes.has(id) || entry.envelopeHash !== canonicalHash(entry.envelope))
                reject("SELECTION_EVIDENCE_INVALID");
            envelopes.set(id, entry);
        }
        const selected = [], exclusions = [];
        const replayedEnvelopes = [];
        for (const id of eligible) {
            const entry = envelopes.get(id);
            if (entry === undefined) {
                exclusions.push({ validatorId: id, reason: "no_status_evidence" });
                continue;
            }
            replayedEnvelopes.push(entry);
            const reason = verifyHistoricalWorkerStatus(entry.envelope, id, registry, registryHash, validators, selectedAt, format.requiredCapabilities);
            if (reason === undefined)
                selected.push(id);
            else
                exclusions.push({ validatorId: id, reason });
        }
        if (selected.length < 5)
            reject("SELECTION_QUORUM_UNAVAILABLE");
        const requiredSignatures = Math.floor(selected.length * 2 / 3) + 1;
        if (canonicalize(eligible) !== canonicalize(evidence.eligibleValidatorIds) ||
            canonicalize(selected) !== canonicalize(evidence.selectedValidatorIds) ||
            requiredSignatures !== evidence.requiredSignatures ||
            canonicalize(exclusions) !== canonicalize(evidence.exclusions) ||
            canonicalize(replayedEnvelopes) !== canonicalize(evidence.workerStatusEnvelopes))
            reject("SELECTION_EVIDENCE_MISMATCH");
        return { evidenceHash: input.evidenceHash, selectedValidatorIds: selected, requiredSignatures };
    }
    catch (error) {
        if (error instanceof GmvHistoricalPriceErrorV1)
            throw error;
        return reject("SELECTION_EVIDENCE_INVALID");
    }
}
function timestamp(value) {
    const parsed = asString(value, "timestamp");
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(parsed) ||
        !Number.isFinite(Date.parse(parsed)) || new Date(parsed).toISOString() !== parsed)
        reject("SCHEMA_INVALID");
    return parsed;
}
function reproduceObservationSet(input, verified) {
    const aggregate = verified.aggregate;
    const set = exact(input.observationSet, ["domain", "schemaVersion", "networkId", "sourceProfileHash",
        "aggregationPolicyHash", "assignmentId", "assignmentHash", "windowStart", "windowEndExclusive", "reports"]);
    if (set.domain !== "crinkl:gmv:price-observation-set:v1" || set.schemaVersion !== 1 ||
        !Array.isArray(set.reports) || set.reports.length > 1024)
        reject("OBSERVATION_SET_INVALID");
    for (const field of ["networkId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId",
        "assignmentHash", "windowStart", "windowEndExclusive"]) {
        const expected = field === "networkId" ? aggregate.networkId :
            field === "sourceProfileHash" ? aggregate.source.sourceProfileHash :
                field === "aggregationPolicyHash" ? aggregate.aggregation.aggregationPolicyHash :
                    field === "assignmentId" ? aggregate.committee.assignmentId :
                        field === "assignmentHash" ? aggregate.committee.assignmentHash : aggregate.window[field];
        if (set[field] !== expected)
            reject("OBSERVATION_SET_BINDING_MISMATCH");
    }
    const reports = set.reports.map((raw) => exact(raw, ["version", "domain", "schemaVersion", "networkId",
        "validatorId", "keyId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId", "assignmentHash",
        "windowStart", "windowEndExclusive", "firstObservedAt", "lastObservedAt", "firstFinalizedSlot",
        "lastFinalizedSlot", "validSampleCount", "observedTwapMicroUsd", "latestEntryHash", "reportHash",
        "signatureAlgorithm", "signedDigestRule", "publicKey", "signature"]));
    const reportHashes = [], prices = [];
    let sampleCount = 0;
    const firstObservations = [], lastObservations = [];
    const firstSlots = [], lastSlots = [];
    for (const [index, report] of reports.entries()) {
        const id = asString(report.validatorId, "validatorId");
        if (index > 0 && Buffer.compare(Buffer.from(String(reports[index - 1].validatorId)), Buffer.from(id)) >= 0)
            reject("OBSERVATION_SIGNERS_INVALID");
        if (!aggregate.committee.selectedValidatorIds.includes(id))
            reject("OBSERVATION_SIGNERS_INVALID");
        if (report.version !== "GmvPriceCommitteeObservationReportV1" ||
            report.domain !== "crinkl:gmv:price-observation-report:v1" || report.schemaVersion !== 1 ||
            report.signatureAlgorithm !== "Ed25519" ||
            report.signedDigestRule !== "SIGN_RAW_32_BYTE_PRICE_OBSERVATION_REPORT_HASH")
            reject("OBSERVATION_REPORT_INVALID");
        for (const field of ["networkId", "sourceProfileHash", "aggregationPolicyHash", "assignmentId",
            "assignmentHash", "windowStart", "windowEndExclusive"])
            if (report[field] !== set[field])
                reject("OBSERVATION_REPORT_BINDING_MISMATCH");
        const first = Date.parse(timestamp(report.firstObservedAt)), last = Date.parse(timestamp(report.lastObservedAt));
        if (!(Date.parse(aggregate.window.windowStart) <= first && first <= last && last < Date.parse(aggregate.window.windowEndExclusive)))
            reject("OBSERVATION_REPORT_INVALID");
        const firstSlot = asNonNegativeInteger(report.firstFinalizedSlot, "firstFinalizedSlot");
        const lastSlot = asNonNegativeInteger(report.lastFinalizedSlot, "lastFinalizedSlot");
        if (firstSlot > lastSlot)
            reject("OBSERVATION_REPORT_INVALID");
        firstObservations.push(String(report.firstObservedAt));
        lastObservations.push(String(report.lastObservedAt));
        firstSlots.push(firstSlot);
        lastSlots.push(lastSlot);
        const count = asPositiveInteger(report.validSampleCount, "validSampleCount");
        if (count < aggregate.aggregation.minimumSamplesPerContributor)
            reject("OBSERVATION_REPORT_INVALID");
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
    const bytes = canonicalize(set);
    prices.sort((a, b) => a - b);
    if (reports.length < verified.requiredSignatures || reports.length !== aggregate.sampleCommitment.contributingValidatorCount ||
        !Number.isSafeInteger(sampleCount) || sampleCount !== aggregate.sampleCommitment.validSampleCount ||
        prices[Math.floor((prices.length - 1) / 2)] !== aggregate.aggregation.priceMicroUsdPerToken ||
        firstObservations.sort()[0] !== aggregate.window.firstObservedAt ||
        lastObservations.sort().at(-1) !== aggregate.window.lastObservedAt ||
        Math.min(...firstSlots) !== aggregate.window.firstFinalizedSlot ||
        Math.max(...lastSlots) !== aggregate.window.lastFinalizedSlot ||
        `sha256:${hashCanonicalValue(set)}` !== aggregate.sampleCommitment.observationSet.contentHash ||
        Buffer.byteLength(bytes) !== aggregate.sampleCommitment.observationSet.byteLength ||
        digest("CRINKL_GMV_PRICE_SAMPLE_SET_ROOT_V1", reportHashes) !== aggregate.sampleCommitment.sampleSetRoot)
        reject("OBSERVATION_SET_COMMITMENT_MISMATCH");
}
export function parseGmvHistoricalPriceSelectionV1(input) {
    try {
        const selection = exact(input, ["rule", "gmvWindowDay", "priceWindowDay", "registryNetworkId",
            "aggregateArtifactContentHash", "aggregateHash", "primaryLookup"]);
        const lookup = exact(selection.primaryLookup, ["status", "observedAt", "reason"]);
        const gmvWindowDay = asNonNegativeInteger(selection.gmvWindowDay, "gmvWindowDay");
        const priceWindowDay = asNonNegativeInteger(selection.priceWindowDay, "priceWindowDay");
        const direct = priceWindowDay === gmvWindowDay && lookup.status === "AVAILABLE" && lookup.reason === "DIRECT_PRICE";
        const fallback = priceWindowDay === gmvWindowDay - 1 && lookup.status === "UNAVAILABLE" &&
            (lookup.reason === "NOT_FOUND" || lookup.reason === "TRANSPORT_UNAVAILABLE");
        if (selection.rule !== "GMV_DAY_OR_PREVIOUS_DAY_V1" || (!direct && !fallback))
            reject("HISTORICAL_PRICE_SELECTION_INVALID");
        const registryNetworkId = asString(selection.registryNetworkId, "registryNetworkId");
        if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u.test(registryNetworkId))
            reject("HISTORICAL_PRICE_SELECTION_INVALID");
        return { rule: "GMV_DAY_OR_PREVIOUS_DAY_V1", gmvWindowDay, priceWindowDay, registryNetworkId,
            aggregateArtifactContentHash: asSha256Digest(selection.aggregateArtifactContentHash, "aggregateArtifactContentHash"),
            aggregateHash: asSha256Digest(selection.aggregateHash, "aggregateHash"),
            primaryLookup: { status: direct ? "AVAILABLE" : "UNAVAILABLE", observedAt: timestamp(lookup.observedAt),
                reason: direct ? "DIRECT_PRICE" : lookup.reason } };
    }
    catch (error) {
        if (error instanceof GmvHistoricalPriceErrorV1)
            throw error;
        return reject("HISTORICAL_PRICE_SELECTION_INVALID");
    }
}
/**
 * An existing aggregate's signed publication and observation-window-end dates
 * identify its fixing day. The original signed assignment and V1/V2 worker
 * selection retain their statement binding; the consuming burn does not
 * redefine it. Selection replay follows the V1 locale or V2 code-unit order
 * in crinkl-proof-validator 3542863ca3cb41103414202247c87523dc274e2d,
 * bin/lib/gmv-price-committee-selection.mjs.
 */
export function verifyGmvHistoricalPriceV1(input) {
    try {
        const selection = parseGmvHistoricalPriceSelectionV1(input.priceSelection), expected = input.expected;
        const registrySnapshot = asRecord(input.authenticatedCommittee.registrySnapshot, "authenticated registry snapshot");
        const expectedDay = asNonNegativeInteger(expected.gmvWindowDay, "expected.gmvWindowDay");
        if (selection.gmvWindowDay !== expectedDay || selection.registryNetworkId !== expected.registryNetworkId ||
            registrySnapshot.networkId !== expected.registryNetworkId)
            reject("HISTORICAL_PRICE_SCOPE_MISMATCH");
        const artifactPin = asSha256Digest(expected.aggregateArtifactContentHash, "expected artifact pin");
        const aggregatePin = asSha256Digest(expected.aggregateHash, "expected aggregate pin");
        if (selection.aggregateArtifactContentHash !== artifactPin || selection.aggregateHash !== aggregatePin)
            reject("HISTORICAL_PRICE_PIN_MISMATCH");
        const assignment = input.authenticatedCommittee.assignment;
        const originalBinding = /^gmv-price:([0-9a-f]{64}):([0-9a-f]{64})$/u.exec(assignment.assignmentId);
        const selectionHash = asSha256Digest(input.committeeSelectionEvidenceHash, "committee selection evidence hash");
        if (originalBinding === null || `sha256:${originalBinding[2]}` !== selectionHash)
            reject("ASSIGNMENT_SELECTION_MISMATCH");
        const originalStatementHash = `sha256:${originalBinding[1]}`;
        const evidence = asRecord(input.committeeSelectionEvidence, "historical selection evidence");
        const v1Capabilities = ["gmv_price_aggregate_v1", "gmv_price_aggregate_request_v2"];
        const v2Capabilities = [...v1Capabilities, "gmv_price_committee_selection_evidence_v2", "gmv_price_aggregate_request_v3"];
        if (evidence.version !== "GmvPriceCommitteeSelectionEvidenceV1" && evidence.version !== "GmvPriceCommitteeSelectionEvidenceV2")
            reject("SELECTION_EVIDENCE_INVALID");
        const replay = verifyPriceCommitteeSelection({ evidence, evidenceHash: selectionHash, subjectHash: originalStatementHash,
            authenticatedRegistrySnapshot: registrySnapshot, authenticatedRegistry: input.authenticatedCommittee.registry,
            authenticatedAssignmentSignedAtUnixMs: assignment.signedAtUnixMs }, {
            version: String(evidence.version), subjectField: "statementHash",
            requiredCapabilities: evidence.version === "GmvPriceCommitteeSelectionEvidenceV1" ? v1Capabilities : v2Capabilities,
            compare: evidence.version === "GmvPriceCommitteeSelectionEvidenceV1" ? (a, b) => a.localeCompare(b) : codeUnitCompare
        });
        if (canonicalize(replay.selectedValidatorIds) !== canonicalize(assignment.selectedValidatorIds))
            reject("ASSIGNMENT_SELECTION_MISMATCH");
        const set = asRecord(input.observationSet, "observation set");
        if (!Array.isArray(set.reports))
            reject("OBSERVATION_SET_INVALID");
        const sampleRoot = digest("CRINKL_GMV_PRICE_SAMPLE_SET_ROOT_V1", set.reports.map((entry) => asSha256Digest(asRecord(entry, "report").reportHash, "reportHash")));
        const verified = verifyGmvPriceAggregateV1({ aggregate: input.aggregate, registry: input.authenticatedCommittee.registry,
            resolvedArtifactContentHash: artifactPin, resolvedSampleSetRoot: sampleRoot });
        const aggregate = verified.aggregate;
        const policyFields = ["aggregationPolicyHash", "maximumPublicationDelaySeconds",
            "minimumPoolTvlMicroUsd", "minimumSamplesPerContributor", "toleranceBps"];
        const trustedPolicy = exact(expected.aggregationPolicy, policyFields);
        const aggregatePolicy = Object.fromEntries(policyFields.map((field) => [field, aggregate.aggregation[field]]));
        if (trustedPolicy.aggregationPolicyHash !== expected.aggregationPolicyHash ||
            canonicalize(trustedPolicy) !== canonicalize(aggregatePolicy))
            reject("HISTORICAL_PRICE_POLICY_MISMATCH");
        if (verified.aggregateHash !== aggregatePin || aggregate.networkId !== expected.priceNetworkId ||
            canonicalize(aggregate.source) !== canonicalize(expected.source) ||
            aggregate.aggregation.aggregationPolicyHash !== asSha256Digest(expected.aggregationPolicyHash, "expected aggregation policy hash") ||
            aggregate.committee.assignmentId !== assignment.assignmentId || aggregate.committee.assignmentHash !== assignment.assignmentHash ||
            canonicalize(aggregate.committee.selectedValidatorIds) !== canonicalize(assignment.selectedValidatorIds))
            reject("HISTORICAL_PRICE_SCOPE_MISMATCH");
        if (assignment.signedAtUnixMs > Date.parse(aggregate.publishedAt))
            reject("ASSIGNMENT_TIME_MISMATCH");
        const fixingWindowDay = Math.floor(Date.parse(aggregate.publishedAt) / 86400000);
        if (Math.floor(Date.parse(aggregate.window.windowEndExclusive) / 86400000) !== fixingWindowDay ||
            fixingWindowDay !== selection.priceWindowDay)
            reject("HISTORICAL_PRICE_DATE_MISMATCH");
        reproduceObservationSet(input, verified);
        if (asPositiveInteger(expected.priceMicroUsdPerToken, "expected priceMicroUsdPerToken") !== aggregate.aggregation.priceMicroUsdPerToken)
            reject("PRICE_VALUE_MISMATCH");
        return { ...verified, fixingWindowDay, priceSelection: selection, originalStatementHash,
            committeeSelectionEvidenceHash: selectionHash };
    }
    catch (error) {
        if (error instanceof GmvHistoricalPriceErrorV1 || (error instanceof Error && error.name === "GmvPriceAggregateErrorV1"))
            throw error;
        return reject("SCHEMA_INVALID");
    }
}
//# sourceMappingURL=dailyPriceV1.js.map