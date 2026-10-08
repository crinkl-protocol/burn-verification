import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { test } from "node:test";
import { parseGmvHistoricalPriceSelectionV1, verifyGmvHistoricalPriceV1 } from "../dist/index.js";
import { canonicalize } from "../dist/canonical.js";

// Public signed evidence, frozen from the Sep25 fixing archive. Private keys
// are absent. Compression retains portable exact evidence and provenance.
// Artifact sha256:c7196712680539549c2d9978f3853b066f17f93bec961e2dc8c0e9824e000647.
const fixture = JSON.parse(gunzipSync(Buffer.from("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", "base64")));
const contentHash = (value) => `sha256:${createHash("sha256").update(canonicalize(value)).digest("hex")}`;
const day = Date.parse("2026-09-25T00:00:00.000Z") / 86400000;
function historicalInput() {
  const { aggregate, authorityEvidence: evidence, observationSet, committeeSelectionEvidence } = structuredClone(fixture);
  const registry = { registrySequence: evidence.registry.registrySequence, registryHash: aggregate.committee.registryHash,
    keys: evidence.registry.validators.flatMap((validator) => validator.signingKeys.map((key) => ({
      validatorId: validator.validatorId, keyId: key.signingKeyId,
      publicKey: Buffer.from(createPublicKey(key.publicKeyPem).export({format:"der",type:"spki"})).subarray(-32).toString("base64"),
      active: validator.status === "active" && key.status === "active"
    }))) };
  const artifactPin = "sha256:c7196712680539549c2d9978f3853b066f17f93bec961e2dc8c0e9824e000647";
  return { aggregate, observationSet, committeeSelectionEvidence,
    committeeSelectionEvidenceHash: contentHash(committeeSelectionEvidence),
    authenticatedCommittee: { registry, registrySnapshot: evidence.registry,
      assignment: { assignmentId: evidence.assignment.assignmentId, assignmentHash: aggregate.committee.assignmentHash,
        selectedValidatorIds: evidence.assignment.selectedValidatorIds, signedAtUnixMs: evidence.signedAssignment.signedAtUnixMs } },
    priceSelection: { rule: "GMV_DAY_OR_PREVIOUS_DAY_V1", gmvWindowDay: day, priceWindowDay: day,
      registryNetworkId: "crinkl-devnet", aggregateArtifactContentHash: artifactPin, aggregateHash: aggregate.aggregateHash,
      primaryLookup: { status: "AVAILABLE", observedAt: "2026-10-09T00:00:00.000Z", reason: "DIRECT_PRICE" } },
    expected: { gmvWindowDay: day, priceNetworkId: "solana-devnet", registryNetworkId: "crinkl-devnet",
      source: structuredClone(aggregate.source), aggregationPolicyHash: aggregate.aggregation.aggregationPolicyHash,
      aggregationPolicy: Object.fromEntries(["aggregationPolicyHash", "maximumPublicationDelaySeconds",
        "minimumPoolTvlMicroUsd", "minimumSamplesPerContributor", "toleranceBps"].map(field=>[field,aggregate.aggregation[field]])),
      aggregateArtifactContentHash: artifactPin, aggregateHash: aggregate.aggregateHash, priceMicroUsdPerToken: 101356 } };
}
function repinArtifact(input) {
  const pin=contentHash(input.aggregate);
  input.priceSelection.aggregateArtifactContentHash=pin; input.expected.aggregateArtifactContentHash=pin;
}
function fallback(input, reason="NOT_FOUND") {
  input.priceSelection.gmvWindowDay=day+1; input.expected.gmvWindowDay=day+1;
  input.priceSelection.primaryLookup={status:"UNAVAILABLE",observedAt:"2026-10-10T00:00:00.000Z",reason};
}
function rebindSelection(input) {
  input.committeeSelectionEvidenceHash=contentHash(input.committeeSelectionEvidence);
  const originalStatement=input.authenticatedCommittee.assignment.assignmentId.split(":")[1];
  input.authenticatedCommittee.assignment.assignmentId=`gmv-price:${originalStatement}:${input.committeeSelectionEvidenceHash.slice(7)}`;
}

test("existing Sep25 signed price verifies for Sep25 GMV consumed on Oct9",()=>{
  const input=historicalInput(), result=verifyGmvHistoricalPriceV1(input);
  assert.equal(result.fixingWindowDay,day);
  assert.equal(result.aggregate.aggregation.priceMicroUsdPerToken,101356);
  assert.equal(result.validDistinctSignatureCount,4);
  assert.equal(result.requiredSignatures,4);
  assert.equal(result.originalStatementHash,"sha256:64cee1c2f407a408847438acb1e4943997675bb6d70e549e1becb42c92510dbe");
  assert.notEqual(result.aggregate.networkId,input.authenticatedCommittee.registrySnapshot.networkId);
});
for(const reason of ["NOT_FOUND","TRANSPORT_UNAVAILABLE"]) test(`verified previous-day price accepts bounded primary lookup ${reason}`,()=>{
  const input=historicalInput(); fallback(input,reason);
  const result=verifyGmvHistoricalPriceV1(input);
  assert.equal(result.fixingWindowDay,result.priceSelection.gmvWindowDay-1);
  assert.equal(result.priceSelection.primaryLookup.reason,reason);
});
for(const delta of [-1,1]) test(`historical consumer rejects ${delta} micro-USD price difference`,()=>{
  const input=historicalInput(); input.expected.priceMicroUsdPerToken+=delta;
  assert.throws(()=>verifyGmvHistoricalPriceV1(input),/PRICE_VALUE_MISMATCH/);
});
const mutations=[
  ["wrong expected GMV day",i=>{i.expected.gmvWindowDay++;},"HISTORICAL_PRICE_SCOPE_MISMATCH"],
  ["trigger-day price selection",i=>{i.priceSelection.priceWindowDay=Date.parse("2026-10-09T00:00:00.000Z")/86400000;},"HISTORICAL_PRICE_SELECTION_INVALID"],
  ["more than one previous day",i=>{fallback(i);i.priceSelection.gmvWindowDay++;i.expected.gmvWindowDay++;},"HISTORICAL_PRICE_SELECTION_INVALID"],
  ["fallback without unavailable lookup",i=>{i.priceSelection.gmvWindowDay++;i.expected.gmvWindowDay++;},"HISTORICAL_PRICE_SELECTION_INVALID"],
  ["invalid primary as fallback reason",i=>{fallback(i,"INVALID_SIGNATURE");},"HISTORICAL_PRICE_SELECTION_INVALID"],
  ["wrong chain network",i=>{i.expected.priceNetworkId="another-chain-network";},"HISTORICAL_PRICE_SCOPE_MISMATCH"],
  ["wrong registry network",i=>{i.expected.registryNetworkId="another-registry-network";},"HISTORICAL_PRICE_SCOPE_MISMATCH"],
  ["wrong accepted full source",i=>{i.expected.source.poolId="different-pool";},"HISTORICAL_PRICE_SCOPE_MISMATCH"],
  ["wrong accepted policy",i=>{i.expected.aggregationPolicyHash=`sha256:${"0".repeat(64)}`;},"HISTORICAL_PRICE_POLICY_MISMATCH"],
  ["lookup predating selected price publication",i=>{i.priceSelection.primaryLookup.observedAt="2026-09-25T00:11:25.694Z";},"HISTORICAL_PRICE_LOOKUP_TIME_MISMATCH"],
  ["missing trusted full policy",i=>{delete i.expected.aggregationPolicy;},"SCHEMA_INVALID"],
  ["weakened trusted sample policy",i=>{i.expected.aggregationPolicy.minimumSamplesPerContributor++;},"HISTORICAL_PRICE_POLICY_MISMATCH"],
  ["weakened trusted publication delay",i=>{i.expected.aggregationPolicy.maximumPublicationDelaySeconds++;},"HISTORICAL_PRICE_POLICY_MISMATCH"],
  ["different trusted minimum pool TVL",i=>{i.expected.aggregationPolicy.minimumPoolTvlMicroUsd="1000001";},"HISTORICAL_PRICE_POLICY_MISMATCH"],
  ["different trusted formation tolerance",i=>{i.expected.aggregationPolicy.toleranceBps++;},"HISTORICAL_PRICE_POLICY_MISMATCH"],
  ["extra trusted policy field",i=>{i.expected.aggregationPolicy.allowUnchecked=true;},"SCHEMA_INVALID"],
  ["switch from an existing immutable artifact pin",i=>{i.expected.aggregateArtifactContentHash=`sha256:${"0".repeat(64)}`;},"HISTORICAL_PRICE_PIN_MISMATCH"],
  ["wrong pinned aggregate hash",i=>{i.expected.aggregateHash=`sha256:${"0".repeat(64)}`;},"HISTORICAL_PRICE_PIN_MISMATCH"],
  ["tampered observation price",i=>{i.observationSet.reports[0].observedTwapMicroUsd++;},"OBSERVATION_SIGNATURE_INVALID"],
  ["missing independent observation bytes",i=>{delete i.observationSet;},"SCHEMA_INVALID"],
  ["invalid aggregate signature",i=>{i.aggregate.signatures[0].signature=Buffer.alloc(64).toString("base64");repinArtifact(i);},"SIGNATURE_INVALID"],
  ["invalid aggregate proof even when fallback requested",i=>{fallback(i);i.aggregate.signatures[0].signature=Buffer.alloc(64).toString("base64");repinArtifact(i);},"SIGNATURE_INVALID"],
  ["insufficient quorum",i=>{i.aggregate.signatures.pop();repinArtifact(i);},"SIGNATURE_QUORUM_UNSATISFIED"],
  ["duplicate active signing key",i=>{const active=i.authenticatedCommittee.registry.keys.filter(key=>key.active);active[1].publicKey=active[0].publicKey;},"DUPLICATE_SIGNING_KEY"],
  ["fabricated retrospective daily assignment",i=>{i.authenticatedCommittee.assignment.assignmentId="gmv-price-day:made-up";},"ASSIGNMENT_SELECTION_MISMATCH"],
  ["rebound original statement hash",i=>{i.committeeSelectionEvidence.statementHash=`sha256:${"0".repeat(64)}`;rebindSelection(i);},"SELECTION_EVIDENCE_INVALID"],
  ["tampered selection roster",i=>{i.committeeSelectionEvidence.selectedValidatorIds.reverse();rebindSelection(i);},"SELECTION_EVIDENCE_MISMATCH"],
  ["weakened selection floor",i=>{i.committeeSelectionEvidence.minimumCommitteeSize=1;rebindSelection(i);},"SELECTION_EVIDENCE_INVALID"],
  ["stale signed selection",i=>{i.authenticatedCommittee.assignment.signedAtUnixMs+=1800001;},"SELECTION_EVIDENCE_INVALID"],
  ["extra selection field",i=>{i.priceSelection.allowInvalidPrimary=true;},"HISTORICAL_PRICE_SELECTION_INVALID"],
  ["malformed lookup timestamp",i=>{i.priceSelection.primaryLookup.observedAt="yesterday";},"SCHEMA_INVALID"]
];
for(const[name,mutate,reason]of mutations)test(`historical verifier rejects ${name}`,()=>{
  const input=historicalInput();mutate(input);assert.throws(()=>verifyGmvHistoricalPriceV1(input),new RegExp(reason));
});
for(const malformed of [null,{},[],"day",-1])test(`historical selection rejects malformed ${JSON.stringify(malformed)}`,()=>{
  assert.throws(()=>parseGmvHistoricalPriceSelectionV1(malformed),/HISTORICAL_PRICE_SELECTION_INVALID/);
});
if(process.env.CRINKL_PRICE_SELECTION_REFERENCE)test("historical selection replay matches validator V2 source for real Sep25 evidence",async()=>{
  const reference=await import(pathToFileURL(process.env.CRINKL_PRICE_SELECTION_REFERENCE).href);
  const input=historicalInput(), actual=verifyGmvHistoricalPriceV1(input);
  const replay=reference.verifyGmvPriceCommitteeSelectionEvidenceV2({evidence:input.committeeSelectionEvidence,
    evidenceHash:input.committeeSelectionEvidenceHash,registry:input.authenticatedCommittee.registrySnapshot,
    statementHash:actual.originalStatementHash,nowUnixMs:input.authenticatedCommittee.assignment.signedAtUnixMs});
  assert.deepEqual(replay.selection.validatorIds,actual.aggregate.committee.selectedValidatorIds);
  assert.equal(replay.selection.requiredSignatures,actual.requiredSignatures);
});
if(process.env.CRINKL_REAL_PRICE_ARCHIVE && process.env.CRINKL_PRICE_AUTHENTICATION_MODULE)
test("named Sep25 archive replays with independently pinned network authority",async()=>{
  const archive=process.env.CRINKL_REAL_PRICE_ARCHIVE;
  const authentication=await import(pathToFileURL(process.env.CRINKL_PRICE_AUTHENTICATION_MODULE).href);
  const read=(name)=>JSON.parse(readFileSync(join(archive,name),"utf8"));
  const key="c7196712680539549c2d9978f3853b066f17f93bec961e2dc8c0e9824e000647";
  const evidence=read(`${key}.authority-evidence.json`);
  const authorityPin=JSON.parse(readFileSync(join(dirname(archive),"registry-authority.json"),"utf8")).publicKeyHash;
  const authenticated=authentication.authenticateGmvPriceCommitteeV1({expectedAuthorityPublicKeyHash:authorityPin,...evidence});
  const input=historicalInput();
  input.aggregate=read(`${key}.json`);input.observationSet=read(`${key}.observation-set.json`);
  const selectionKey=evidence.assignment.assignmentId.split(":")[2];
  input.committeeSelectionEvidence=read(`${selectionKey}.committee-selection.json`);
  input.committeeSelectionEvidenceHash=`sha256:${selectionKey}`;
  input.authenticatedCommittee={...authenticated,registrySnapshot:evidence.registry,
    assignment:{...authenticated.assignment,signedAtUnixMs:evidence.signedAssignment.signedAtUnixMs}};
  const verified=verifyGmvHistoricalPriceV1(input);
  console.log("REPLAY_RECEIPT "+JSON.stringify({artifactContentHash:verified.artifactContentHash,
    aggregateHash:verified.aggregateHash,originalStatementHash:verified.originalStatementHash,
    priceMicroUsdPerToken:verified.aggregate.aggregation.priceMicroUsdPerToken,
    fixingDate:new Date(verified.fixingWindowDay*86400000).toISOString().slice(0,10),
    signatureQuorum:`${verified.validDistinctSignatureCount}/${verified.requiredSignatures}`,
    priceNetworkId:verified.aggregate.networkId,registryNetworkId:evidence.registry.networkId}));
});
