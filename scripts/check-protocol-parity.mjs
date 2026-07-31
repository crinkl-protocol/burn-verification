#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const provenance = JSON.parse(
  readFileSync(resolve(packageRoot, "protocol-provenance.json"), "utf8")
);

function option(name, environmentName, fallback) {
  const index = process.argv.indexOf(name);
  if (index !== -1) {
    const value = process.argv[index + 1];
    assert.ok(value && !value.startsWith("--"), `${name} requires a value`);
    return value;
  }
  return process.env[environmentName] ?? fallback;
}

const protocolRepo = option(
  "--protocol-repo",
  "CRINKL_PROTOCOL_REPO",
  "../crinkl-protocol"
);
const protocolRef = option(
  "--protocol-ref",
  "CRINKL_PROTOCOL_REF",
  provenance.adoptedProtocol.mergeCommit
);
const specificationRepo = option(
  "--spec-repo",
  "CRINKL_PROTOCOL_SPEC_REPO",
  "../crinkl-protocol-spec"
);
const specificationRef = option(
  "--spec-ref",
  "CRINKL_PROTOCOL_SPEC_REF",
  provenance.publicSpecification.mergeCommit
);
assert.ok(!protocolRef.startsWith("-"), "protocol ref must not start with '-'");
assert.ok(
  !specificationRef.startsWith("-"),
  "public specification ref must not start with '-'"
);

function git(repo, ...args) {
  return execFileSync("git", ["-C", resolve(repo), ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function assertContainsCommit(repo, ref, commit, authority) {
  try {
    git(repo, "merge-base", "--is-ancestor", commit, ref);
  } catch {
    assert.fail(`${authority} ref ${ref} does not contain provenance commit ${commit}`);
  }
}

function gitFile(repo, ref, file) {
  return git(repo, "show", `${ref}:${file}`);
}

function orderedReasons(source) {
  const match = source.match(
    /export const GMV_PRICE_AGGREGATE_REASONS_V1 = \[([\s\S]*?)\](?: as const)?;/
  );
  assert.ok(match, "shared verifier reason vocabulary is present");
  return Array.from(match[1].matchAll(/"([A-Z0-9_]+)"/g), (entry) => entry[1]);
}

function specificationReasons(source) {
  const match = source.match(
    /Aggregate verification \(code `GMV_PRICE_AGGREGATE_INVALID`\):\s*\n\s*\n([^\n]+)/
  );
  assert.ok(match, "public specification aggregate reason vocabulary is present");
  return Array.from(match[1].matchAll(/`([A-Z0-9_]+)`/g), (entry) => entry[1]);
}

function numberedChecks(source) {
  return Array.from(
    source.matchAll(/^(\d+)\.\s+\*\*([^*]+)\*\*(?:[.,])?\s+(.+)$/gm),
    (entry) => ({
      number: Number(entry[1]),
      name: entry[2].replace(/[.,]$/, ""),
      body: entry[3]
    })
  );
}

assert.equal(
  provenance.schema,
  "CrinklBurnVerificationProtocolProvenanceV1",
  "protocol provenance schema"
);
assert.equal(
  provenance.publicSpecification.maturity,
  "draft",
  "public specification maturity remains explicit"
);
assert.match(
  provenance.adoptedProtocol.mergeCommit,
  /^[0-9a-f]{40}$/,
  "adopted protocol provenance uses a full commit"
);
assert.match(
  provenance.publicSpecification.mergeCommit,
  /^[0-9a-f]{40}$/,
  "public specification provenance uses a full commit"
);

assertContainsCommit(
  protocolRepo,
  protocolRef,
  provenance.adoptedProtocol.mergeCommit,
  "adopted protocol"
);
assertContainsCommit(
  specificationRepo,
  specificationRef,
  provenance.publicSpecification.mergeCommit,
  "public specification"
);

const protocolRule = gitFile(
  protocolRepo,
  protocolRef,
  provenance.adoptedProtocol.ruleDocument
);
const protocolVectors = JSON.parse(
  gitFile(
    protocolRepo,
    protocolRef,
    provenance.adoptedProtocol.vectorManifest
  )
);
const specificationFormat = gitFile(
  specificationRepo,
  specificationRef,
  provenance.publicSpecification.formatDocument
);
const specificationConformance = gitFile(
  specificationRepo,
  specificationRef,
  provenance.publicSpecification.conformanceDocument
);
const verifierSourcePath = existsSync(resolve(packageRoot, "src/priceAggregateV1.ts"))
  ? resolve(packageRoot, "src/priceAggregateV1.ts")
  : resolve(packageRoot, "dist/priceAggregateV1.js");
const verifierSource = readFileSync(verifierSourcePath, "utf8");

assert.match(
  protocolRule,
  /contributingValidatorCount` names validators drawn from[\s\S]*?MUST NOT claim more[\s\S]*?strictly greater[\s\S]*?`SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE`[\s\S]*?Equality is valid:/,
  "adopted protocol states the strict contributor bound and equality boundary"
);

const vector = protocolVectors.rejectCases.find(
  (candidate) => candidate.id === provenance.adoptedProtocol.vectorId
);
assert.ok(vector, "adopted protocol contributor-bound vector is present");
assert.equal(vector.code, "GMV_PRICE_AGGREGATE_INVALID");
assert.equal(vector.reason, "SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE");
assert.match(
  vector.mutation,
  /committee size \+ 1[\s\S]*signatures[\s\S]*only violated invariant/,
  "adopted vector isolates the contributor bound"
);

assert.match(
  specificationFormat,
  /contributingValidatorCount` \| integer \| Positive and no greater than `committee\.selectedValidatorIds\.length`; equality is valid\./,
  "public format states the non-strict equality boundary"
);
assert.match(
  specificationFormat,
  /Contributor bound:\s*`contributingValidatorCount <= committee\.selectedValidatorIds\.length`\./,
  "public format states the contributor formula"
);

const checks = numberedChecks(specificationConformance);
assert.deepEqual(
  checks.map(({ number }) => number),
  Array.from({ length: 17 }, (_, index) => index + 1),
  "public conformance checks are contiguous"
);
assert.match(checks[5].body, /PUBLICATION_WINDOW_INVALID/);
assert.equal(checks[6].name, "Sample contributor bound");
assert.match(
  checks[6].body,
  /contributingValidatorCount <= n[\s\S]*equality is valid[\s\S]*SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE/
);
assert.match(checks[7].body, /SAMPLE_FLOOR_UNSATISFIED/);
assert.match(checks[8].body, /SAMPLE_ROOT_MISMATCH/);
assert.match(checks[16].body, /SIGNATURE_QUORUM_UNSATISFIED/);

const verifierReasons = orderedReasons(verifierSource);
const publicReasons = specificationReasons(specificationConformance);
assert.deepEqual(
  verifierReasons.slice(0, publicReasons.length),
  publicReasons,
  "shared verifier aggregate reasons match the public closed vocabulary and order"
);
assert.equal(
  verifierReasons[publicReasons.length],
  "CANDIDATE_V4_PROJECTION_INVALID",
  "the public closed aggregate vocabulary ends at the candidate-binding boundary"
);

const publicationIndex = verifierSource.indexOf(
  'return fail("PUBLICATION_WINDOW_INVALID")'
);
const contributorCheckIndex = verifierSource.indexOf(
  "aggregate.sampleCommitment.contributingValidatorCount > selected.length"
);
const contributorReasonIndex = verifierSource.indexOf(
  'return fail("SAMPLE_CONTRIBUTORS_EXCEED_COMMITTEE")',
  contributorCheckIndex
);
const floorIndex = verifierSource.indexOf(
  'return fail("SAMPLE_FLOOR_UNSATISFIED")',
  contributorReasonIndex
);
const rootIndex = verifierSource.indexOf(
  '"SAMPLE_ROOT_MISMATCH"',
  floorIndex
);
assert.ok(publicationIndex >= 0, "publication-window check is present");
assert.ok(
  contributorCheckIndex > publicationIndex,
  "contributor bound follows publication"
);
assert.ok(
  contributorReasonIndex > contributorCheckIndex,
  "strict greater-than check emits the contributor reason"
);
assert.ok(floorIndex > contributorReasonIndex, "sample floor follows contributor bound");
assert.ok(rootIndex > floorIndex, "sample root follows sample floor");

const protocolHead = git(protocolRepo, "rev-parse", protocolRef).trim();
const specificationHead = git(
  specificationRepo,
  "rev-parse",
  specificationRef
).trim();
console.log(
  `OK protocol=${protocolHead} specification=${specificationHead} reasons=${publicReasons.length} checks=${checks.length}`
);
