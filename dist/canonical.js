import { createHash } from "node:crypto";
export function canonicalize(value) {
    if (value === null) {
        return "null";
    }
    if (typeof value === "string" || typeof value === "boolean") {
        return JSON.stringify(value);
    }
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
            throw new Error("Canonical numbers must be safe integers without negative zero");
        }
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
    }
    const objectValue = value;
    const keys = Object.keys(objectValue).sort();
    const fields = keys.map((key) => {
        const fieldValue = objectValue[key];
        if (fieldValue === undefined) {
            throw new Error(`Canonical object field ${key} is undefined`);
        }
        return `${JSON.stringify(key)}:${canonicalize(fieldValue)}`;
    });
    return `{${fields.join(",")}}`;
}
export function sha256Hex(input) {
    return createHash("sha256").update(input, "utf8").digest("hex");
}
export function sha256BytesHex(input) {
    return createHash("sha256").update(input).digest("hex");
}
export function hashCanonicalValue(value) {
    return sha256Hex(canonicalize(value));
}
export function asRecord(value, fieldName) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`${fieldName} must be an object`);
    }
    return value;
}
export function assertExactKeys(value, expectedKeys, fieldName) {
    const expected = [...expectedKeys].sort();
    const actual = Object.keys(value).sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
        throw new Error(`${fieldName} has unexpected keys: expected ${expected.join(",")}; got ${actual.join(",")}`);
    }
}
export function assertExactKeysWithOptional(value, requiredKeys, optionalKeys, fieldName) {
    const allowed = new Set([...requiredKeys, ...optionalKeys]);
    const actual = Object.keys(value).sort();
    const missing = requiredKeys.filter((key) => !Object.hasOwn(value, key));
    const unexpected = actual.filter((key) => !allowed.has(key));
    if (missing.length > 0 || unexpected.length > 0) {
        throw new Error(`${fieldName} key mismatch: missing ${missing.join(",") || "none"}; unexpected ${unexpected.join(",") || "none"}`);
    }
}
export function asString(value, fieldName) {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error(`${fieldName} must be a non-empty string`);
    }
    return value;
}
export function asSha256Digest(value, fieldName) {
    const digest = asString(value, fieldName);
    if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) {
        throw new Error(`${fieldName} must be a canonical sha256 digest`);
    }
    return digest;
}
export function asOptionalString(value, fieldName) {
    if (value === undefined) {
        return undefined;
    }
    return asString(value, fieldName);
}
export function asInteger(value, fieldName) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new Error(`${fieldName} must be a safe integer`);
    }
    return value;
}
export function asNonNegativeInteger(value, fieldName) {
    const parsed = asInteger(value, fieldName);
    if (parsed < 0) {
        throw new Error(`${fieldName} must be non-negative`);
    }
    return parsed;
}
export function asPositiveInteger(value, fieldName) {
    const parsed = asInteger(value, fieldName);
    if (parsed <= 0) {
        throw new Error(`${fieldName} must be positive`);
    }
    return parsed;
}
export function asStringLiteral(value, allowed, fieldName) {
    const candidate = asString(value, fieldName);
    if (!allowed.includes(candidate)) {
        throw new Error(`${fieldName} must be one of ${allowed.join(",")}`);
    }
    return candidate;
}
export function asArray(value, fieldName, parseEntry) {
    if (!Array.isArray(value)) {
        throw new Error(`${fieldName} must be an array`);
    }
    return value.map((entry, index) => parseEntry(entry, index));
}
//# sourceMappingURL=canonical.js.map