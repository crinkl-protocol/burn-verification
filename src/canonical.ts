import { createHash } from "node:crypto";

export type CanonicalScalar = null | boolean | number | string;

export type CanonicalValue =
  | CanonicalScalar
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

export function canonicalize(value: CanonicalValue): string {
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

  const objectValue = value as { readonly [key: string]: CanonicalValue };
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

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function sha256BytesHex(input: Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function hashCanonicalValue(value: CanonicalValue): string {
  return sha256Hex(canonicalize(value));
}

export function asRecord(value: unknown, fieldName: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function assertExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
  fieldName: string
): void {
  const expected = [...expectedKeys].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${fieldName} has unexpected keys: expected ${expected.join(",")}; got ${actual.join(",")}`);
  }
}

export function assertExactKeysWithOptional(
  value: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  fieldName: string
): void {
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  const actual = Object.keys(value).sort();
  const missing = requiredKeys.filter((key) => !Object.hasOwn(value, key));
  const unexpected = actual.filter((key) => !allowed.has(key));

  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${fieldName} key mismatch: missing ${missing.join(",") || "none"}; unexpected ${
        unexpected.join(",") || "none"
      }`
    );
  }
}

export function asString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value;
}

export type Sha256Digest = `sha256:${string}`;

export function asSha256Digest(value: unknown, fieldName: string): Sha256Digest {
  const digest = asString(value, fieldName);
  if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) {
    throw new Error(`${fieldName} must be a canonical sha256 digest`);
  }
  return digest as Sha256Digest;
}

export function asOptionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return asString(value, fieldName);
}

export function asInteger(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0)) {
    throw new Error(`${fieldName} must be a safe integer`);
  }
  return value;
}

export function asNonNegativeInteger(value: unknown, fieldName: string): number {
  const parsed = asInteger(value, fieldName);
  if (parsed < 0) {
    throw new Error(`${fieldName} must be non-negative`);
  }
  return parsed;
}

export function asPositiveInteger(value: unknown, fieldName: string): number {
  const parsed = asInteger(value, fieldName);
  if (parsed <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return parsed;
}

export function asStringLiteral<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  fieldName: string
): T[number] {
  const candidate = asString(value, fieldName);
  if (!allowed.includes(candidate)) {
    throw new Error(`${fieldName} must be one of ${allowed.join(",")}`);
  }
  return candidate;
}

export function asArray<T>(value: unknown, fieldName: string, parseEntry: (entry: unknown, index: number) => T): T[] {
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => parseEntry(entry, index));
}
