export type CanonicalScalar = null | boolean | number | string;
export type CanonicalValue = CanonicalScalar | readonly CanonicalValue[] | {
    readonly [key: string]: CanonicalValue;
};
export declare function canonicalize(value: CanonicalValue): string;
export declare function sha256Hex(input: string): string;
export declare function sha256BytesHex(input: Uint8Array): string;
export declare function hashCanonicalValue(value: CanonicalValue): string;
export declare function asRecord(value: unknown, fieldName: string): Record<string, unknown>;
export declare function assertExactKeys(value: Record<string, unknown>, expectedKeys: readonly string[], fieldName: string): void;
export declare function assertExactKeysWithOptional(value: Record<string, unknown>, requiredKeys: readonly string[], optionalKeys: readonly string[], fieldName: string): void;
export declare function asString(value: unknown, fieldName: string): string;
export type Sha256Digest = `sha256:${string}`;
export declare function asSha256Digest(value: unknown, fieldName: string): Sha256Digest;
export declare function asOptionalString(value: unknown, fieldName: string): string | undefined;
export declare function asInteger(value: unknown, fieldName: string): number;
export declare function asNonNegativeInteger(value: unknown, fieldName: string): number;
export declare function asPositiveInteger(value: unknown, fieldName: string): number;
export declare function asStringLiteral<const T extends readonly string[]>(value: unknown, allowed: T, fieldName: string): T[number];
export declare function asArray<T>(value: unknown, fieldName: string, parseEntry: (entry: unknown, index: number) => T): T[];
//# sourceMappingURL=canonical.d.ts.map