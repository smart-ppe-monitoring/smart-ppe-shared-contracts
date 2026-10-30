import { uuidv7 } from "uuidv7";

/**
 * Generate a UUID v7 (time-ordered UUID).
 * UUIDv7 encodes a Unix timestamp in the most-significant bits,
 * making it monotonically sortable and friendlier to B-tree indexes.
 */
export { uuidv7 };

/** Alias: generate a new UUID v7 */
export const generateId = uuidv7;

/**
 * Regex matching standard 36-character hyphenated UUID strings (v1-v7: 8-4-4-4-12).
 * Sửa lỗi regex chấp nhận 36 dấu gạch nối (SEC-13).
 */
export const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Type guard verifying if an unknown value is a 36-character hyphenated UUID string.
 */
export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_REGEX.test(value);
}
