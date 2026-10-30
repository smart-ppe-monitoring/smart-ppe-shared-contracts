import crypto from "node:crypto";

/**
 * Convert arbitrary text to URL-friendly slug.
 * Handles Vietnamese diacritics, strips invalid characters, and provides
 * a randomized fallback UUID if normalized slug is empty or input is invalid (SEC-21).
 */
export function toSlug(text?: string | null, fallback?: string): string {
  if (!text || typeof text !== "string") {
    return fallback || crypto.randomUUID();
  }

  const slug = text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d")
    .replace(/Đ/g, "d")
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, " ")
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  if (!slug) {
    return fallback || crypto.randomUUID();
  }

  return slug;
}
