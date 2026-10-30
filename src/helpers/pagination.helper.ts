import { PaginationMeta } from "../types/pagination.type";

export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 20;
export const MAX_PAGINATION_LIMIT = 100;
export const MAX_PAGINATION_PAGE = 1_000_000;

/**
 * Standardize 1-indexed pagination parameters:
 * - page: integer >= 1 (defaults to 1, max 1000000)
 * - limit: integer between 1 and 100 (defaults to 20, max 100)
 */
export function calculatePaginationSkip(
  pageInput?: number,
  limitInput?: number,
  defaultLimit = DEFAULT_LIMIT,
): {
  skip: number;
  take: number;
  page: number;
  limit: number;
} {
  const numPage = Number(pageInput);
  const page = Number.isFinite(numPage)
    ? Math.min(MAX_PAGINATION_PAGE, Math.max(1, Math.floor(numPage)))
    : DEFAULT_PAGE;

  const numDefaultLimit = Number(defaultLimit);
  const safeDefaultLimit = Number.isFinite(numDefaultLimit)
    ? Math.min(MAX_PAGINATION_LIMIT, Math.max(1, Math.floor(numDefaultLimit)))
    : DEFAULT_LIMIT;

  const numLimit = Number(limitInput);
  const rawLimit = Number.isFinite(numLimit)
    ? Math.floor(numLimit)
    : safeDefaultLimit;
  const limit = Math.min(MAX_PAGINATION_LIMIT, Math.max(1, rawLimit));

  const rawSkip = (page - 1) * limit;
  const skip = Number.isSafeInteger(rawSkip) ? Math.max(0, rawSkip) : 0;

  return { skip, take: limit, page, limit };
}

/**
 * Format PaginationMeta object with (page, limit, total, totalPages)
 */
export function formatPaginationMeta(
  page: number,
  limit: number,
  total: number,
): PaginationMeta {
  const numPage = Number(page);
  const safePage = Number.isFinite(numPage)
    ? Math.min(MAX_PAGINATION_PAGE, Math.max(1, Math.floor(numPage)))
    : DEFAULT_PAGE;

  const numLimit = Number(limit);
  const safeLimit = Number.isFinite(numLimit)
    ? Math.min(MAX_PAGINATION_LIMIT, Math.max(1, Math.floor(numLimit)))
    : DEFAULT_LIMIT;

  const numTotal = Number(total);
  const safeTotal = Number.isFinite(numTotal)
    ? Math.max(0, Math.floor(numTotal))
    : 0;

  return {
    page: safePage,
    limit: safeLimit,
    total: safeTotal,
    totalPages: safeLimit > 0 ? Math.ceil(safeTotal / safeLimit) : 0,
  };
}
