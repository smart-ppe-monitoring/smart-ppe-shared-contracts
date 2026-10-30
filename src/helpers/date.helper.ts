import {
  VIETNAM_TIMEZONE,
  VIETNAM_OFFSET_HOURS,
  VIETNAM_OFFSET_MS,
  VIETNAM_DATE_REGEX,
  ISO_DATE_REGEX,
} from "../constants/date.constant";

/**
 * Returns UTC Date boundaries for a given date in DD/MM/YYYY (Vietnamese standard)
 * or YYYY-MM-DD (ISO standard) format based on Vietnam time (UTC+7).
 *
 * Examples:
 *   '22/08/2026' (DD/MM/YYYY) ->
 *     startOfDay: 2026-08-21T17:00:00.000Z (which is 2026-08-22 00:00:00 UTC+7)
 *     endOfDay:   2026-08-22T16:59:59.999Z (which is 2026-08-22 23:59:59.999 UTC+7)
 *   '2026-08-22' (YYYY-MM-DD) ->
 *     startOfDay: 2026-08-21T17:00:00.000Z
 *     endOfDay:   2026-08-22T16:59:59.999Z
 */
export function getVietnamDayRange(dateString: string): {
  startOfDay: Date;
  endOfDay: Date;
} {
  let year: number;
  let month: number;
  let day: number;

  const vnMatch = dateString.match(VIETNAM_DATE_REGEX);
  const isoMatch = dateString.match(ISO_DATE_REGEX);

  if (vnMatch) {
    day = Number(vnMatch[1]);
    month = Number(vnMatch[2]);
    year = Number(vnMatch[3]);
  } else if (isoMatch) {
    year = Number(isoMatch[1]);
    month = Number(isoMatch[2]);
    day = Number(isoMatch[3]);
  } else {
    throw new Error(
      `Invalid date format for Vietnam day range: ${dateString}. Expected DD/MM/YYYY or YYYY-MM-DD.`,
    );
  }

  // Validate maximum days in month (including leap years)
  const maxDaysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (day > maxDaysInMonth) {
    throw new Error(
      `Invalid calendar day: ${day} exceeds maximum days (${maxDaysInMonth}) for month ${month}/${year}.`,
    );
  }

  // Create UTC date representing the local 00:00:00 in UTC+7
  const startOfDay = new Date(
    Date.UTC(year, month - 1, day, 0 - VIETNAM_OFFSET_HOURS, 0, 0, 0),
  );
  const endOfDay = new Date(
    Date.UTC(year, month - 1, day, 23 - VIETNAM_OFFSET_HOURS, 59, 59, 999),
  );

  return { startOfDay, endOfDay };
}

/**
 * Formats a Date to DD/MM/YYYY (default, Vietnamese standard) or YYYY-MM-DD in Vietnam timezone (UTC+7).
 * Trả về chuỗi rỗng nếu date không hợp lệ thay vì 'NaN/NaN/NaN' gây lỗi PostgreSQL 22007 (SEC-16).
 */
export function formatVietnamDate(
  date: Date,
  format: "DD/MM/YYYY" | "YYYY-MM-DD" = "DD/MM/YYYY",
): string {
  if (!date || !(date instanceof Date) || isNaN(date.getTime())) {
    return "";
  }
  const localDate = new Date(date.getTime() + VIETNAM_OFFSET_MS);
  const year = localDate.getUTCFullYear();
  const month = String(localDate.getUTCMonth() + 1).padStart(2, "0");
  const day = String(localDate.getUTCDate()).padStart(2, "0");

  if (format === "YYYY-MM-DD") {
    return `${year}-${month}-${day}`;
  }
  return `${day}/${month}/${year}`;
}

/**
 * Parses a date string in DD/MM/YYYY or YYYY-MM-DD format to a Date object in Vietnam time (00:00:00 UTC+7).
 */
export function parseVietnamDate(dateString: string): Date | null {
  try {
    return getVietnamDayRange(dateString).startOfDay;
  } catch {
    return null;
  }
}

/**
 * Formats a Date to readable Vietnamese datetime string (Asia/Ho_Chi_Minh).
 */
export function formatVietnamDateTime(date: Date): string {
  if (!date || !(date instanceof Date) || isNaN(date.getTime())) {
    return "";
  }
  return date.toLocaleString("vi-VN", { timeZone: VIETNAM_TIMEZONE });
}

/**
 * Maximum 32-bit signed integer delay for Node.js timers (setTimeout/setInterval).
 * Equivalent to ~24.8 days (2,147,483,647 ms).
 */
export const MAX_TIMEOUT_MS = 2147483647;

/**
 * Chuyển đổi chuỗi thời lượng (ví dụ: "15m", "1h", "7d", "30s") thành số milliseconds.
 * Nếu không khớp định dạng, trả về fallbackMs.
 * Đảm bảo giá trị trả về không vượt quá MAX_TIMEOUT_MS (2^31 - 1) để tránh tràn 32-bit timer trong Node.js (SEC-08).
 */
export function parseDurationToMs(
  duration: string | undefined | null,
  fallbackMs: number,
): number {
  const safeFallback = Math.min(fallbackMs, MAX_TIMEOUT_MS);
  if (!duration || typeof duration !== "string") return safeFallback;
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return safeFallback;
  const val = parseInt(match[1], 10);
  const unit = match[2];
  let ms: number;
  switch (unit) {
    case "s":
      ms = val * 1000;
      break;
    case "m":
      ms = val * 60 * 1000;
      break;
    case "h":
      ms = val * 60 * 60 * 1000;
      break;
    case "d":
      ms = val * 24 * 60 * 60 * 1000;
      break;
    default:
      return safeFallback;
  }
  return Math.min(ms, MAX_TIMEOUT_MS);
}
