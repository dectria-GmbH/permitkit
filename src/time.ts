import {
  daysInMonth,
  isFiniteNumber,
  matches,
  parseDate,
  sliceText,
  toNumber,
} from "./intrinsics.js";
import { fail, type Check, type Issue, type Path } from "./validate.js";

/**
 * ISO 8601 date-time with seconds, at most millisecond precision and an explicit offset in
 * the range of the ECMAScript date-time format. Wider forms (offsets above 23:59, offsets
 * without a colon, more fraction digits) parse differently or not at all across engines, so
 * they are rejected.
 */
const isoInstant =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,3})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$/;

/** The longest approval window that a policy can set, in seconds (31 days). */
export const maxApprovalWindowSeconds = 31 * 24 * 3600;

/**
 * The earliest and latest accepted instants. Inside this range, the UTC form of every timestamp
 * has a four-digit year, so a normalized time (`toISOString()`) is again a valid timestamp.
 * An offset can move a local time across a bound: `0000-01-01T00:30:00+01:00` is in year -1.
 */
export const earliestInstant = Date.parse("0000-01-01T00:00:00.000Z");
export const latestInstant = Date.parse("9999-12-31T23:59:59.999Z");

/**
 * The latest accepted request time. The end of the longest approval window after it is still
 * inside the accepted range, so `approval.expiresAt` is always a valid timestamp.
 */
export const latestRequestInstant = latestInstant - maxApprovalWindowSeconds * 1000;

const timestampMessage =
  "Use an ISO 8601 date-time with an offset, for example 2026-01-15T10:00:00Z.";

/** A timestamp between 0000-01-01T00:00:00Z and 9999-12-31T23:59:59.999Z. */
export const timestamp: Check<string> = (value, path, issues) =>
  checkTimestamp(value, path, issues, latestInstant);

/**
 * A request or evaluation time. It ends 31 days before the latest timestamp, so the end of an
 * approval window that starts at it can still be written as a timestamp.
 */
export const requestTime: Check<string> = (value, path, issues) =>
  checkTimestamp(value, path, issues, latestRequestInstant);

/** Format first, then the calendar day, then the range, as the earlier schema did. */
function checkTimestamp(value: unknown, path: Path, issues: Issue[], latest: number) {
  if (typeof value !== "string") return fail(issues, path, timestampMessage);
  if (!matches(isoInstant, value)) return fail(issues, path, timestampMessage);
  if (!isCalendarInstant(value)) return fail(issues, path, "The date-time does not exist.");
  if (!inRange(value, latestInstant)) {
    return fail(
      issues,
      path,
      "The date-time must be between 0000-01-01T00:00:00Z and 9999-12-31T23:59:59.999Z.",
    );
  }
  if (!inRange(value, latest)) {
    return fail(issues, path, "A request time must be at most 9999-11-30T23:59:59.999Z.");
  }
  return value;
}

function inRange(value: string, latest: number): boolean {
  const time = parseDate(value);
  // Written so that an unreadable time fails the check.
  return time >= earliestInstant && time <= latest;
}

/**
 * Rejects days that the month does not have. V8 reads 2026-02-30 as 2 March, other engines
 * return NaN, so the day is checked here instead of trusting Date.parse.
 */
function isCalendarInstant(value: string): boolean {
  const year = toNumber(sliceText(value, 0, 4));
  const month = toNumber(sliceText(value, 5, 7));
  const day = toNumber(sliceText(value, 8, 10));
  return day <= daysInMonth(year, month) && isFiniteNumber(parseDate(value));
}

/** Milliseconds since the epoch for a value that `timestamp` accepted. */
export function instant(value: string): number {
  return parseDate(value);
}
