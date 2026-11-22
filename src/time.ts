import { z } from "zod";

/**
 * ISO 8601 date-time with seconds, at most millisecond precision and an explicit offset in
 * the range of the ECMAScript date-time format. Wider forms (offsets above 23:59, offsets
 * without a colon, more fraction digits) parse differently or not at all across engines, so
 * they are rejected.
 */
const isoInstant =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,3})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$/;

export const timestampSchema = z
  .string()
  .regex(isoInstant, "Use an ISO 8601 date-time with an offset, for example 2026-01-15T10:00:00Z.")
  .refine(isCalendarInstant, "The date-time does not exist.");

/**
 * Rejects days that the month does not have. V8 reads 2026-02-30 as 2 March, other engines
 * return NaN, so the day is checked here instead of trusting Date.parse.
 */
function isCalendarInstant(value: string): boolean {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  // setUTCFullYear, because Date.UTC maps the years 0 to 99 to 1900 to 1999.
  const end = new Date(0);
  end.setUTCFullYear(year, month, 0);
  const daysInMonth = end.getUTCDate();
  return day <= daysInMonth && Number.isFinite(Date.parse(value));
}

/** Milliseconds since the epoch for a value that timestampSchema accepted. */
export function instant(value: string): number {
  return Date.parse(value);
}
