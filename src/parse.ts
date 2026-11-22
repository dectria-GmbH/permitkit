import type { z } from "zod";

/**
 * Zod safeParse that cannot throw. Zod reads some options through plain property access, so a
 * polluted Object.prototype can make its error path throw; that input then counts as invalid.
 */
export function safeParse<T extends z.ZodTypeAny>(
  schema: T,
  value: unknown,
): { success: true; data: z.output<T> } | { success: false; error: { issues: z.ZodIssue[] } } {
  try {
    const result = schema.safeParse(value);
    if (result.success) return { success: true, data: result.data };
    return { success: false, error: { issues: result.error.issues } };
  } catch {
    return {
      success: false,
      error: {
        issues: [{ code: "custom", path: [], message: "The input could not be validated." }],
      },
    };
  }
}
