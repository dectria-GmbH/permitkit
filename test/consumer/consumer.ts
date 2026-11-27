// Compiled with `tsc --strict` against the built declarations in dist, as a consumer sees them
// (pnpm consumer-types, after the build). Each line is something consumer code may write.
import { PermitkitError, type PriorRequest } from "../../dist/index.js";

/** A subclass can set its own name. */
export class SubA extends PermitkitError {
  override name = "SubA";
}

/** Code that holds an error can rename it. */
export function rename(error: PermitkitError): void {
  error.name = "Renamed";
}

/** A subclass can assign its name in the constructor. */
export class SubB extends PermitkitError {
  constructor() {
    super("policy_invalid", "m");
    this.name = "SubB";
  }
}

/** The brand check narrows unknown values. */
export function codeOf(value: unknown): string | null {
  return PermitkitError.is(value) ? value.code : null;
}

/** An earlier request, typed with the exported PriorRequest. */
export const earlier: PriorRequest = { principalId: "u-1", permission: "ticket:refund" };
