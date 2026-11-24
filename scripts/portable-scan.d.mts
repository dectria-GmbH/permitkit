export function portabilityFindings(source: string): string[];
export function filesUnder(root: URL, directory: string, extension: string): string[];
export function compareWithAllowlist(
  root: URL,
  files: string[],
  allowlist: Record<string, string[]>,
): string[];
export const allowlist: {
  readonly src: Record<string, string[]>;
  readonly dist: Record<string, string[]>;
};
