import { compareText, digest } from "./canonical.js";
import { PermitkitError, type PolicyIssue } from "./errors.js";

const namePattern = /^[a-z][a-z0-9_-]*$/;

export interface ResourceDefinition {
  /** Actions on this resource type. Permission names are `<resource>:<action>`. */
  readonly actions: readonly string[];
  /** Names of string properties that grants and role assignments may restrict. */
  readonly scopes?: readonly string[];
  /** Names of numeric properties that grants may cap and approval rules may test. */
  readonly limits?: readonly string[];
}

export type CatalogDefinition = Readonly<Record<string, ResourceDefinition>>;

export interface ResourceEntry {
  readonly type: string;
  readonly actions: readonly string[];
  readonly scopes: readonly string[];
  readonly limits: readonly string[];
}

/**
 * The fixed permission catalogue. It lives in code, so a new permission needs a release.
 * Policies (roles, scopes, limits) are data and may only refer to catalogued names.
 */
export interface Catalog {
  /** All permission names, sorted. */
  readonly permissions: readonly string[];
  /** All resource entries, sorted by type. */
  readonly resources: readonly ResourceEntry[];
  /** SHA-256 over the canonical catalogue. Part of every policy digest. */
  readonly digest: string;
  isPermission(permission: string): boolean;
  /** The resource entry of a permission, or undefined if the permission is unknown. */
  resourceOf(permission: string): ResourceEntry | undefined;
}

const catalogs = new WeakSet<object>();

/** True only for objects that defineCatalog returned in this process. */
export function isCatalog(value: unknown): value is Catalog {
  return typeof value === "object" && value !== null && catalogs.has(value);
}

export function defineCatalog(definition: CatalogDefinition): Catalog {
  const issues: PolicyIssue[] = [];
  const resources = new Map<string, ResourceEntry>();
  const permissions = new Set<string>();
  const normalized: Record<string, { actions: string[]; scopes: string[]; limits: string[] }> = {};

  for (const type of Object.keys(definition)) {
    const entry = definition[type];
    if (!namePattern.test(type)) {
      issues.push(issue(type, "Resource type name is not valid."));
      continue;
    }
    if (entry === undefined || !Array.isArray(entry.actions) || entry.actions.length === 0) {
      issues.push(issue(`${type}.actions`, "A resource type needs at least one action."));
      continue;
    }
    const lists = {
      actions: [...entry.actions],
      scopes: [...(entry.scopes ?? [])],
      limits: [...(entry.limits ?? [])],
    };
    for (const [key, list] of Object.entries(lists)) {
      const seen = new Set<string>();
      for (const name of list) {
        if (typeof name !== "string" || !namePattern.test(name)) {
          issues.push(issue(`${type}.${key}`, `Name ${JSON.stringify(name)} is not valid.`));
        } else if (seen.has(name)) {
          issues.push(issue(`${type}.${key}`, `Name ${name} appears twice.`));
        }
        seen.add(name);
      }
    }
    for (const name of lists.scopes) {
      if (lists.limits.includes(name)) {
        issues.push(issue(type, `Property ${name} cannot be both a scope and a limit.`));
      }
    }
    resources.set(
      type,
      Object.freeze({
        type,
        actions: Object.freeze([...lists.actions].toSorted(compareText)),
        scopes: Object.freeze([...lists.scopes].toSorted(compareText)),
        limits: Object.freeze([...lists.limits].toSorted(compareText)),
      }),
    );
    for (const action of lists.actions) permissions.add(`${type}:${action}`);
    normalized[type] = {
      actions: [...lists.actions].toSorted(compareText),
      scopes: [...lists.scopes].toSorted(compareText),
      limits: [...lists.limits].toSorted(compareText),
    };
  }

  if (resources.size === 0 && issues.length === 0) {
    issues.push(issue("", "The catalogue needs at least one resource type."));
  }
  if (issues.length > 0) {
    throw new PermitkitError("catalog_invalid", "The catalogue definition is not valid.", issues);
  }

  const catalog: Catalog = Object.freeze({
    permissions: Object.freeze([...permissions].toSorted(compareText)),
    resources: Object.freeze(
      [...resources.keys()].toSorted(compareText).map((type) => resources.get(type)!),
    ),
    digest: digest(normalized),
    isPermission(permission: string): boolean {
      return permissions.has(permission);
    },
    resourceOf(permission: string): ResourceEntry | undefined {
      if (!permissions.has(permission)) return undefined;
      const separator = permission.indexOf(":");
      return resources.get(permission.slice(0, separator));
    },
  });
  catalogs.add(catalog);
  return catalog;
}

function issue(path: string, message: string): PolicyIssue {
  return { path, message, hint: "Fix the catalogue definition in code." };
}
