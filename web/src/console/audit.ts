// The audit view's query and its export (01 N4; 06 T7; api/openapi.yaml
// listAudit). The query is the contract's: entity as
// <entity_type>:<entity_id> (at most 160 characters), since as an RFC
// 3339 instant, limit 1..1000. The export is the events exactly as the
// API listed them, prev_hash and hash included, with the query and when
// it was read, so the chain can be checked outside the console; the
// console checks nothing itself.
import type { components } from "../api/types";

export type ApiAuditEvent = components["schemas"]["AuditEvent"];

export const ENTITY_MAX_CHARS = 160;
export const LIMIT_MAX = 1000;
/** The listing's first bound; the API's default is the same. Display-only. */
export const LIMIT_DEFAULT = 100;

export interface AuditQuery {
  entity?: string;
  since?: string;
  limit: number;
}

export type QueryProblem = "entity" | "since" | "limit";

const ENTITY = /^[a-z_]+:[^\s]+$/;

/** The query of the form's values, or what is not the shape the contract takes. */
export function auditQuery(entity: string, sinceUtc: string | null, sinceTyped: boolean, limit: string): { query: AuditQuery } | { problems: QueryProblem[] } {
  const problems: QueryProblem[] = [];
  const e = entity.trim();
  if (e !== "" && (e.length > ENTITY_MAX_CHARS || !ENTITY.test(e))) problems.push("entity");
  if (sinceTyped && sinceUtc === null) problems.push("since");
  const n = Number(limit.trim());
  if (!Number.isInteger(n) || n < 1 || n > LIMIT_MAX) problems.push("limit");
  if (problems.length > 0) return { problems };
  return { query: { limit: n, ...(e === "" ? {} : { entity: e }), ...(sinceUtc === null ? {} : { since: sinceUtc }) } };
}

export interface AuditExport {
  exported_from: "GET /v1/audit";
  query: AuditQuery;
  read_at: string;
  truncated: boolean;
  events: ApiAuditEvent[];
}

/** The export document: the events as listed, the query, when it was read. */
export function exportDocument(query: AuditQuery, readAt: string, truncated: boolean, events: readonly ApiAuditEvent[]): AuditExport {
  return { exported_from: "GET /v1/audit", query, read_at: readAt, truncated, events: [...events] };
}

/** The export's file name: the instant it was read, safe on every file system. */
export function exportFileName(readAt: string): string {
  return `ansp-audit-${readAt.replace(/[:.]/g, "-")}.json`;
}

/** A hash shortened for a table cell (the whole one is in the export and the title). Display-only. */
export function shortHash(h: string): string {
  return h.length <= 16 ? h : `${h.slice(0, 8)}…${h.slice(-8)}`;
}
