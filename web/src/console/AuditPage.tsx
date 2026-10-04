"use client";

// /<locale>/audit: the append-only, hash-chained events (01 N4, 06 T7;
// GET /v1/audit, x-auth session:admin) by entity and time, oldest first
// after `since`, as the API lists them: who (actor type and id), why
// (purpose), what (entity, event type, payload) and the chain (prev_hash,
// hash). The listing is exported as JSON exactly as it was read, the
// chain hashes included; the console checks nothing in it. A refusal of
// the API, a 403 or a 501 for an operation it does not serve yet
// included, is shown as it said it.
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Input, Label } from "@rootxkit/uspace-ui/ui";
import { failureOf, type CallFailure } from "../api/client";
import { auditQuery, exportDocument, exportFileName, LIMIT_DEFAULT, shortHash, type ApiAuditEvent, type AuditQuery, type QueryProblem } from "./audit";
import { useConsole } from "./context";
import { mayAdminister } from "./roles";
import { Empty, ProblemNotice, Time } from "./ui";

interface Listing {
  query: AuditQuery;
  readAt: string;
  truncated: boolean;
  events: ApiAuditEvent[];
}

function download(listing: Listing) {
  const doc = exportDocument(listing.query, listing.readAt, listing.truncated, listing.events);
  const blob = new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = exportFileName(listing.readAt);
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function AuditPage() {
  const t = useT();
  const params = useSearchParams();
  const { client, role } = useConsole();
  const [entity, setEntity] = useState(params.get("entity") ?? "");
  const [since, setSince] = useState("");
  const [limit, setLimit] = useState(String(LIMIT_DEFAULT));
  const [problems, setProblems] = useState<QueryProblem[]>([]);
  const [listing, setListing] = useState<Listing | null>(null);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const built = auditQuery(entity, since === "" ? null : inputToUtc(since), since !== "", limit);
    if ("problems" in built) {
      setProblems(built.problems);
      return;
    }
    setProblems([]);
    setFailure(null);
    setBusy(true);
    try {
      const { data } = await client.GET("/v1/audit", { params: { query: built.query } });
      if (data !== undefined) setListing({ query: built.query, readAt: new Date().toISOString(), truncated: data.truncated === true, events: data.events });
    } catch (err: unknown) {
      setFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.audit.title")}</h2>
      {!mayAdminister(role) && <Empty textKey="ansp.audit.role" testId="audit-role" />}
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void load();
        }}
      >
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="audit-entity">{t("ansp.audit.entity")}</Label>
          <Input id="audit-entity" value={entity} onChange={(e) => setEntity(e.target.value)} className="w-80 font-mono" data-testid="audit-entity" />
          {problems.includes("entity") && <p className="m-0 text-xs text-[var(--us-danger)]">{t("ansp.audit.problem.entity")}</p>}
        </div>
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="audit-since">{t("ansp.audit.since")}</Label>
          <Input id="audit-since" type="datetime-local" step={1} value={since} onChange={(e) => setSince(e.target.value)} data-testid="audit-since" />
          {problems.includes("since") && <p className="m-0 text-xs text-[var(--us-danger)]">{t("ansp.audit.problem.since")}</p>}
        </div>
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="audit-limit">{t("ansp.audit.limit")}</Label>
          <Input id="audit-limit" inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value)} className="w-24" />
          {problems.includes("limit") && <p className="m-0 text-xs text-[var(--us-danger)]">{t("ansp.audit.problem.limit")}</p>}
        </div>
        <Button type="submit" size="sm" disabled={busy} data-testid="audit-load">
          {t("ansp.audit.load")}
        </Button>
      </form>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.audit.hint")}</p>
      {failure !== null && <ProblemNotice failure={failure} />}
      {listing !== null && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <p className="m-0 text-sm" data-testid="audit-count">
              {t("ansp.audit.count", { count: listing.events.length })} <Time iso={listing.readAt} />
            </p>
            <Button type="button" size="sm" variant="outline" disabled={listing.events.length === 0} onClick={() => download(listing)} data-testid="audit-export">
              {t("ansp.audit.export")}
            </Button>
          </div>
          {listing.truncated && <p className="m-0 text-xs">{t("ansp.audit.truncated")}</p>}
          {listing.events.length === 0 ? (
            <Empty textKey="ansp.audit.none" testId="audit-none" />
          ) : (
            <table className="w-full border-collapse text-xs" data-testid="audit-table">
              <thead>
                <tr className="border-b border-[var(--us-border)]">
                  <th className="p-1 text-start">{t("ansp.audit.col.id")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.ts")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.actor")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.purpose")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.entity")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.event")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.payload")}</th>
                  <th className="p-1 text-start">{t("ansp.audit.col.chain")}</th>
                </tr>
              </thead>
              <tbody>
                {listing.events.map((e) => (
                  <tr key={e.id} className="border-b border-[var(--us-border)] align-top" data-event={e.id}>
                    <td className="p-1 font-mono">{e.id}</td>
                    <td className="p-1">
                      <Time iso={e.ts} />
                    </td>
                    <td className="p-1 font-mono">
                      {e.actor_type}:{e.actor_id}
                    </td>
                    <td className="p-1">{e.purpose}</td>
                    <td className="p-1 font-mono">
                      {e.entity_type}:{e.entity_id}
                    </td>
                    <td className="p-1 font-mono">{e.event_type}</td>
                    <td className="p-1">
                      <pre className="m-0 max-w-[28rem] overflow-x-auto whitespace-pre-wrap break-all font-mono">{JSON.stringify(e.payload)}</pre>
                    </td>
                    <td className="p-1 font-mono">
                      <span title={e.prev_hash}>{shortHash(e.prev_hash)}</span>
                      {" → "}
                      <span title={e.hash}>{shortHash(e.hash)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
