// The pure parts of the sources, policy, audit and occurrence pages:
// the switch rows (type first, then each adapter, then a switch of an
// unregistered instance), the policy body (refusing what is not finite
// and positive, sending what is), the audit query and export (the chain
// hashes kept), and the occurrence body (the reporter reference only in
// the body; a send without an answer never repeated by itself). Each
// refusal is paired with the case that passes (E-01).
import { describe, expect, it } from "vitest";
import type { CallFailure } from "../api/client";
import type { ApiAdapter, ApiSourceControl } from "./adapters";
import { auditQuery, exportDocument, exportFileName, shortHash, type ApiAuditEvent } from "./audit";
import { deadlinePreview, emptyForm, occurrenceBody, outcomeAfter, type OccurrenceForm } from "./occurrence";
import { changes, formOf, historyVersions, HISTORY_VERSIONS, policyAuditEntity, policyBody, unitOf, type ApiPolicyUpdate } from "./policy";
import { isEnabled, switchAuditEntity, switchBody, switchRows } from "./sources";

function adapter(id: string): ApiAdapter {
  return { id, kind: "replay", display_name: id, source_class: "ads_b", status: "running", enabled: true, last_frame_at: null, last_status_at: null, counters: {} };
}

function control(instance: string, enabled: boolean): ApiSourceControl {
  return {
    source_type: "manned",
    instance_id: instance,
    enabled,
    reason: "maintenance (synthetic)",
    actor: "admin",
    changed_at: "2026-10-02T10:00:00.000Z",
    version: 3,
    epoch: "4f5a2b1c-0000-4000-8000-000000000000",
  };
}

describe("switch rows", () => {
  it("lists the type first, then the adapters, then a switch of an unregistered instance", () => {
    const rows = switchRows([adapter("sbs-1"), adapter("replay-1")], [control("gone-1", false), control("sbs-1", false)]);
    expect(rows.map((r) => r.instance)).toEqual(["*", "replay-1", "sbs-1", "gone-1"]);
    expect(rows[2]?.control?.enabled).toBe(false);
    expect(rows[3]?.adapter).toBeNull();
  });

  it("calls a row with no switch enabled, and a disabled switch disabled", () => {
    expect(isEnabled({ control: null })).toBe(true);
    expect(isEnabled({ control: control("sbs-1", false) })).toBe(false);
    expect(isEnabled({ control: control("sbs-1", true) })).toBe(true);
  });

  it("sends the switch with the reason trimmed, and names its audit entity", () => {
    expect(switchBody(false, "  maintenance ")).toEqual({ enabled: false, reason: "maintenance" });
    expect(switchAuditEntity("*")).toBe("source_control:manned/*");
    expect(switchAuditEntity("sbs-1")).toBe("source_control:manned/sbs-1");
  });
});

const POLICY: ApiPolicyUpdate = {
  feed_margin_lateral_m: 5000,
  feed_margin_vertical_m: 1500,
  stale_after_s: 15,
  source_liveness_s: 15,
  cisp_alarm_after_s: 10,
  cisp_heartbeat_s: 15,
  cis_reconcile_s: 60,
  cis_stale_bound_s: 300,
  notice_escalation_s: 60,
  default_zone_type: "PROHIBITED",
  country: "GEO",
};

describe("policy", () => {
  it("states each threshold's unit from its name", () => {
    expect(unitOf("feed_margin_lateral_m")).toBe("m");
    expect(unitOf("stale_after_s")).toBe("s");
  });

  it("sends the row as typed, and refuses zero, a word, a lower-case country", () => {
    expect(policyBody(formOf(POLICY))).toEqual({ body: POLICY });
    const bad = { ...formOf(POLICY), stale_after_s: "0", cis_reconcile_s: "soon", country: "geo" };
    const built = policyBody(bad);
    expect("problems" in built && built.problems).toEqual([
      { field: "stale_after_s", problem: "positive" },
      { field: "cis_reconcile_s", problem: "number" },
      { field: "country", problem: "country" },
    ]);
  });

  it("names the thresholds a change moves, and none for the same row", () => {
    expect(changes(POLICY, { ...POLICY, stale_after_s: 20 })).toEqual([{ field: "stale_after_s", from: "15", to: "20" }]);
    expect(changes(POLICY, POLICY)).toEqual([]);
  });

  it("reads the history back by version, bounded", () => {
    expect(historyVersions(3)).toEqual([3, 2, 1]);
    expect(historyVersions(40)).toHaveLength(HISTORY_VERSIONS);
    expect(policyAuditEntity(7)).toBe("ansp_policy:7");
  });
});

describe("audit", () => {
  it("builds the contract's query, and refuses a malformed entity, a partial time, a limit out of range", () => {
    expect(auditQuery("restriction:01K6P0", "2026-10-02T00:00:00Z", true, "100")).toEqual({
      query: { entity: "restriction:01K6P0", since: "2026-10-02T00:00:00Z", limit: 100 },
    });
    expect(auditQuery("", null, false, "1")).toEqual({ query: { limit: 1 } });
    expect(auditQuery("restriction", null, true, "1001")).toEqual({ problems: ["entity", "since", "limit"] });
    expect(auditQuery(`x:${"a".repeat(160)}`, null, false, "5")).toEqual({ problems: ["entity"] });
  });

  it("exports the events as listed, the chain hashes included", () => {
    const event: ApiAuditEvent = {
      id: 1042,
      ts: "2026-10-02T12:05:00.000Z",
      actor_type: "user",
      actor_id: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z",
      purpose: "source switch (04 3.6, U-15)",
      entity_type: "source_control",
      entity_id: "manned/sbs-1",
      event_type: "source_control_set",
      payload: { enabled: false } as unknown as ApiAuditEvent["payload"],
      prev_hash: "9f2c4be4d1a0b5c6d7e8f90112233445566778899aabbccddeeff00112233445",
      hash: "0b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff0",
    };
    const doc = exportDocument({ limit: 100 }, "2026-10-02T12:06:00.000Z", false, [event]);
    expect(JSON.parse(JSON.stringify(doc)).events[0]).toEqual(event);
    expect(doc.query).toEqual({ limit: 100 });
    expect(exportFileName("2026-10-02T12:06:00.000Z")).toBe("ansp-audit-2026-10-02T12-06-00-000Z.json");
    expect(shortHash(event.hash)).toBe("0b1c2d3e…cddeeff0");
    expect(shortHash("abc")).toBe("abc");
  });
});

function filled(over: Partial<OccurrenceForm> = {}): OccurrenceForm {
  return {
    ...emptyForm(),
    occurred_at: "2026-10-02T11:20:00Z",
    became_aware_at: "2026-10-02T11:25:00Z",
    narrative: "Synthetic airprox for the test.",
    ...over,
  };
}

describe("occurrence", () => {
  it("builds the body with the protected reference in it, and only what was given", () => {
    const built = occurrenceBody(
      filled({
        manned: [{ icao24: "4CA7B5", callsign: "TST123" }],
        aircraft: [{ serial: "1581F5FHD23440010000", operator_reg: "", flight_id: "", authorisation_number: "" }],
        intent_refs: "2F8343BE-6482-4D1B-A474-16847E01AF1E",
        min_h_m: "180",
        min_v_m: "",
        reporter_person_ref: " staff-0042 ",
      }),
    );
    expect(built).toEqual({
      body: {
        channel: "mandatory",
        category: "airprox",
        occurred_at: "2026-10-02T11:20:00Z",
        became_aware_at: "2026-10-02T11:25:00Z",
        narrative: "Synthetic airprox for the test.",
        aircraft: [{ serial: "1581F5FHD23440010000" }],
        manned: [{ icao24: "4ca7b5", callsign: "TST123" }],
        intent_refs: ["2f8343be-6482-4d1b-a474-16847e01af1e"],
        min_separation: { h_m: 180 },
        reporter_person_ref: "staff-0042",
      },
    });
    expect("body" in occurrenceBody(filled()) && Object.keys((occurrenceBody(filled()) as { body: object }).body)).not.toContain("reporter_person_ref");
  });

  it("refuses a missing time or narrative, a bad ICAO address, intent id or separation", () => {
    const built = occurrenceBody({
      ...emptyForm(),
      manned: [{ icao24: "xyz", callsign: "" }],
      intent_refs: "not-a-uuid",
      min_h_m: "-1",
    });
    expect("problems" in built && built.problems.map((p) => `${p.field}:${p.problem}`)).toEqual([
      "occurred_at:required",
      "became_aware_at:required",
      "narrative:required",
      "manned[0].icao24:icao24",
      "intent_refs[0]:uuid",
      "min_separation.h_m:number",
    ]);
  });

  it("shows the deadline 72 h after becoming aware, and none without that time", () => {
    expect(deadlinePreview("2026-10-02T11:25:00Z")).toBe("2026-10-05T11:25:00.000Z");
    expect(deadlinePreview(null)).toBeNull();
  });

  it("calls a refusal refused and no answer, a 502 or a 504 unknown", () => {
    const f = (status: number, problem: boolean): CallFailure => ({
      status,
      problem: problem ? { type: "", title: "x", status, detail: null, instance: null, errors: [] } : null,
      slug: null,
      retryAfterS: null,
      fieldErrors: [],
    });
    expect(outcomeAfter(f(400, true))).toBe("refused");
    expect(outcomeAfter(f(503, true))).toBe("refused");
    expect(outcomeAfter(f(0, false))).toBe("unknown");
    expect(outcomeAfter(f(502, true))).toBe("unknown");
    expect(outcomeAfter(f(504, true))).toBe("unknown");
  });
});
