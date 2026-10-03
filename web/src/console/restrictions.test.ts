// Merging the stream into the list: a frame that applies changes what it
// carries; a stale one, an unknown one and a malformed one are refused
// and say so (E-01 pairs).
import { describe, expect, it } from "vitest";
import type { ConsoleFrame } from "@rootxkit/uspace-ui/live";
import { alarm, FEATURE, restriction } from "../../test/fixtures";
import { mergeAlarm, mergeState, stateBodyOf, type ApiStateBody } from "./restrictions";

function frame(body: unknown, schema = "restriction/state/v1"): ConsoleFrame {
  return {
    schema,
    msgId: "01K6P0AAAAAAAAAAAAAAAAAAAA",
    producer: "ansp/api",
    ts: null,
    rxTs: "2026-10-02T12:00:00.000Z",
    capturedAt: "2026-10-02T12:00:00.000Z",
    timeSource: "system",
    backlog: false,
    body,
  } as ConsoleFrame;
}

const BODY: ApiStateBody = {
  restriction_id: "01K6P0A1B2C3D4E5F6G7H8J9KM",
  ansp_ref: "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM",
  state: "active",
  starts_at: "2026-10-02T12:00:00.000Z",
  ends_at: "2026-10-02T16:00:00.000Z",
  ansp_version: 2,
  feature: FEATURE,
};

describe("stateBodyOf", () => {
  it("reads a restriction/state/v1 body", () => {
    expect(stateBodyOf(frame(BODY))).toEqual(BODY);
  });

  it.each([
    ["another schema", frame(BODY, "console/status/v1")],
    ["no restriction_id", frame({ ...BODY, restriction_id: 7 })],
    ["an unknown state", frame({ ...BODY, state: "paused" })],
    ["a fractional version", frame({ ...BODY, ansp_version: 1.5 })],
    ["no feature", frame({ ...BODY, feature: null })],
  ])("refuses %s", (_, f) => {
    expect(stateBodyOf(f)).toBeNull();
  });
});

describe("mergeState", () => {
  it("applies a newer version: state, window, version, feature, and nothing else", () => {
    const list = [restriction()];
    const m = mergeState(list, BODY);
    expect(m).toMatchObject({ unknown: false, stale: false });
    expect(m.restrictions[0]).toMatchObject({ state: "active", ansp_version: 2, reason_text: list[0]?.reason_text, lower_m: 0 });
    expect(list[0]?.state).toBe("planned");
  });

  it("applies a delivery outcome of the same version, published marking the version the CISP holds", () => {
    const list = [restriction({ state: "active", ansp_version: 2 })];
    const deliveries = { ...restriction().deliveries, cisp: { state: "sent" as const, attempts: 1 } };
    const m = mergeState(list, { ...BODY, deliveries, published: true, dss: { state: "pending" } });
    expect(m.restrictions[0]).toMatchObject({ published_version: 2, dss: { state: "pending" }, deliveries });
  });

  it("does not apply an older version", () => {
    const list = [restriction({ state: "ended", ansp_version: 3 })];
    const m = mergeState(list, BODY);
    expect(m.stale).toBe(true);
    expect(m.restrictions[0]?.state).toBe("ended");
  });

  it("asks for a reload for a restriction it does not hold", () => {
    const m = mergeState([restriction()], { ...BODY, restriction_id: "01K6P0A1B2C3D4E5F6G7H8J9KN" });
    expect(m.unknown).toBe(true);
    expect(m.restrictions).toHaveLength(1);
  });
});

describe("mergeAlarm", () => {
  it("puts a new alarm first and replaces an alarm by its id", () => {
    const a = alarm();
    expect(mergeAlarm([], a)).toEqual([a]);
    const cleared = { ...a, state: "cleared" as const };
    expect(mergeAlarm([a], cleared)).toEqual([cleared]);
  });

  it("keeps the list without an alarm", () => {
    const a = alarm();
    expect(mergeAlarm([a], undefined)).toEqual([a]);
  });
});
