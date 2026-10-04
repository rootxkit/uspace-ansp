// The delivery lines: each state the API reports has its words, and each
// "not yet" line has its twin that says it is done (E-01).
import { describe, expect, it } from "vitest";
import { alarm, restriction } from "../../test/fixtures";
import { channelLine, cispLine, deliveryLines, dssLine, openAlarmsOf } from "./delivery";

describe("the CISP line", () => {
  it("says published with the version and the time when the CISP holds the current version", () => {
    const r = restriction({
      state: "active",
      ansp_version: 3,
      published_version: 3,
      deliveries: { ...restriction().deliveries, cisp: { state: "sent", attempts: 1, last_attempt_at: "2026-10-02T12:00:01.000Z" } },
    });
    expect(cispLine(r, null)).toEqual({
      key: "ansp.delivery.cisp.published_at",
      vars: { version: 3, at: "2026-10-02T12:00:01.000Z" },
      attention: false,
    });
  });

  it("says not yet published since the alarm's since for an active version the CISP lacks", () => {
    const r = restriction({ state: "active", ansp_version: 2, published_version: null });
    const l = cispLine(r, alarm());
    expect(l.key).toBe("ansp.delivery.cisp.not_yet_since");
    expect(l.vars["since"]).toBe("2026-10-02T12:00:00.000Z");
    expect(l.attention).toBe(true);
  });

  it("says which version the CISP still holds when it is behind", () => {
    const r = restriction({ state: "active", ansp_version: 3, published_version: 2 });
    const l = cispLine(r, null);
    expect(l.key).toBe("ansp.delivery.cisp.behind");
    expect(l.vars).toMatchObject({ version: 3, published: 2 });
    expect(l.attention).toBe(true);
  });

  it("says not yet published, without alarm, for a fresh planned restriction", () => {
    const l = cispLine(restriction(), null);
    expect(l.key).toBe("ansp.delivery.cisp.not_yet");
    expect(l.attention).toBe(false);
  });

  it("says refused with the HTTP status for a failed delivery, and never lost", () => {
    const r = restriction({
      deliveries: {
        ...restriction().deliveries,
        cisp: { state: "failed", attempts: 1, last_status_code: 400, last_attempt_at: "2026-10-02T12:00:00.210Z" },
      },
    });
    const l = cispLine(r, null);
    expect(l).toMatchObject({ key: "ansp.delivery.cisp.failed", attention: true });
    expect(l.vars["code"]).toBe(400);
    expect(l.key).not.toContain("lost");
  });

  it("says not delivered after its attempts for an abandoned delivery", () => {
    const r = restriction({ deliveries: { ...restriction().deliveries, cisp: { state: "abandoned", attempts: 40 } } });
    expect(cispLine(r, null)).toMatchObject({ key: "ansp.delivery.cisp.abandoned", vars: { attempts: 40 } });
  });
});

describe("the DSS line", () => {
  it.each([
    ["none", "ansp.delivery.dss.none", false],
    ["written", "ansp.delivery.dss.written", false],
    ["deleted", "ansp.delivery.dss.deleted", false],
    ["failed", "ansp.delivery.dss.failed", true],
  ] as const)("%s is %s", (state, key, attention) => {
    const r = restriction({ state: "active", dss: { state, since: "2026-10-02T12:00:00.000Z", ansp_version: 1, dss_version: 1 } });
    expect(dssLine(r)).toMatchObject({ key, attention });
  });

  it("says pending since T, and asks for attention while the restriction is active", () => {
    const active = dssLine(restriction({ state: "active", dss: { state: "pending", since: "2026-10-02T12:00:00.000Z" } }));
    expect(active).toEqual({
      key: "ansp.delivery.dss.pending_since",
      vars: { since: "2026-10-02T12:00:00.000Z", version: "", dss_version: "" },
      attention: true,
    });
    const planned = dssLine(restriction({ state: "planned", dss: { state: "pending" } }));
    expect(planned).toMatchObject({ key: "ansp.delivery.dss.pending", attention: false });
  });

  it("says the state is not reported when the API gives none", () => {
    const r = restriction();
    delete r.dss;
    expect(dssLine(r).key).toBe("ansp.delivery.dss.unknown");
  });
});

describe("the further channels", () => {
  it("say nothing while they have done nothing", () => {
    expect(channelLine("uss_notify", { state: "none", attempts: 0 })).toBeNull();
    expect(channelLine("direct_degraded", undefined)).toBeNull();
  });

  it("say what was sent, and a degraded direct delivery always asks for attention", () => {
    expect(channelLine("uss_notify", { state: "sent", attempts: 1, last_attempt_at: "2026-10-02T12:00:02.000Z" })).toMatchObject({
      key: "ansp.delivery.uss_notify.sent",
      attention: false,
    });
    expect(channelLine("direct_degraded", { state: "sent", attempts: 1 })).toMatchObject({
      key: "ansp.delivery.direct_degraded.sent",
      attention: true,
    });
  });
});

describe("all lines", () => {
  it("are CISP first, then DSS, then the channels that did something", () => {
    const r = restriction({
      state: "active",
      ansp_version: 2,
      deliveries: { ...restriction().deliveries, uss_notify: { state: "queued", attempts: 0 } },
    });
    expect(deliveryLines(r, [alarm()]).map((l) => l.key)).toEqual([
      "ansp.delivery.cisp.not_yet_since",
      "ansp.delivery.dss.none",
      "ansp.delivery.uss_notify.queued",
    ]);
  });

  it("read a cleared alarm, or one of another version, as no alarm", () => {
    const r = restriction({ state: "active", ansp_version: 2 });
    expect(deliveryLines(r, [alarm({ state: "cleared" })])[0]?.key).toBe("ansp.delivery.cisp.not_yet");
    expect(deliveryLines(r, [alarm({ ansp_version: 1 })])[0]?.key).toBe("ansp.delivery.cisp.not_yet");
  });

  it("keep the open alarms of one restriction", () => {
    const mine = alarm();
    const other = alarm({ id: "01K6P0A9QZ3V1H8M2T6R4W5X7D", restriction_id: "01K6P0A1B2C3D4E5F6G7H8J9KN" });
    const cleared = alarm({ id: "01K6P0A9QZ3V1H8M2T6R4W5X7E", state: "cleared" });
    expect(openAlarmsOf(mine.restriction_id ?? "", [mine, other, cleared])).toEqual([mine]);
  });
});
