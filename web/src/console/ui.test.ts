// ProblemNotice's lead line per answer, rendered as the console renders
// it (the kit's I18nProvider with the app's catalogues): a 501 from api
// says the operation is not served yet, in both languages, ahead of any
// slug; its twins say a refusal with the status and a stale CIS.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider, createTranslator, type Lang } from "@rootxkit/uspace-ui/i18n";
import type { CallFailure } from "../api/client";
import { catalogues } from "../i18n/catalogues";
import en from "../i18n/en.json";
import ka from "../i18n/ka.json";
import { ProblemNotice, Time, utcText, utcTime } from "./ui";

function failure(status: number, slug: string | null): CallFailure {
  return {
    status,
    problem: { type: `https://schemas.uspace.ge/problems/${slug ?? "x"}`, title: "Title", status, detail: "Detail", instance: null, errors: [] },
    slug,
    retryAfterS: null,
    fieldErrors: [],
  } as CallFailure;
}

function rendered(f: CallFailure, lang: Lang = "en"): string {
  return renderToStaticMarkup(createElement(I18nProvider, { lang, catalogues }, createElement(ProblemNotice, { failure: f })));
}

describe("ProblemNotice", () => {
  it("says a 501 not_implemented is an operation the API does not serve yet", () => {
    const html = rendered(failure(501, "not_implemented"));
    expect(html).toContain(en["ansp.problem.not_served"]);
    expect(html).toContain('data-status="501"');
    expect(html).toContain("Title");
    expect(html).not.toContain("The API refused it");
  });

  it("says it in Georgian too", () => {
    expect(rendered(failure(501, "not_implemented"), "ka")).toContain(ka["ansp.problem.not_served"]);
  });

  it("puts the 501 ahead of any slug the answer carries", () => {
    const html = rendered(failure(501, "cis_stale"));
    expect(html).toContain(en["ansp.problem.not_served"]);
    expect(html).not.toContain(en["ansp.problem.cis_stale"]);
  });

  it("says a refusal with its status for a 500, and a stale CIS for cis_stale, never not served", () => {
    const refused = rendered(failure(500, "internal"));
    expect(refused).not.toContain(en["ansp.problem.not_served"]);
    expect(refused).toContain("The API refused it (500).");
    const stale = rendered(failure(503, "cis_stale"));
    expect(stale).toContain(en["ansp.problem.cis_stale"]);
    expect(stale).not.toContain(en["ansp.problem.not_served"]);
  });
});

describe("times", () => {
  const tr = (lang: Lang) => createTranslator(lang, catalogues);

  it("a time is rendered in UTC, laid out by each catalogue, and says UTC", () => {
    // 02:07:49 in Tbilisi is the evening before in UTC: the zone is UTC, never the viewer's.
    expect(utcTime("2026-10-16T02:07:49+04:00", tr("en"))).toBe("15 Oct 2026, 22:07:49 UTC");
    expect(utcTime("2026-10-16T02:07:49+04:00", tr("ka"))).toBe("15 ოქტ. 2026, 22:07:49 UTC");
    // The pair: a UTC instant keeps its wall clock.
    expect(utcTime("2026-01-02T03:04:05Z", tr("en"))).toBe("2 Jan 2026, 03:04:05 UTC");
  });

  it("utcText is the same text, a dash for no time, and the value as sent for a non-time", () => {
    expect(utcText("2026-10-16T05:28:00+04:00", "en")).toBe("16 Oct 2026, 01:28:00 UTC");
    expect(utcText(null, "ka")).toBe("—");
    expect(utcText("not a time", "en")).toBe("not a time");
    expect(utcTime("not a time", tr("en"))).toBeNull();
  });

  it("the Time element renders UTC with the RFC 3339 value as its title, never GMT+x", () => {
    for (const lang of ["en", "ka"] as const) {
      const html = renderToStaticMarkup(createElement(I18nProvider, { lang, catalogues }, createElement(Time, { iso: "2026-10-16T05:28:00+04:00" })));
      expect(html).toContain(lang === "en" ? "16 Oct 2026, 01:28:00 UTC" : "16 ოქტ. 2026, 01:28:00 UTC");
      expect(html).toContain('title="2026-10-16T05:28:00+04:00"');
      expect(html).not.toContain("GMT");
    }
  });

  it("every month has a name in both catalogues", () => {
    for (let m = 1; m <= 12; m++) {
      expect((en as Record<string, string>)[`ansp.time.month.${m}`]).toBeTruthy();
      expect((ka as Record<string, string>)[`ansp.time.month.${m}`]).toBeTruthy();
    }
  });
});
