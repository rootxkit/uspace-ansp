// Synthetic restrictions and alarms in the shapes of api/openapi.yaml
// (its RestrictionPlanned and DeliveryAlarmOpen examples), for the unit
// tests. Test data, not traffic.
import type { ApiAlarm, ApiRestriction } from "../src/console/delivery";

export const FEATURE: ApiRestriction["feature"] = {
  type: "Feature",
  id: "DAR7K2Q",
  geometry: {
    type: "Polygon",
    coordinates: [
      [
        [44.78, 41.7],
        [44.82, 41.7],
        [44.82, 41.73],
        [44.78, 41.73],
        [44.78, 41.7],
      ],
    ],
  },
  properties: {
    identifier: "DAR7K2Q",
    country: "GEO",
    type: "PROHIBITED",
    variant: "COMMON",
    reason: ["DAR"],
    name: [
      { text: "Dynamic restriction (synthetic example)", lang: "en-GB" },
      { text: "დინამიკური შეზღუდვა (სინთეტიკური)", lang: "ka-GE" },
    ],
  },
} as ApiRestriction["feature"];

const NONE = { state: "none", attempts: 0 } as const;

export function restriction(over: Partial<ApiRestriction> = {}): ApiRestriction {
  return {
    id: "01K6P0A1B2C3D4E5F6G7H8J9KM",
    ansp_ref: "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM",
    identifier: "DAR7K2Q",
    uspace_airspace_id: "GEOTU01",
    zone_type: "PROHIBITED",
    geometry: FEATURE.geometry as ApiRestriction["geometry"],
    radius_m: null,
    lower_m: 0,
    lower_ref: "AMSL",
    upper_m: 1200,
    upper_ref: "AMSL",
    starts_at: "2026-10-02T12:00:00.000Z",
    ends_at: "2026-10-02T16:00:00.000Z",
    reason_text: "Search and rescue operation (synthetic example)",
    state: "planned",
    ansp_version: 1,
    created_by: "watch_supervisor",
    created_at: "2026-10-02T11:50:00.000Z",
    activated_at: null,
    ended_at_actual: null,
    request_id: null,
    published_version: null,
    supersedes_id: null,
    dss_constraint_id: "2f8343be-6482-4d1b-a474-16847e01af1e",
    dss_version: null,
    feature: FEATURE,
    constraint_reference: null,
    dss: { state: "none" },
    deliveries: { cisp: { ...NONE }, dss: { ...NONE }, uss_notify: { ...NONE }, direct_degraded: { ...NONE } },
    cis_version: "42",
    cis_age_s: 12.5,
    ...over,
  };
}

export function alarm(over: Partial<ApiAlarm> = {}): ApiAlarm {
  return {
    id: "01K6P0A9QZ3V1H8M2T6R4W5X7C",
    kind: "cisp_not_published",
    state: "open",
    restriction_id: "01K6P0A1B2C3D4E5F6G7H8J9KM",
    ansp_version: 2,
    since: "2026-10-02T12:00:00.000Z",
    raised_at: "2026-10-02T12:00:10.120Z",
    detail: "restriction DAR7K2Q (version 2) is active and not yet published to the CISP",
    ...over,
  };
}
