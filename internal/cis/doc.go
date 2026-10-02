// Package cis is this system's projection of the Common Information
// Service (spec 02 F3; docs/PLAN.md sections 3, 5.1, 7; brief WP-7): it
// pulls the CISP's uspace_airspace, ussp_list and restrictions datasets,
// receives the CISP's signed change notifications, keeps the current
// version of each in cis_cache and in KV cis_current, and serves them
// with their age. A projection is never an authority (LESSONS G-08): the
// CISP is, and what is held here is shown with its version and age.
//
// The parts:
//
//   - Client: the CISP's F3 API through the generated client of the
//     pinned api/clients/cisp.yaml (GET /v1/{dataset} unfiltered with
//     If-None-Match, GET /v1/{dataset}/versions/{v} for the publisher's
//     signature, the subscription calls). Every call carries a cis.read
//     token whose aud is the CISP's host (M18), has a deadline, never
//     follows a redirect and reads a bounded body (20 MB for a dataset).
//   - ParseVersion: a dataset is accepted whole or refused whole, never
//     repaired (spec 06 T9): ED-318 through uspace-core's ed318.Parse
//     with ParseLimits and at most MaxFeatures features, the CISP's cis_*
//     members checked against X-CIS-Version, uspace_airspace built into
//     zones with ed318.ToZones; ussp_list decoded strictly into the
//     generated cis/ussp_list/v1 type.
//   - Projection: the writer in api. A version is used only when its
//     publisher's detached JWS verifies (core's DetachedVerifier; the
//     authority for uspace_airspace and ussp_list, this system for
//     restrictions); otherwise it is held and the version in use stays.
//     A new version is committed to cis_cache first (the row never goes
//     back to a lower version, compared under its lock; fetched_at is the
//     database clock), then put to KV cis_current and pushed on
//     cis.v1.<dataset>. A 304 only moves fetched_at. Every dataset is
//     pulled again every cis_reconcile_s whatever the notifications say,
//     and the subscription is registered at start (reused by its
//     callback after a restart) and registered again when the CISP says
//     it does not know it. Status is the readiness line: "ok (age 12 s)",
//     "stale (age 400 s)", "down since T" or "no CIS projection", with
//     every refusal, hold and failure named.
//   - Receiver: POST /v1/cis/notifications (M1, M19). A compact JWS
//     verified by core's CompactVerifier against ANSP_CIS_NOTIFY_ISSUERS
//     with aud one of ANSP_AUDIENCES, sub the subscription this system
//     registered, iat within 5 min, and the delivery id remembered in the
//     database (a replay is acknowledged 204 and counted). publication and
//     the restriction reasons trigger a pull (202); subscription_test,
//     republished and any reason this build does not know are 204 without
//     one (M16). The notification is a hint, never data: the dataset is
//     read whole from ANSP_CISP_URL, and a pull_url that is not https on
//     the CISP's host is counted (M5).
//   - Follower: the hot path's copy (manned-feed), fed by KV and the
//     push, with no database: Version, Age, USpaceVolumes and USSPs, a
//     higher version replacing, the same version moving fetched_at; it
//     starts empty and says "no CIS projection" (SC-22).
//
// The process passes its logger and exports the counters; every
// refusal, hold, drop and failure here is counted by a stable name.
package cis
