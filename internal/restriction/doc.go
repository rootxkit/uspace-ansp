// Package restriction is the ANSP's dynamic airspace reconfiguration
// (spec 01 section 4 N1, N4; 2021/665 ATS.TR.237): the restriction state
// machine with its versions and audit, the validation of a restriction,
// its placement in a designated U-space airspace, its ED-318 feature and
// its F3548 volumes (docs/WORKPACKAGES/WP-5.md). Nothing here commands an
// aircraft: a restriction is information to the CISP, the DSS and the
// USSPs, and every change is recorded with who, why, when and until when.
// A library package: it never logs; it counts (Service.Counters) and
// returns errors, and the process decides.
//
// # The state machine
//
// States planned, active, ended, cancelled; the column and the message
// member that number the versions is ansp_version (M4: with ansp_ref the
// idempotency key towards the CISP and the DSS). Transitions (Transition):
//
//	plan      -> planned            (Service.Plan; version 1)
//	activate  planned -> active     at once when starts_at <= now; before
//	                                starts_at the row stays planned with
//	                                activate_at and an event, no version,
//	                                and the ticker (Service.Tick) activates
//	                                it at starts_at, versioned, as system
//	extend    active -> active      a later ends_at within
//	                                CstrMaxDurationHours of starts_at; past
//	                                it a linked re-issue (supersedes_id)
//	                                from the current ends_at is planned
//	end       active -> ended       ends_at set to now
//	cancel    planned -> cancelled
//	expire    active -> ended       at ends_at, by the ticker; a planned
//	                                re-issue continuing it is activated
//
// Every versioned transition bumps ansp_version and, in one transaction,
// writes the restriction, a restriction_versions row (the feature, the
// constraint document, the state, the window, the envelope msg_id, who and
// why) and an events row (actor, reason, before and after). After the
// commit the version is published on restr.v1.<state>.<restriction_id>
// (JetStream, message id <restriction_id>.<version>) and given to the
// console stream; a publish that fails is counted and left for the ticker,
// which republishes every version above the row's bus_version as backlog,
// so a bus outage delays restr.v1 and loses nothing. Every instant a
// judgement uses (now, due activations, due expiries) is the database's
// clock. An illegal transition is a Refusal 409 illegal_transition naming
// the operation and the state.
//
// # Validation and placement
//
// Validate reports every problem, repairs none: zone type PROHIBITED or
// REQ_AUTHORIZATION (D4; empty takes the policy's default_zone_type);
// both limits with a reference, AMSL or WGS84, AGL refused with ReasonAGL
// (D3, D-01); lower below upper; starts_at before ends_at, not more than
// StartLead in the past, within CstrMaxPlanningHorizonDays; reason_text
// at most 200 characters (it becomes the feature's name and message); the
// shape through ed318.Parse of the feature it would make (the
// antimeridian, ring and circle rules are core's). ParseShape holds a
// polygon to one outer ring (no holes in v1) of at most CstrMaxVertices
// vertices with geodesy.ValidRing. A window longer than
// CstrMaxDurationHours is returned as the chain of re-issues it would
// make, and planned only with confirm_chain.
//
// Place requires a current USPACE feature of the CIS projection (M9, gap
// 13; no switch): the named one, or with none named the one feature that
// covers the shape. The shape must lie inside it (partly outside is
// refused) and upper_m may not exceed the airspace's upper limit in the
// same reference; references that differ are reference_mismatch, never
// converted. A projection that is absent or older than cis_stale_bound_s
// is 503 cis_stale. Area (CstrMaxAreaKm2) and the relation of two shapes
// are the store's (PostGIS on geography; core has neither).
//
// # The feature (feature.go)
//
// Feature builds the ED-318 UASZone of a restriction with the member
// names of uspace-core/ed318: identifier DAR plus 4 base-36 characters
// (Identifier: a non-cycling database sequence permuted by a per-database
// offset, D4, M10), country (policy), name and message from reason_text
// (lang "en"), type, variant COMMON, reason [DAR], one
// limitedApplicability period from starts_at to ends_at in UTC with Z and
// milliseconds, one zoneAuthority with purpose INFORMATION
// (ANSP_AUTHORITY_*), extendedProperties.ansp {ansp_ref, restriction_id,
// uspace_airspace_id}, and the geometry with its layer (upper,
// upperReference, lower, lowerReference, uom "m"). It is exported and
// parsed back (CheckFeature) before it is stored or leaves. The feature is
// built once, at plan; later versions keep it, and an extend changes only
// the period's endDateTime (WithEnd): the CISP refuses an extend whose
// feature differs anywhere else (uspace-cisp PLAN section 15 Q36), which
// is also why ansp_version and state travel beside the feature and not in
// it. FeatureCollection is the collection served to a receiver's pull_url
// with core's metadata members issued and provider (M15).
//
// UNVERIFIED, inherited from uspace-core/ed318: the names of a zone's
// vertical limits (the geometry's layer with upper, upperReference,
// lower, lowerReference and uom); that an absent uom means metres; the
// unit of a circle's radius (metres). The EUROCAE ED-318 text is not
// available to the project (spec 09 section 3).
//
// # The F3548 volumes (constraint.go)
//
// Volumes is one Volume4D in W84 metres: a WGS84 limit passes through; an
// AMSL limit is made HAE with geoid.HAEFromAMSL, the lower with the
// least undulation over the outline and the upper with the greatest (a
// conservative envelope, gap 3), the undulations recorded in the version's
// constraint derivation. Without a geoid an AMSL plan, activation or
// extension is refused 503 geoid_unavailable and counted; an end, cancel
// or expiry is never held up by it and is written without a constraint.
// Details adds type DAR and the geozone where ed318.ToED269 can map the
// feature, which for a DAR it cannot, so it is omitted and counted (gap
// 16).
//
// # Restriction requests (F11)
//
// A request is recorded received, idempotent per requester by client_ref
// (another body under the ref is 409), at most MaxOpenRequests undecided
// per requester; a supervisor accepts it, which plans the restriction in
// the same transaction (a refused plan leaves the request received), or
// declines it with a reason.
package restriction
