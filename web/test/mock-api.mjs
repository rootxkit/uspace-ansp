#!/usr/bin/env node
// The Playwright fixture server: a stand-in for the deployment's Caddy in
// front of `next start`. It answers the API operations the console uses
// in the shapes of api/openapi.yaml (sign-in with MFA, restrictions,
// delivery alarms, restriction requests, adapters, sources) and the
// restriction stream (WS /v1/restrictions/stream in the console frame),
// and passes every other request to Next.js with the X-Forwarded-*
// headers Caddy sets, so the browser sees one origin, as in a deployment.
// The BFF reaches the API here too (WEB_API_INTERNAL_URL).
//
//   MOCK_PORT=3000 MOCK_UPSTREAM=http://127.0.0.1:3100 node test/mock-api.mjs
//
// Fixture data, not an implementation: it judges nothing. A plan is
// recorded as sent; a window longer than 24 h without confirm_chain is
// answered with the chain_required refusal the API gives (two re-issues),
// so the editor's chain path can be driven; the outbox is a control call.
//
// Control (tests only):
//   GET  /__mock/health
//   POST /__mock/reset                    accounts, restrictions and requests as at start
//   GET  /__mock/requests                 the API requests answered (method, path, body keys, headers seen)
//   POST /__mock/deliver {id}             the outbox's outcome for a restriction: published to the
//                                         CISP, written to the DSS, its alarm cleared; one frame
//   POST /__mock/state {stream?, cisStale?}
//
// Accounts (test data, not credentials of anything): super1 (watch
// supervisor; no authenticator until its first sign-in, so the enrolment
// is shown once), viewer1 (viewer, enrolled). The TOTP code is the fixed
// MOCK_TOTP_CODE.
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";

const PORT = Number(process.env.MOCK_PORT ?? "3000");
const UPSTREAM = new URL(process.env.MOCK_UPSTREAM ?? "http://127.0.0.1:3100");
const STATUS_PERIOD_MS = 1000;
export const MOCK_TOTP_CODE = "246810";
const SESSION_TTL_MS = 3_600_000;
const CHALLENGE_TTL_MS = 300_000;
const PROBLEM = "https://schemas.uspace.ge/problems/";

function iso(ms = Date.now()) {
  return new Date(ms).toISOString();
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
let serial = 0;
/** A ULID-shaped id (26 Crockford characters); fixture ids, monotonic. */
function ulid(prefix = "01K6P0") {
  serial += 1;
  let n = serial;
  let tail = "";
  for (let i = 0; i < 20; i++) {
    tail = CROCKFORD[n % 32] + tail;
    n = Math.floor(n / 32);
  }
  return prefix + tail;
}

function b64url(v) {
  return Buffer.from(JSON.stringify(v)).toString("base64url");
}

let state;
function reset() {
  serial = 0;
  state = {
    stream: true,
    cisStale: false,
    accounts: {
      super1: { id: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z", username: "super1", password: "super1-test-password", role: "watch_supervisor", enrolled: false },
      viewer1: { id: "01K6NZ8Q2W3E4R5T6Y7V8W9X1A", username: "viewer1", password: "viewer1-test-password", role: "viewer", enrolled: true },
    },
    challenges: new Map(),
    sessions: new Map(),
    restrictions: [],
    versions: new Map(),
    alarms: [],
    requests: [
      {
        id: "01K6P0R0000000000000000001",
        requester: "authority-01",
        source: "authority",
        received_at: "2026-10-02T09:00:00.000Z",
        state: "received",
        payload: {
          client_ref: "req-event-17",
          case_ref: "EVT-17 (synthetic)",
          uspace_airspace_id: "GEOTU01",
          geometry: {
            type: "Polygon",
            coordinates: [
              [
                [44.79, 41.71],
                [44.81, 41.71],
                [44.81, 41.72],
                [44.79, 41.72],
                [44.79, 41.71],
              ],
            ],
          },
          radius_m: null,
          lower_m: 0,
          lower_ref: "AMSL",
          upper_m: 900,
          upper_ref: "AMSL",
          starts_at: "2026-10-06T08:00:00.000Z",
          ends_at: "2026-10-06T12:00:00.000Z",
          reason_text: "Public event (synthetic example)",
        },
      },
    ],
  };
}
reset();
const recorded = [];
const clients = new Set();

function json(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

function problem(res, status, slug, title, detail = null, errors = [], headers = {}) {
  json(res, status, { type: `${PROBLEM}${slug}`, title, status, detail, instance: null, errors }, { "Content-Type": "application/problem+json", ...headers });
}

function readJson(req) {
  return new Promise((resolve) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", () => {
      try {
        resolve(text === "" ? {} : JSON.parse(text));
      } catch {
        resolve({});
      }
    });
  });
}

function sessionOf(token) {
  const s = token === null ? undefined : state.sessions.get(token);
  return s !== undefined && s.expiresMs > Date.now() ? s : null;
}

function bearer(req) {
  const h = req.headers["authorization"] ?? "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

function cookie(req, name) {
  for (const part of (req.headers["cookie"] ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function issueSession(account) {
  const expiresMs = Date.now() + SESSION_TTL_MS;
  const payload = {
    iss: "http://127.0.0.1:3000",
    aud: "127.0.0.1",
    sub: account.id,
    scope: "session",
    roles: [account.role],
    realm: "console",
    jti: randomBytes(8).toString("hex"),
    exp: Math.floor(expiresMs / 1000),
  };
  // Unsigned: the fixture's token is never verified by the web (the API decides).
  const token = `${b64url({ alg: "RS256", kid: "mock" })}.${b64url(payload)}.${randomBytes(16).toString("base64url")}`;
  state.sessions.set(token, { account, expiresMs });
  return { token, expiresMs };
}

function user(a) {
  return { id: a.id, username: a.username, role: a.role, status: "active", created_at: "2026-09-30T08:00:00.000Z", last_login_at: null };
}

// ---- restrictions -------------------------------------------------------

const NONE = () => ({ state: "none", attempts: 0 });

function feature(r) {
  return {
    type: "Feature",
    id: r.identifier,
    geometry: { ...r.geometry, layer: { upper: r.upper_m, upperReference: r.upper_ref, lower: r.lower_m, lowerReference: r.lower_ref, uom: "m" } },
    properties: {
      identifier: r.identifier,
      country: "GEO",
      type: r.zone_type,
      variant: "COMMON",
      reason: ["DAR"],
      name: [{ text: `Dynamic restriction ${r.identifier} (synthetic)`, lang: "en-GB" }],
      message: [{ text: r.reason_text, lang: "en-GB" }],
      limitedApplicability: [{ startDateTime: r.starts_at, endDateTime: r.ends_at }],
      zoneAuthority: [{ name: [{ text: "Test ANSP", lang: "en-GB" }], purpose: "AUTHORIZATION" }],
    },
  };
}

function version(r, by, reason) {
  const list = state.versions.get(r.id) ?? [];
  list.push({ restriction_id: r.id, version: r.ansp_version, state: r.state, feature: r.feature, changed_by: by, changed_at: iso(), change_reason: reason });
  state.versions.set(r.id, list);
}

function create(body, role, requestId = null) {
  const id = ulid();
  const identifier = `DAR${id.slice(-4)}`;
  const r = {
    id,
    ansp_ref: `ansp-01:${id}`,
    identifier,
    uspace_airspace_id: body.uspace_airspace_id,
    zone_type: body.zone_type ?? "PROHIBITED",
    geometry: body.geometry,
    radius_m: body.radius_m ?? null,
    lower_m: body.lower_m,
    lower_ref: body.lower_ref,
    upper_m: body.upper_m,
    upper_ref: body.upper_ref,
    starts_at: body.starts_at,
    ends_at: body.ends_at,
    reason_text: body.reason_text,
    state: "planned",
    ansp_version: 1,
    created_by: role,
    created_at: iso(),
    activated_at: null,
    ended_at_actual: null,
    request_id: requestId,
    published_version: null,
    supersedes_id: null,
    dss_constraint_id: "2f8343be-6482-4d1b-a474-16847e01af1e",
    dss_version: null,
    constraint_reference: null,
    dss: { state: "none" },
    deliveries: { cisp: NONE(), dss: NONE(), uss_notify: NONE(), direct_degraded: NONE() },
    cis_version: "42",
    cis_age_s: 3,
  };
  r.feature = feature(r);
  state.restrictions.unshift(r);
  version(r, role, body.reason_text);
  return r;
}

function stateFrame(r, extra = {}) {
  return frame("restriction/state/v1", {
    restriction_id: r.id,
    ansp_ref: r.ansp_ref,
    state: r.state,
    starts_at: r.starts_at,
    ends_at: r.ends_at,
    ansp_version: r.ansp_version,
    feature: r.feature,
    deliveries: r.deliveries,
    dss: r.dss,
    ...extra,
  });
}

function broadcast(text) {
  for (const c of clients) if (!c.destroyed) c.write(wsText(text));
}

// ---- the console frame and the WebSocket -------------------------------

function frame(schema, body) {
  const now = iso();
  return JSON.stringify({
    schema,
    msg_id: ulid("01K6PW"),
    producer: "ansp/api",
    ts: now,
    rx_ts: now,
    captured_at: now,
    time_source: "system",
    backlog: false,
    body,
  });
}

function statusFrame() {
  return frame("console/status/v1", {
    connection_id: "mock-connection",
    server_ts: iso(),
    policy_version: "pol-000001",
    stale_after_s: 15,
    live_max_age_s: 3,
    dropped_frames: 0,
    degraded: state.cisStale ? ["cis_projection_stale"] : [],
    sources: [],
    adapters: [],
    cis_version: "42",
    cis_age_s: state.cisStale ? 400 : 3,
    nats: "connected",
  });
}

function snapshotFrame() {
  return frame("console/snapshot/v1", {
    tracks: [],
    alerts: [],
    manned: [],
    zones_version: null,
    restrictions: state.restrictions.map((r) => JSON.parse(stateFrame(r))),
  });
}

function wsText(text) {
  const payload = Buffer.from(text);
  let head;
  if (payload.length < 126) {
    head = Buffer.from([0x81, payload.length]);
  } else if (payload.length < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x81;
    head[1] = 126;
    head.writeUInt16BE(payload.length, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x81;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([head, payload]);
}

function wsClose(code) {
  const b = Buffer.alloc(4);
  b[0] = 0x88;
  b[1] = 2;
  b.writeUInt16BE(code, 2);
  return b;
}

function upgrade(req, socket) {
  const url = new URL(req.url ?? "/", "http://mock");
  const key = req.headers["sec-websocket-key"];
  if (url.pathname !== "/v1/restrictions/stream" || !state.stream || typeof key !== "string") {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  recorded.push({ method: "WS", path: url.pathname, keys: [], cookie: cookie(req, "uspace_session") !== null, origin: req.headers["origin"] ?? null });
  // The session rides the upgrade as the cookie (M22); without a live one
  // the API closes 4401 ("sign in again").
  if (sessionOf(cookie(req, "uspace_session")) === null) {
    socket.end(wsClose(4401));
    return;
  }
  clients.add(socket);
  socket.write(wsText(statusFrame()));
  socket.write(wsText(snapshotFrame()));
  const timer = setInterval(() => {
    if (!socket.destroyed) socket.write(wsText(statusFrame()));
  }, STATUS_PERIOD_MS);
  const end = () => {
    clearInterval(timer);
    clients.delete(socket);
  };
  socket.on("data", () => undefined);
  socket.on("close", end);
  socket.on("error", end);
}

// ---- the API -------------------------------------------------------------

const SUPERVISOR = "watch_supervisor";

async function api(req, res, url) {
  const path = url.pathname;
  const body = req.method === "POST" || req.method === "PUT" ? await readJson(req) : {};
  recorded.push({
    method: req.method,
    path,
    keys: Object.keys(body).sort(),
    idempotencyKey: req.headers["idempotency-key"] ?? null,
    authorization: bearer(req) !== null,
    body: path.startsWith("/v1/auth/") ? undefined : body,
  });

  if (req.method === "POST" && path === "/v1/auth/login") {
    const a = state.accounts[body.username];
    if (a === undefined || a.password !== body.password) return problem(res, 401, "invalid_credentials", "Invalid credentials");
    const token = randomBytes(12).toString("hex");
    const expiresMs = Date.now() + CHALLENGE_TTL_MS;
    state.challenges.set(token, { account: a, expiresMs });
    const answer = { mfa_token: token, expires_at: iso(expiresMs) };
    if (!a.enrolled) {
      answer.enrolment = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: `otpauth://totp/ANSP:${a.username}?secret=JBSWY3DPEHPK3PXP&issuer=ANSP` };
    }
    return json(res, 200, answer);
  }
  if (req.method === "POST" && path === "/v1/auth/mfa") {
    const c = state.challenges.get(body.mfa_token);
    if (c === undefined || c.expiresMs < Date.now()) return problem(res, 401, "mfa_refused", "MFA refused", "the challenge is unknown or expired");
    if (body.code !== MOCK_TOTP_CODE) return problem(res, 401, "mfa_refused", "MFA refused", "the code is wrong");
    state.challenges.delete(body.mfa_token);
    c.account.enrolled = true;
    const s = issueSession(c.account);
    return json(res, 200, { token: s.token, token_type: "Bearer", expires_at: iso(s.expiresMs), idle_timeout_s: 1800, user: user(c.account) });
  }

  const session = sessionOf(bearer(req));
  if (session === null) return problem(res, 401, "unauthenticated", "Unauthenticated", "no live session");
  const role = session.account.role;
  const supervisorOnly = () => {
    if (role === SUPERVISOR) return false;
    problem(res, 403, "forbidden", "Forbidden", `role ${role} may not do this; it needs watch_supervisor`);
    return true;
  };

  if (req.method === "POST" && path === "/v1/auth/logout") {
    state.sessions.delete(bearer(req));
    res.writeHead(204);
    return res.end();
  }
  if (req.method === "GET" && path === "/v1/auth/me") {
    return json(res, 200, { ...user(session.account), session_expires_at: iso(session.expiresMs) });
  }

  if (path === "/v1/restrictions" && req.method === "GET") {
    const st = url.searchParams.get("state");
    const list = state.restrictions.filter((r) => st === null || r.state === st);
    return json(res, 200, { restrictions: list, cis_version: "42", cis_age_s: state.cisStale ? 400 : 3 });
  }
  if (path === "/v1/restrictions" && req.method === "POST") {
    if (supervisorOnly()) return;
    if (state.cisStale) return problem(res, 503, "cis_stale", "CIS projection stale", "the uspace_airspace projection is 400 s old (bound 300 s)");
    if (typeof req.headers["idempotency-key"] !== "string") return problem(res, 400, "invalid_request", "Invalid request", null, [{ field: "Idempotency-Key", reason: "required" }]);
    const hours = (Date.parse(body.ends_at) - Date.parse(body.starts_at)) / 3_600_000;
    if (hours > 24 && body.confirm_chain !== true) {
      const mid = iso(Date.parse(body.starts_at) + 24 * 3_600_000);
      return problem(res, 400, "chain_required", "Chain required", "the window is longer than CstrMaxDurationHours (24 h)", [
        { field: "chain[0]", reason: `${body.starts_at} to ${mid}` },
        { field: "chain[1]", reason: `${mid} to ${body.ends_at}` },
      ]);
    }
    const r = create(body, role);
    broadcast(stateFrame(r));
    return json(res, 201, r);
  }
  let m = /^\/v1\/restrictions\/([0-9A-Z]{26})$/.exec(path);
  if (m && req.method === "GET") {
    const r = state.restrictions.find((x) => x.id === m[1]);
    return r === undefined ? problem(res, 404, "not_found", "Not found") : json(res, 200, r);
  }
  m = /^\/v1\/restrictions\/([0-9A-Z]{26})\/versions$/.exec(path);
  if (m && req.method === "GET") return json(res, 200, { versions: state.versions.get(m[1]) ?? [] });
  m = /^\/v1\/restrictions\/([0-9A-Z]{26})\/(activate|extend|end|cancel)$/.exec(path);
  if (m && req.method === "POST") {
    if (supervisorOnly()) return;
    const r = state.restrictions.find((x) => x.id === m[1]);
    if (r === undefined) return problem(res, 404, "not_found", "Not found");
    const op = m[2];
    const allowed = { activate: ["planned"], extend: ["planned", "active"], end: ["active"], cancel: ["planned"] }[op];
    if (!allowed.includes(r.state)) return problem(res, 409, "conflict", "Conflict", `a ${r.state} restriction cannot be ${op}ed`);
    r.ansp_version += 1;
    let alarm;
    if (op === "activate") {
      r.state = "active";
      r.activated_by = role;
      r.activated_at = iso();
      r.deliveries = { ...r.deliveries, cisp: { state: "queued", attempts: 1, last_attempt_at: iso() } };
      r.dss = { state: "pending", since: iso() };
      alarm = { id: ulid("01K6PA"), kind: "cisp_not_published", state: "open", restriction_id: r.id, ansp_version: r.ansp_version, since: iso(), raised_at: iso(), detail: `restriction ${r.identifier} (version ${r.ansp_version}) is active and not yet published to the CISP` };
      state.alarms.unshift(alarm);
    } else if (op === "extend") {
      r.ends_at = body.ends_at;
    } else if (op === "end") {
      r.state = "ended";
      r.ended_by = role;
      r.ended_at_actual = iso();
    } else {
      r.state = "cancelled";
      r.cancelled_by = role;
    }
    r.feature = feature(r);
    version(r, role, body.reason ?? "");
    broadcast(stateFrame(r, alarm === undefined ? {} : { alarm }));
    return json(res, 200, r);
  }
  if (path === "/v1/delivery-alarms" && req.method === "GET") {
    const all = url.searchParams.get("all") === "true";
    return json(res, 200, { alarms: state.alarms.filter((a) => all || a.state !== "cleared") });
  }
  m = /^\/v1\/delivery-alarms\/([0-9A-Z]{26})\/acknowledge$/.exec(path);
  if (m && req.method === "POST") {
    if (supervisorOnly()) return;
    const a = state.alarms.find((x) => x.id === m[1]);
    if (a === undefined) return problem(res, 404, "not_found", "Not found");
    a.state = "acknowledged";
    a.acknowledged_by = role;
    a.acknowledged_at = iso();
    a.ack_reason = body.reason;
    return json(res, 200, a);
  }
  m = /^\/v1\/restriction-requests\/([0-9A-Z]{26})$/.exec(path);
  if (m && req.method === "GET") {
    const q = state.requests.find((x) => x.id === m[1]);
    return q === undefined ? problem(res, 404, "not_found", "Not found") : json(res, 200, q);
  }
  m = /^\/v1\/restriction-requests\/([0-9A-Z]{26})\/(accept|decline)$/.exec(path);
  if (m && req.method === "POST") {
    if (supervisorOnly()) return;
    const q = state.requests.find((x) => x.id === m[1]);
    if (q === undefined) return problem(res, 404, "not_found", "Not found");
    if (q.state !== "received") return problem(res, 409, "conflict", "Conflict", `the request is ${q.state}`);
    q.state = m[2] === "accept" ? "accepted" : "declined";
    q.decided_by = role;
    q.decided_at = iso();
    q.decision_reason = body.reason;
    if (m[2] === "accept") {
      const r = create({ ...q.payload, zone_type: body.zone_type }, role, q.id);
      q.restriction_id = r.id;
      broadcast(stateFrame(r));
    }
    return json(res, 200, q);
  }
  if (path === "/v1/adapters" && req.method === "GET") {
    return json(res, 200, {
      adapters: [
        {
          id: "replay-1",
          kind: "replay",
          display_name: "Replay (synthetic)",
          source_class: "ads_b",
          status: "running",
          enabled: true,
          last_frame_at: iso(Date.now() - 1000),
          last_status_at: iso(Date.now() - 1000),
          counters: { accepted: 1520, refused: 3, dropped: 0 },
        },
        {
          id: "sbs-1",
          kind: "dump1090_sbs",
          display_name: "Tower receiver",
          source_class: "ads_b",
          status: "disabled",
          enabled: false,
          last_frame_at: "2026-10-02T10:00:00.000Z",
          last_status_at: "2026-10-02T10:00:02.000Z",
          counters: { accepted: 40, refused: 0 },
        },
        {
          id: "json-1",
          kind: "dump1090_json",
          display_name: "Field receiver",
          source_class: "mode_s",
          status: "silent",
          enabled: true,
          last_frame_at: "2026-10-02T11:00:00.000Z",
          last_status_at: "2026-10-02T11:00:02.000Z",
          counters: {},
        },
      ],
    });
  }
  if (path === "/v1/sources" && req.method === "GET") {
    return json(res, 200, {
      sources: [
        {
          source_type: "manned",
          instance_id: "sbs-1",
          enabled: false,
          reason: "Receiver under maintenance (synthetic)",
          actor: "admin",
          changed_at: "2026-10-02T10:00:05.000Z",
          version: 4,
          epoch: "4f5a2b1c-0000-4000-8000-000000000000",
        },
      ],
    });
  }
  return problem(res, 404, "not_found", "Not found", `no fixture for ${req.method} ${path}`);
}

async function control(req, res, path) {
  if (path === "/__mock/health") return json(res, 200, { ok: true });
  if (path === "/__mock/requests") return json(res, 200, recorded);
  const input = await readJson(req);
  if (path === "/__mock/reset") {
    reset();
    recorded.length = 0;
    for (const c of clients) c.destroy();
    return json(res, 200, { ok: true });
  }
  if (path === "/__mock/state") {
    if (typeof input.stream === "boolean") {
      state.stream = input.stream;
      if (!state.stream) for (const c of clients) c.destroy();
    }
    if (typeof input.cisStale === "boolean") state.cisStale = input.cisStale;
    return json(res, 200, { stream: state.stream, cisStale: state.cisStale });
  }
  if (path === "/__mock/deliver") {
    const r = state.restrictions.find((x) => x.id === input.id);
    if (r === undefined) return json(res, 404, { error: "no such restriction" });
    r.published_version = r.ansp_version;
    r.deliveries = {
      ...r.deliveries,
      cisp: { state: "sent", attempts: 1, last_attempt_at: iso(), last_status_code: 200 },
      dss: { state: "sent", attempts: 1, last_attempt_at: iso(), last_status_code: 200 },
      uss_notify: { state: "sent", attempts: 1, last_attempt_at: iso(), last_status_code: 204 },
    };
    r.dss = { state: "written", since: iso(), ansp_version: r.ansp_version, dss_version: 1 };
    let alarm;
    for (const a of state.alarms) {
      if (a.restriction_id === r.id && a.kind === "cisp_not_published" && a.state !== "cleared") {
        a.state = "cleared";
        a.cleared_at = iso();
        a.clear_reason = "published";
        a.duration_s = 1;
        alarm = a;
      }
    }
    broadcast(stateFrame(r, { published: true, ...(alarm === undefined ? {} : { alarm }) }));
    return json(res, 200, r);
  }
  return json(res, 404, { error: "unknown control" });
}

function passToNext(req, res) {
  const upstream = http.request(
    {
      host: UPSTREAM.hostname,
      port: UPSTREAM.port,
      method: req.method,
      path: req.url,
      // What Caddy sets: the BFF trusts one hop (WEB_TRUSTED_PROXY_HOPS)
      // and checks a sign-in's Origin against this scheme and host.
      headers: {
        ...req.headers,
        "x-forwarded-for": req.socket.remoteAddress ?? "127.0.0.1",
        "x-forwarded-proto": "http",
        "x-forwarded-host": req.headers.host ?? `127.0.0.1:${PORT}`,
      },
    },
    (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", (err) => {
    if (!res.headersSent) json(res, 502, { title: "upstream unreachable", detail: err.message });
    else res.destroy(err);
  });
  req.pipe(upstream);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://mock");
  if (url.pathname.startsWith("/__mock/")) {
    void control(req, res, url.pathname);
    return;
  }
  if (url.pathname.startsWith("/v1/")) {
    void api(req, res, url);
    return;
  }
  passToNext(req, res);
});
server.on("upgrade", upgrade);

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock-api: 127.0.0.1:${PORT}, pages from ${UPSTREAM.origin}`);
});
