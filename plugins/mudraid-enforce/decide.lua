-- mudraid-enforce: /decide client (EP-110-US-04, doc 03 A03-09/10).
--
-- THE single client function through which every protected request obtains
-- its live decision. Honors the bundle's evaluation contract exactly:
-- decide_required=true, on_timeout=deny, on_error=deny. There is NO stub
-- or bypass flag by design: if no reachable /decide endpoint exists (not
-- configured, connection refused, timeout, malformed response), the outcome
-- is "error" and the handler denies with a typed reason. Absence of the
-- enforcement service can never become implicit allow.
--
-- ============================= AUTHENTICATION =========================
-- EP-220-US-01 landed the authoritative POST /api/v2/enforcement/decide as
-- a PRIVATE AUTHENTICATED route (doc 08 A08-06 "private authenticated
-- route"; §23 "private runtime/feed/evidence routes require workload
-- identity and authorization"). It authenticates the caller with a shared
-- service secret presented in the X-Service-Secret header — the same
-- internal service-to-service profile used across the platform
-- (X-Internal-Sync-Secret / X-Service-Secret), and the exact credential
-- the enforcement-service `require_enforcement_service_secret` dependency
-- verifies against ENFORCEMENT_SERVICE_SECRET.
--
-- This module attaches that credential from conf.decide_service_secret
-- (a Kong env-vault reference; never committed material). It is DENY-CLOSED
-- on the credential too: if /decide is configured but no secret is
-- available, the call is NOT made anonymously — the outcome is "error"
-- (DECIDE_CREDENTIAL_UNCONFIGURED), which the handler treats as deny. A
-- missing/invalid/expired credential on the server side returns 401/403,
-- which this module already maps to "error" -> deny.
--
-- ======================= RESPONSE AUTHENTICATION =======================
-- AUDIT-009 A9-02: the decision RESPONSE is now signature-verified WHEN
-- SIGNED. The authority signs every /decide response (RS256 over canonical
-- claims binding: signature profile + version, decision id, outcome +
-- stable reason code, tenant, environment, platform surface, agent,
-- action, canonical resource, bundle/policy versions, decided-at and a
-- bounded validity window — see enforcement-service's
-- app/application/decision_signature.py). This module verifies that
-- signature against the published enforcement_decision_signing key series
-- and this adapter's OWN bundle surface + matched action, refusing the
-- whole response on any mismatch (verify_signature below).
--
-- VERIFY WHEN PRESENT, REFUSE WHEN PRESENT-AND-WRONG. A response carrying
-- no signature is still read exactly as before — the authority activates
-- signing by rollout, and refusing every unsigned response would turn the
-- activation into a flag-day. A response CARRYING a signature must verify
-- completely: unknown key, mutated bound field, foreign surface or action,
-- expired window each refuse the whole response ("error" -> deny). Until
-- the authority-side activation is universal, a party able to terminate
-- TLS can still strip the signature — the transport + binding + freshness
-- checks below remain the floor, never described as more than they are.
--
-- ...UNTIL AN OPERATOR SAYS OTHERWISE. `require_signed_decisions` (schema.lua,
-- reaching this module as verify_opts.require_signed) closes exactly that
-- gap: with it set, an unsigned response is refused
-- (DECIDE_RESPONSE_SIGNATURE_REQUIRED -> deny) rather than read, so stripping
-- the signature stops being a way to remove the protection. It is OFF by
-- default and that default is the contracted state — a gateway upgraded to
-- this version behaves exactly as it did — and it is CONFIGURATION rather
-- than a constant because the Python middleware, this plugin and the
-- authority's per-surface signing rollout reach the switch-over at different
-- moments. The Python middleware carries the equivalent setting under the
-- same name; the two adapters must not disagree about what an unsigned
-- decision means on the same surface.
--
-- The mode governs ABSENCE ONLY. A present signature is verified identically
-- either way, and every signature failure deny-closes either way.
--
-- Request envelope (POST {base}/api/v1/adapter/enforcement/decide, JSON):
--   {
--     "schema_version": "mudraid.enforce.decide-request/1",
--     "decision_id": "<uuid minted by the adapter>",
--     "correlation_id": "<X-Correlation-ID>",
--     "adapter": { "type": "kong_mudraid_enforce", "version": "<plugin>" },
--     "bundle": { "version": <int>, "payload_digest": "<sha256hex>" },
--     "surface": { "platform_id", "environment",
--                  "canonical_resource_uri" },  -- all from the signed bundle
--     "action": { "action_key", "action_version", "tool_name",
--                 "mapping_id", "mapping_revision", "risk_class",
--                 "required_scopes" },
--     "request": { "transport": "mcp_streamable_http",
--                  "http_method", "path" },
--     "presented_authorization": "<raw Authorization header or null>"
--   }
--
-- Response: HTTP 200 with the versioned "2.0" envelope, read by
-- read_response below (contract, decision-id binding, freshness, optional
-- signature, closed decision vocabulary). ANY other status/shape is
-- "error" (deny-closed). The raw presented credential is forwarded ONLY to
-- the enforcement service for verification (mirroring
-- verification-service /verify); it is never logged here and never sent
-- anywhere else.
-- =======================================================================

local cjson = require "cjson.safe"
local endpoints = require "kong.plugins.mudraid-enforce.endpoints"
local canonical = require "kong.plugins.mudraid-enforce.canonical"
local base64 = require "kong.plugins.mudraid-enforce.base64"

local _M = {}

-- Pinned, not negotiated (the ``alg: none`` lesson). Mirrors
-- DECISION_SIGNATURE_PROFILE / DECISION_SIGNATURE_ALGORITHM in
-- enforcement-service's decision_signature.py and the Python middleware's
-- _decision_signature.py — three implementations, one set of constants they
-- are each checked against (shared corpus: adapter-conformance.json).
_M.SIGNATURE_PROFILE = "mudraid.decision.signature/1"
_M.SIGNATURE_ALGORITHM = "RS256"

-- Signature-window skew tolerance (seconds). Matches the authority's
-- MAX_CLOCK_SKEW and the Python middleware's _MAX_CLOCK_SKEW.
_M.SIGNATURE_CLOCK_SKEW_SECONDS = 300

-- The versioned request contract. Both adapters stamp this exact string and
-- enforcement-service validates it against an enumerated supported list; see
-- shared/mudraid_contracts/mudraid_contracts/adapters/decide_contract.py.
_M.ENVELOPE_SCHEMA = "mudraid.enforce.decide-request/1"

-- The authority's own response envelope version (doc 08). Validated, not
-- assumed: a response whose version we do not implement is one whose fields we
-- cannot read, and reading it anyway is how an "allow" gets believed.
_M.SUPPORTED_RESPONSE_SCHEMAS = { ["2.0"] = true }

-- A decision is a small JSON object. Anything at this scale is a fault or an
-- attack, and both are answered the same way.
_M.MAX_RESPONSE_BYTES = 64 * 1024
_M.MAX_DECISION_ID_LEN = 128

-- HTTP client seam. Resolved lazily so this module can be required (and its
-- deny-closed credential logic unit-tested) outside the gateway image where
-- resty.http is unavailable; production behaviour is unchanged (resty.http
-- is package.loaded-cached after the first call). Tests inject `_M._http`.
local function http_lib()
  return _M._http or require "resty.http"
end

--- Obtain one live decision. Single attempt — a retry here could
-- double-meter a root decision (A03-13); the caller denies on failure
-- instead of retrying.
-- @param verify_opts optional response-signature verification context:
--   { crypto = { verify_rs256(pem, msg, sig) },  -- crypto.lua, injected
--     json = { null = ..., array_mt = ... },     -- canonical encode opts
--     keys = { [key_id] = public_pem },          -- decision key series
--     expected = { platform_id, environment, canonical_resource_uri,
--                  action_key, bundle_version },  -- from the SIGNED bundle
--     require_signed = <boolean>,  -- conf.require_signed_decisions: refuse an
--                                  -- UNSIGNED response instead of reading it
--     now = <epoch seconds> }                     -- injectable for tests
-- @return "allow" | "deny" | "error", detail table
function _M.call(conf, envelope, verify_opts)
  -- THE PUBLIC ADAPTER CHANNEL, derived from one base URL. Previously this
  -- read conf.decide_url directly and presented conf.decide_service_secret in
  -- X-Service-Secret — MudraID's own workload credential, shared by every
  -- gateway, naming no tenant. A customer holding it could call the private
  -- enforcement route as us, and the Python middleware they installed
  -- alongside this plugin was already using a per-adapter bearer against the
  -- public channel. Two customer-installable adapters, two trust models, one
  -- of them requiring our internal secret.
  local url, url_err = endpoints.decide_url(conf)
  if not url then
    -- No stub-decide flag exists: unconfigured means not safely decided.
    return "error", { reason = "DECIDE_UNCONFIGURED", detail = url_err }
  end
  -- Deny-closed on the credential, unchanged in spirit and narrowed in scope:
  -- the adapter bearer is the ONLY credential this call will present. With
  -- none, no request is made at all — never an anonymous one, and never a
  -- fallback to some other configured secret.
  local authorization, cred_err = endpoints.bearer(conf)
  if not authorization then
    return "error", { reason = "DECIDE_CREDENTIAL_UNCONFIGURED", detail = cred_err }
  end
  local body = cjson.encode(envelope)
  if not body then
    return "error", { reason = "DECIDE_ENVELOPE_ENCODE_FAILED" }
  end
  local client = http_lib().new()
  client:set_timeout(conf.decide_timeout_ms)
  local res, err = client:request_uri(url, {
    method = "POST",
    body = body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json",
      ["X-Correlation-ID"] = envelope.correlation_id,
      -- THIS adapter instance's bearer. The server resolves the registered
      -- adapter from it and derives the tenant, environment and surface
      -- server-side, so this plugin never names a platform id and cannot
      -- speak for a tenant it was not issued for. A revoked or unknown token
      -- gets the route's single neutral 401, which maps to "error" -> deny.
      ["Authorization"] = authorization,
    },
  })
  if not res then
    -- Timeout and transport errors are indistinguishable "not safely
    -- decided" outcomes: on_timeout=deny / on_error=deny (bundle contract).
    return "error", { reason = "DECIDE_UNREACHABLE", detail = err }
  end
  if res.status ~= 200 then
    return "error", { reason = "DECIDE_STATUS_" .. tostring(res.status) }
  end
  return _M.read_response(res.body or "", envelope.decision_id, verify_opts)
end


--- Read one authoritative 200 body, or refuse. Pure — no transport, no
-- Kong PDK — so the shared conformance corpus can drive it directly, the
-- way the Python runner drives the middleware's _read_decision.
-- @return "allow" | "deny" | "error", detail table
function _M.read_response(body_text, expected_decision_id, verify_opts)
  if #body_text > _M.MAX_RESPONSE_BYTES then
    -- Refused before parsing: an oversized decision is not a decision.
    return "error", { reason = "DECIDE_RESPONSE_OVERSIZED" }
  end
  local decoded = cjson.decode(body_text)
  if type(decoded) ~= "table" then
    return "error", { reason = "DECIDE_RESPONSE_MALFORMED" }
  end
  -- Response contract: absent and unsupported are the same refusal.
  if not _M.SUPPORTED_RESPONSE_SCHEMAS[decoded.schema_version] then
    return "error", { reason = "DECIDE_RESPONSE_SCHEMA_UNSUPPORTED" }
  end
  -- BINDING. Without a decision id equal to the one we sent, "allow" is a
  -- string anything on the path could have produced — including a replay of a
  -- different request's genuine allow.
  local returned_id = decoded.decision_id
  if type(returned_id) ~= "string" or returned_id == ""
    or #returned_id > _M.MAX_DECISION_ID_LEN then
    return "error", { reason = "DECIDE_RESPONSE_DECISION_ID_INVALID" }
  end
  if returned_id ~= expected_decision_id then
    return "error", { reason = "DECIDE_RESPONSE_DECISION_ID_MISMATCH" }
  end
  -- ── FRESHNESS ─────────────────────────────────────────────────────────────
  --
  -- A decision is an answer about a moment. Without an age bound a captured
  -- allow stays usable indefinitely — and worse here than usual, because the
  -- decision id is ECHOED from the request, so replaying a whole exchange
  -- would pair a stale allow with a fresh-looking id. The binding above stops
  -- one request's answer being used for another; only this stops YESTERDAY's
  -- answer being used for today's.
  --
  -- Absent or unparseable is a refusal, never an unbounded default.
  local decided_at = _M.parse_instant(decoded.decided_at)
  if not decided_at then
    return "error", { reason = "DECIDE_RESPONSE_DECIDED_AT_INVALID" }
  end
  local now = (verify_opts and verify_opts.now) or _M.now()
  if decided_at - _M.CLOCK_SKEW_SECONDS > now then
    return "error", { reason = "DECIDE_RESPONSE_DATED_IN_FUTURE" }
  end
  if now - decided_at > _M.MAX_DECISION_AGE_SECONDS then
    return "error", { reason = "DECIDE_RESPONSE_STALE" }
  end
  -- The authority's own bound, when it sets one.
  local deadline_at = _M.parse_instant(decoded.deadline_at)
  if deadline_at and now - _M.CLOCK_SKEW_SECONDS > deadline_at then
    return "error", { reason = "DECIDE_RESPONSE_PAST_DEADLINE" }
  end

  -- ── SIGNATURE (A9-02): verify when present, refuse when present-and-wrong ──
  --
  -- Placed AFTER the envelope-level binding so the signature is checked on a
  -- response already known to answer THIS request, and BEFORE the outcome is
  -- read so no allow/deny is ever surfaced from a response whose signature
  -- failed. cjson decodes JSON null to a truthy sentinel, so absence is
  -- checked by type, mirroring bundle.lua's json_null handling.
  local sig = decoded.signature
  local sig_absent = sig == nil
    or (verify_opts and verify_opts.json and sig == verify_opts.json.null)
    or (not verify_opts and type(sig) ~= "table")
  if sig_absent then
    -- MANDATORY MODE (conf.require_signed_decisions). Verify-when-present is
    -- the rollout posture; this is the destination. Once the authority signs
    -- every response for a surface, an UNSIGNED response there is a stripped
    -- signature — the exact thing the signature exists to detect — and reading
    -- it would leave a TLS-terminating party able to remove the protection by
    -- deleting a field. The operator says when that point is reached, per
    -- gateway, because the fleet reaches it at different moments.
    --
    -- Only ABSENCE is governed here. A PRESENT signature is verified
    -- identically in both modes below, and every failure deny-closes in both:
    -- turning the requirement off is not a way to get a bad signature read.
    if verify_opts and verify_opts.require_signed then
      -- Its own reason, not the invalid one. "No signature at all" is a
      -- stalled or misconfigured rollout; "a signature that did not check
      -- out" is a key problem or an attack. An operator reading the log has
      -- to be able to tell them apart — they lead to opposite actions.
      return "error", { reason = "DECIDE_RESPONSE_SIGNATURE_REQUIRED" }
    end
  else
    local serr = _M.verify_signature(decoded, verify_opts)
    if serr then
      return "error", { reason = "DECIDE_RESPONSE_SIGNATURE_INVALID", detail = serr }
    end
  end

  if type(decoded.decision) ~= "string" then
    return "error", { reason = "DECIDE_RESPONSE_MALFORMED" }
  end
  if decoded.decision == "allow" then
    return "allow", decoded
  end
  if decoded.decision == "deny" then
    return "deny", decoded
  end
  -- Unknown decision vocabulary is never optimistically interpreted.
  return "error", { reason = "DECIDE_DECISION_UNRECOGNIZED" }
end


--- Verify a PRESENT decision-response signature. nil on success, else a
-- reason string (every reason is answered identically by the caller — the
-- response is refused whole — so nothing on the wire distinguishes "wrong
-- key" from "wrong surface" for a probing attacker).
--
-- Mirrors verify_decision_signature in the Python middleware and the
-- reference verifier in enforcement-service's decision_signature.py; the
-- shared corpus (adapter-conformance.json, decide_response_signature) is run
-- against all of them. Order is theirs too: structural checks, the
-- asymmetric operation, and only THEN are the claims compared against the
-- envelope in hand and this adapter's own expectations.
function _M.verify_signature(decoded, opts)
  local sig = decoded.signature
  if type(sig) ~= "table" then
    return "signature is not an object"
  end
  if type(opts) ~= "table" or type(opts.crypto) ~= "table"
    or type(opts.crypto.verify_rs256) ~= "function" then
    -- A missing verifier must never read as a valid signature.
    return "signature verification is unavailable"
  end
  if type(opts.keys) ~= "table" or next(opts.keys) == nil then
    -- A signed response with no keys to check it against is unverifiable,
    -- which is a refusal — never "nothing to check".
    return "no decision verification keys are available"
  end

  if sig.profile ~= _M.SIGNATURE_PROFILE then
    return "unsupported signature profile"
  end
  -- Compared against the pinned constant, never read from the signature and
  -- used — the ``alg: none`` lesson.
  if sig.algorithm ~= _M.SIGNATURE_ALGORITHM then
    return "unsupported signature algorithm"
  end

  local key_id = sig.key_id
  if type(key_id) ~= "string" or key_id == "" then
    return "signature names no key"
  end
  local public_pem = opts.keys[key_id]
  if type(public_pem) ~= "string" or public_pem == "" then
    -- Unknown or retired key — the rotation refusal. A key no longer
    -- published is a key whose signatures are no longer trusted.
    return "signature names an unknown key"
  end

  local claims = sig.claims
  if type(claims) ~= "table" then
    return "signature carries no claims"
  end
  if claims.key_id ~= key_id then
    return "claims name a different key than the signature"
  end
  if claims.profile ~= _M.SIGNATURE_PROFILE then
    return "claims name a different signature profile"
  end
  if claims.algorithm ~= _M.SIGNATURE_ALGORITHM then
    return "claims name a different signature algorithm"
  end

  local claim_bytes, cerr = canonical.encode(claims, opts.json)
  if not claim_bytes then
    return "claims could not be canonicalized: " .. tostring(cerr)
  end
  local raw = base64.decode(sig.signature)
  if not raw then
    return "signature is not valid base64"
  end
  local ok, verr = opts.crypto.verify_rs256(public_pem, claim_bytes, raw)
  if not ok then
    return verr or "signature does not verify"
  end

  -- ── Only now are the claims trustworthy enough to be compared ─────────────
  --
  -- Claims ↔ envelope: the unsigned envelope copy of every signed field must
  -- agree byte-for-byte, so an edit to the envelope alone is a refusal. The
  -- cjson null sentinel and Lua nil are the same fact (absence) here.
  local null = opts.json and opts.json.null
  local function normalized(v)
    if v == null then return nil end
    return v
  end
  local bound = { "decision_id", "outcome", "decision", "decided_at", "deadline_at" }
  for i = 1, #bound do
    local field = bound[i]
    if normalized(claims[field]) ~= normalized(decoded[field]) then
      return "signature does not cover this envelope (" .. field .. ")"
    end
  end
  local envelope_reason = type(decoded.reason) == "table"
    and normalized(decoded.reason.primary) or nil
  if normalized(claims.reason_primary) ~= envelope_reason then
    return "signature does not cover this envelope (reason)"
  end

  -- Claims ↔ this adapter's own surface and request (from the SIGNED bundle,
  -- never from the response being checked). Each nil expectation skips its
  -- comparison; a present one that the claims contradict refuses.
  local expected = opts.expected or {}
  if expected.platform_id ~= nil and claims.platform_id ~= expected.platform_id then
    return "decision is bound to another platform"
  end
  if expected.environment ~= nil and claims.environment ~= expected.environment then
    return "decision is bound to another environment"
  end
  if expected.canonical_resource_uri ~= nil
    and claims.resource ~= expected.canonical_resource_uri then
    return "decision is bound to another resource"
  end
  if expected.action_key ~= nil and claims.action_key ~= expected.action_key then
    return "decision is bound to another action"
  end
  if expected.bundle_version ~= nil and claims.bundle_version ~= expected.bundle_version then
    return "decision is bound to another bundle version"
  end

  if expected.execution_request_digest ~= nil
    and claims.execution_request_digest ~= expected.execution_request_digest then
    return "decision is bound to another execution"
  end

  local not_before = _M.parse_instant(claims.not_before)
  local expires_at = _M.parse_instant(claims.expires_at)
  if not not_before or not expires_at then
    return "signature carries no usable validity window"
  end
  local moment = opts.now or _M.now()
  if moment + _M.SIGNATURE_CLOCK_SKEW_SECONDS < not_before then
    return "decision signature is not yet valid"
  end
  if moment - _M.SIGNATURE_CLOCK_SKEW_SECONDS > expires_at then
    return "decision signature has expired"
  end

  return nil
end


-- ── Freshness constants and instant parsing ─────────────────────────────────
--
-- Mirrors _read_decision in the Python middleware. The two adapters must refuse
-- the same responses for the same reasons, or "portable enforcement" has a gap
-- in it that only shows up on one gateway.
_M.MAX_DECISION_AGE_SECONDS = 60
_M.CLOCK_SKEW_SECONDS = 30

--- Seconds since epoch. Injectable so tests are not clock-dependent.
function _M.now()
  return os.time()
end

--- Parse an ISO-8601 instant to epoch seconds, or nil.
--
-- A NAIVE timestamp (no offset, no Z) is refused rather than assumed UTC. The
-- ambiguity is a whole timezone wide, and guessing errs in the direction that
-- makes a decision look FRESHER than it is for any eastward offset — which is
-- the direction that admits a stale allow.
function _M.parse_instant(value)
  if type(value) ~= "string" or value == "" then
    return nil
  end
  local y, mo, d, h, mi, sec, rest =
    value:match("^(%d%d%d%d)-(%d%d)-(%d%d)[Tt](%d%d):(%d%d):(%d%d)(.*)$")
  if not y then
    return nil
  end
  -- Fractional seconds are permitted and ignored; the offset must follow.
  rest = rest:gsub("^%.%d+", "")

  local offset = 0
  if rest == "Z" or rest == "z" then
    offset = 0
  else
    local sign, oh, om = rest:match("^([%+%-])(%d%d):?(%d%d)$")
    if not sign then
      return nil  -- naive, or an offset we do not understand: refuse
    end
    offset = (tonumber(oh) * 3600 + tonumber(om) * 60) * (sign == "-" and -1 or 1)
  end

  -- os.time with a UTC-normalised table. `!*t` formatting is not available for
  -- construction, so the local-time skew is removed by measuring it once.
  local as_local = os.time({
    year = tonumber(y), month = tonumber(mo), day = tonumber(d),
    hour = tonumber(h), min = tonumber(mi), sec = tonumber(sec), isdst = false,
  })
  if not as_local then
    return nil
  end
  local probe = os.time(os.date("!*t", as_local))
  local local_offset = as_local - probe
  return as_local + local_offset - offset
end


return _M
