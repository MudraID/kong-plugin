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
-- Doc 08 also defines a RESPONSE `response_authentication` (signed/MAC'd
-- decision) and request signing/replay hardening as the fuller profile;
-- those are a documented follow-up. The request-side service-secret
-- handshake here closes the "every real Kong->/decide call is denied"
-- gap without leaving the path unauthenticated.
--
-- ============================= PROVISIONAL =============================
-- The remaining /decide request/response envelope details (full doc-08 2.0
-- field set, response signature verification, replay protection) are
-- EP-220-owned. The shape below is a PROVISIONAL adapter-side envelope
-- carrying only facts this plugin actually holds (bundle binding, matched
-- canonical action, request framing, presented credential). When the full
-- doc-08 profile lands, ONLY this module changes — the handler's outcome
-- contract (allow / deny / error->deny) is stable.
--
-- PROVISIONAL request (POST conf.decide_url, JSON):
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
-- PROVISIONAL response: HTTP 200 with {"decision": "allow"|"deny", ...}.
-- ANY other status/shape is "error" (deny-closed). The raw presented
-- credential is forwarded ONLY to the internal enforcement service for
-- verification (mirroring verification-service /verify); it is never
-- logged here and never sent anywhere else.
-- =======================================================================

local cjson = require "cjson.safe"
local endpoints = require "kong.plugins.mudraid-enforce.endpoints"

local _M = {}

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
-- @return "allow" | "deny" | "error", detail table
function _M.call(conf, envelope)
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
  local body_text = res.body or ""
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
  if returned_id ~= envelope.decision_id then
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
  local now = _M.now()
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
