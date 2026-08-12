-- mudraid-enforce: adapter-channel client (EP-110-US-04).
--
-- Talks to the PUBLIC adapter channel with THIS adapter instance's per-adapter
-- bearer token (registered via the operator adapter registry; hashed at rest
-- server-side). The channel derives the tenant from the credential — this
-- client never names a platform id.
--
-- Endpoints, derived from ONE base URL (endpoints.lua):
--   POST {base}/api/v1/adapter/enforcement/heartbeat        -> desired version
--   GET  {base}/api/v1/adapter/enforcement/bundle           -> signed bundle
--   POST {base}/api/v1/adapter/enforcement/acknowledgements -> ack ingestion
--
-- THESE WERE /api/v1/internal/* UNTIL THIS CHANGE, and the credential was
-- already the right one — the per-adapter bearer, not a shared secret — so
-- nothing was exposed here. The problem was reachability: `internal` paths are
-- not routed for a customer, so a customer-installed gateway calling them gets
-- 404 and fails closed forever. The Python middleware was already on the public
-- channel; this brings the two adapters to the same paths as well as the same
-- credential.
--
-- (contract:
-- services/platform-integration-service/app/api/routes/enforcement_adapters.py)
--
-- All calls run on background timers (never on the proxy hot path) and are
-- single-attempt per tick — the poll loop is the retry.
--
-- The bearer token is never logged; failures log status codes only.
--
-- ===================== THE SECOND, SEPARATE CHANNEL =====================
-- The signed CONTAINMENT feed is a different artifact on a different owner:
-- enforcement-service owns it (doc 05 §25), not platform-integration, so it is
-- NOT served over the adapter channel above. fetch_containment/post_containment_ack
-- talk to enforcement-service directly, over the same X-Service-Secret transport
-- decide.lua uses for the private /decide route.
--
-- THE VALUE IS NOT THE SAME CREDENTIAL, and that difference is the point.
-- decide_service_secret is ONE workload secret shared by every gateway, so it
-- names no tenant; scoping a containment projection by it would let any holder
-- read any tenant's projection — the exact set of agents, actions and resources
-- that tenant has contained, and why. So the containment channel presents
-- containment_adapter_credential: an HMAC-authenticated credential an operator
-- mints for exactly one (organization, environment, adapter id), which the
-- server verifies and derives the served stream FROM
-- (services/enforcement-service/app/domain/containment/adapter_credential.py).
-- This gateway cannot even NAME another tenant's surface, in the same sense the
-- platform-integration adapter channel above cannot.
--
-- Deny-closed and never silently anonymous, on both: with no credential the
-- call is not made at all. The refusal reaches the hot path as "no verified
-- projection", which denies protected actions, rather than as an empty feed
-- that would read as "nothing is contained".

local http = require "resty.http"
local endpoints = require "kong.plugins.mudraid-enforce.endpoints"
local cjson_decode_mod = require("cjson.safe").new()
local cjson_encode_mod = require("cjson.safe").new()

-- Mark decoded JSON arrays with the array metatable so canonical
-- re-serialization can distinguish [] from {} (bundle payloads contain
-- empty arrays, e.g. required_scopes).
cjson_decode_mod.decode_array_with_array_mt(true)

local _M = {}

_M.null = cjson_decode_mod.null or require("cjson.safe").null
_M.array_mt = cjson_decode_mod.array_mt or require("cjson.safe").array_mt

--- The channel origin: the customer's `base_url` when set, else the
--- MudraID-operated `channel_url`.
---
--- base_url WINS, and the order matters. `channel_url` carries an internal
--- default (`http://platform-integration-service:8009`) so an existing
--- MudraID-operated gateway keeps working across this change. If the default
--- took precedence, a customer setting base_url would silently keep calling an
--- internal hostname that does not resolve for them — a misconfiguration that
--- looks like a network fault.
local function base_url(conf)
  local derived = endpoints.normalize_base(conf.base_url)
  if derived then
    return derived
  end
  return (conf.channel_url:gsub("/+$", ""))
end

local function request(conf, method, path, body_table)
  local client = http.new()
  client:set_timeout(conf.channel_timeout_ms)
  -- Deny-closed on the credential, the same rule decide.lua follows: no token
  -- means no request, never an anonymous one. Previously this concatenated
  -- conf.adapter_token unguarded, so a nil token raised inside the request
  -- rather than refusing before it.
  local authorization = endpoints.bearer(conf)
  if not authorization then
    return nil, nil, "no adapter_token configured"
  end
  local headers = {
    ["Authorization"] = authorization,
    ["Accept"] = "application/json",
  }
  local body
  if body_table ~= nil then
    body = cjson_encode_mod.encode(body_table)
    if not body then
      return nil, nil, "encode failed"
    end
    headers["Content-Type"] = "application/json"
  end
  local res, err = client:request_uri(base_url(conf) .. path, {
    method = method,
    body = body,
    headers = headers,
  })
  if not res then
    return nil, nil, err or "transport error"
  end
  local decoded
  if res.body and #res.body > 0 then
    decoded = cjson_decode_mod.decode(res.body)
  end
  return res.status, decoded
end

--- POST /heartbeat. Returns { desired_bundle_version, desired_payload_digest }
-- (either may be the JSON null sentinel when nothing is published), or
-- nil + error.
function _M.heartbeat(conf)
  local status, body, err = request(conf, "POST", endpoints.HEARTBEAT_PATH)
  if not status then
    return nil, err
  end
  if status ~= 200 or type(body) ~= "table" then
    return nil, "heartbeat status " .. tostring(status)
  end
  return body
end

--- GET /bundle. Returns the raw fetched bundle table (verification is the
-- caller's job — nothing here is trusted), or nil + error. A 404
-- NO_BUNDLE_PUBLISHED is reported distinctly so the poller can go quiet.
function _M.fetch_bundle(conf)
  local status, body, err = request(conf, "GET", endpoints.BUNDLE_PATH)
  if not status then
    return nil, err
  end
  if status == 404 then
    return nil, "no_bundle_published"
  end
  if status ~= 200 or type(body) ~= "table" then
    return nil, "bundle fetch status " .. tostring(status)
  end
  return body
end

--- POST /acknowledgements with one report. Returns true on acceptance.
-- A replayed report_id returns 201 with replayed=true server-side — still
-- success here. A 409 ACK_REPLAY_MISMATCH means OUR report content drifted
-- for a reused report_id; that is a bug fact, logged and treated as
-- delivered (retrying forever cannot succeed).
function _M.post_ack(conf, report)
  local status, _, err = request(
    conf, "POST", endpoints.ACK_PATH, report)
  if not status then
    return false, err
  end
  if status == 201 then
    return true
  end
  if status == 409 then
    return true, "ack_replay_mismatch"
  end
  return false, "ack status " .. tostring(status)
end

-- ---------------------------------------------------------------------------
-- Containment feed (enforcement-service, X-Service-Secret)
-- ---------------------------------------------------------------------------

-- Single-attempt request against enforcement-service. `secret` is deliberately
-- a parameter rather than read from conf here, so a caller cannot reach this
-- function without having decided which credential it is presenting — and this
-- plugin now holds two for that service (the shared /decide workload secret and
-- the surface-scoped containment adapter credential), which is exactly when
-- "whichever one is in conf" stops being a safe default.
local function service_request(conf, secret, method, url, body_table)
  if type(url) ~= "string" or url == "" then
    return nil, nil, "url unconfigured"
  end
  if type(secret) ~= "string" or secret == "" then
    -- Never anonymous. The route is private and authenticated; an anonymous
    -- attempt would be refused anyway, and must not even be made.
    return nil, nil, "service secret unconfigured"
  end
  local client = http.new()
  client:set_timeout(conf.channel_timeout_ms)
  local headers = {
    ["X-Service-Secret"] = secret,
    ["Accept"] = "application/json",
  }
  local body
  if body_table ~= nil then
    body = cjson_encode_mod.encode(body_table)
    if not body then
      return nil, nil, "encode failed"
    end
    headers["Content-Type"] = "application/json"
  end
  local res, err = client:request_uri(url, {
    method = method,
    body = body,
    headers = headers,
  })
  if not res then
    return nil, nil, err or "transport error"
  end
  local decoded
  if res.body and #res.body > 0 then
    decoded = cjson_decode_mod.decode(res.body)
  end
  return res.status, decoded
end

--- GET the current signed containment record. Returns the RAW decoded body —
--- verification is the caller's job, nothing here is trusted.
--
-- The feed head is honest about an unpublished stream (`published: false`,
-- HTTP 200), which is reported distinctly so the poller can go quiet instead of
-- logging a failure every tick. It is NOT an empty projection: a stream that
-- has never published has nothing to verify, so the adapter keeps having no
-- projection and protected actions keep failing closed.
function _M.fetch_containment(conf)
  local status, body, err = service_request(
    conf, conf.containment_adapter_credential, "GET", conf.containment_feed_url)
  if not status then
    return nil, err
  end
  if status == 404 then
    return nil, "no_containment_feed_published"
  end
  if status ~= 200 or type(body) ~= "table" then
    return nil, "containment feed status " .. tostring(status)
  end
  if body.published == false then
    return nil, "no_containment_feed_published"
  end
  return body
end

--- POST one signed adapter acknowledgement of the containment feed.
-- 201 is acceptance; the server dedups on (adapter, sequence), so a re-sent
-- acknowledgement is a no-op rather than a duplicated row that could skew a
-- convergence percentile. 401 means OUR ack signature did not verify — a
-- misconfiguration that retrying cannot fix, so it is reported distinctly.
function _M.post_containment_ack(conf, ack)
  local status, _, err = service_request(
    conf, conf.containment_adapter_credential, "POST", conf.containment_ack_url, ack)
  if not status then
    return false, err
  end
  if status == 201 or status == 200 then
    return true
  end
  if status == 401 then
    return false, "containment_ack_signature_rejected"
  end
  return false, "containment ack status " .. tostring(status)
end

return _M
