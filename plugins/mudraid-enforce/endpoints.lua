-- mudraid-enforce: one base URL in, every adapter endpoint out.
--
-- WHY THIS EXISTS
-- ===============
-- The Python middleware takes TWO values from a customer and derives the rest::
--
--     HttpDecideClient(base_url=..., adapter_token=...)
--
-- This plugin took a different shape for the same job: an explicit
-- `channel_url`, an explicit `decide_url`, and — the part that cannot ship —
-- `decide_service_secret`, MudraID's own workload credential, presented as
-- `X-Service-Secret` to a private route.
--
-- THAT IS NOT A CONFIGURATION DIFFERENCE, IT IS A DIFFERENT TRUST MODEL. A
-- customer holding `decide_service_secret` holds the credential every MudraID
-- gateway shares. It names no tenant, so it cannot be scoped to them, and it
-- authenticates callers to the private enforcement route as us. Shipping the
-- Python middleware and this plugin together would have handed customers two
-- integration models, one of which requires our internal secret.
--
-- So the two adapters now speak the SAME public channel:
--
--     bundle    GET  {base}/api/v1/adapter/enforcement/bundle
--     decide    POST {base}/api/v1/adapter/enforcement/decide
--     keys      GET  {base}/api/v1/adapter/enforcement/keys
--     heartbeat POST {base}/api/v1/adapter/enforcement/heartbeat
--     acks      POST {base}/api/v1/adapter/enforcement/acknowledgements
--
-- authenticated by ONE per-adapter bearer, from which the server derives the
-- tenant, environment and surface. This module is the derivation, kept in one
-- file so the two adapters cannot drift into different paths.
--
-- THE OVERRIDES ARE NOT THE CUSTOMER SETUP, and the distinction matters.
-- `channel_url` and `decide_url` remain, for MudraID-operated deployments that
-- reach a service over a private address and for tests pointing at a loopback
-- stub. Each REPLACES one derived URL and is validated exactly as strictly.
-- Supplying one changes where a request goes, never how carefully it is
-- checked — the same rule the Python client's docstring states for its own
-- overrides.
--
-- Mirrors `_BUNDLE_PATH` / `_DECIDE_PATH` / `_KEYS_PATH` in
-- sdks/mudraid-middleware-python/src/mudraid_platform_middleware/decide_client.py.
-- kong/tests/lua/test_endpoints.lua asserts the two agree by reading that file,
-- so a path renamed on one side fails on the other rather than becoming a
-- customer whose gateway 404s while their middleware works.

local _M = {}

_M.PREFIX = "/api/v1/adapter/enforcement"

_M.BUNDLE_PATH = _M.PREFIX .. "/bundle"
_M.DECIDE_PATH = _M.PREFIX .. "/decide"
_M.KEYS_PATH = _M.PREFIX .. "/keys"
_M.HEARTBEAT_PATH = _M.PREFIX .. "/heartbeat"
_M.ACK_PATH = _M.PREFIX .. "/acknowledgements"

--- Strip trailing slashes so `https://api.example/` and `https://api.example`
--- derive byte-identical URLs. A base URL that differs only by a slash must not
--- produce two different request lines — that difference reaches a server as a
--- 404 nobody can explain from the config.
function _M.normalize_base(base)
  if type(base) ~= "string" then
    return nil
  end
  local trimmed = base:gsub("%s+$", ""):gsub("^%s+", "")
  if trimmed == "" then
    return nil
  end
  trimmed = trimmed:gsub("/+$", "")
  if not trimmed:match("^https?://") then
    return nil
  end
  return trimmed
end

--- Resolve one endpoint: an explicit override if given, else derived from base.
---
--- Returns nil plus a reason rather than a partial URL. A caller that receives
--- nil must refuse the call — deriving `nil .. path` would produce a request to
--- a relative path, which is the shape that turns a misconfiguration into a
--- request somewhere unintended.
function _M.resolve(base, override, path)
  if type(override) == "string" and override ~= "" then
    return override
  end
  local normalized = _M.normalize_base(base)
  if not normalized then
    return nil, "no base_url configured (and no explicit override)"
  end
  return normalized .. path
end

function _M.bundle_url(conf)
  return _M.resolve(conf.base_url, conf.channel_url_override, _M.BUNDLE_PATH)
end

function _M.decide_url(conf)
  return _M.resolve(conf.base_url, conf.decide_url, _M.DECIDE_PATH)
end

function _M.keys_url(conf)
  return _M.resolve(conf.base_url, conf.keys_url, _M.KEYS_PATH)
end

function _M.heartbeat_url(conf)
  return _M.resolve(conf.base_url, conf.channel_url_override, _M.HEARTBEAT_PATH)
end

function _M.ack_url(conf)
  return _M.resolve(conf.base_url, conf.channel_url_override, _M.ACK_PATH)
end

--- The one credential a customer holds.
---
--- Deliberately NOT falling back to any other configured secret. An adapter
--- with no token makes no call at all, which reaches the hot path as a refusal
--- rather than as an anonymous request that some route might answer.
function _M.bearer(conf)
  local token = conf.adapter_token
  if type(token) ~= "string" or token == "" then
    return nil, "no adapter_token configured"
  end
  return "Bearer " .. token
end

return _M
