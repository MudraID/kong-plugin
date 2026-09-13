-- Exact request-byte binding for owner-configured action inputs.
-- Pure Lua; crypto/encoding are injected so the same vectors run outside Kong.
local canonical = require "kong.plugins.mudraid-enforce.canonical"
local _M = {}

function _M.bind(b, action, context, opts)
  if type(context.body) ~= "string" or #context.body == 0 or #context.body > 65536 then
    return nil, "request conditions require bounded exact bytes"
  end
  local content_type = context.content_type
  if type(content_type) ~= "string" or #content_type == 0 or #content_type > 256
    or content_type:find("[\r\n]") then
    return nil, "invalid content type"
  end
  local token = context.authorization
  if type(token) ~= "string" then return nil, "missing caller" end
  token = token:match("^%s*(.-)%s*$")
  if token:sub(1, 7):lower() == "bearer " then
    token = token:sub(8):match("^%s*(.-)%s*$")
  end
  if token == "" then return nil, "missing caller" end
  if type(action.required_scopes) ~= "table" then return nil, "missing scopes" end
  local scopes, seen = {}, {}
  for _, scope in ipairs(action.required_scopes) do
    if type(scope) ~= "string" then return nil, "invalid scope" end
    if not seen[scope] then scopes[#scopes + 1] = scope; seen[scope] = true end
  end
  table.sort(scopes)
  if opts.json and opts.json.array_mt then setmetatable(scopes, opts.json.array_mt) end
  local surface = b.payload.content.surface
  local material = {
    profile = "mudraid.execution.request/1",
    body_sha256 = opts.crypto.sha256_hex(context.body),
    content_type = content_type, http_method = context.method, path = context.path,
    caller_token_sha256 = opts.crypto.sha256_hex(token),
    platform_id = surface.platform_id, environment = surface.environment,
    resource = surface.canonical_resource_uri, action_key = action.action_key,
    action_version = action.action_version, mapping_id = action.mapping_id,
    mapping_version = action.mapping_revision, bundle_version = b.bundle_version,
    bundle_payload_digest = b.payload_digest, required_scopes = scopes,
  }
  for _, key in ipairs({"body_sha256", "http_method", "path", "caller_token_sha256",
    "platform_id", "environment", "resource", "action_key", "action_version",
    "mapping_id", "mapping_version", "bundle_version", "bundle_payload_digest"}) do
    if material[key] == nil or material[key] == "" then return nil, "incomplete binding" end
  end
  local encoded, err = canonical.encode(material, opts.json)
  if not encoded then return nil, err end
  return opts.crypto.sha256_hex(encoded), {
    profile = material.profile, body_sha256 = material.body_sha256,
    content_type = content_type, body_base64 = opts.encode_base64(context.body),
  }
end

return _M
