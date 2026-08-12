-- mudraid-enforce: request-path normalization for the protected-surface test.
--
-- ============================== WHY THIS EXISTS =========================
-- `is_protected` decides whether the whole control loop runs. It does a byte
-- prefix compare of the request path against `conf.protected_paths`, and the
-- path it compares comes from `kong.request.get_path()`.
--
-- That value is the RAW path — Kong's PDK takes `ngx.var.request_uri` and cuts
-- it at the first "?", so percent-escapes arrive undecoded and dot segments
-- arrive unresolved. Kong's ROUTER, meanwhile, matches on a normalized path.
-- The two disagreeing is the bug: a request written as
--
--     POST /%6dcp/messages          (%6d is "m")
--     POST /mcp/../mcp/messages
--
-- is routed by Kong to the same protected upstream, and reaches `is_protected`
-- as a string that does not start with "/mcp". The plugin then returns early —
-- no header strip, no framing check, no containment check, NO /decide — and the
-- request is forwarded to the protected upstream untouched. Every guarantee in
-- doc 03 is skipped by an encoding the gateway itself considers equivalent.
--
-- ========================== WHAT THIS DOES ABOUT IT =====================
-- `_M.candidates` returns every spelling of the path the surface test should
-- consider, and `is_protected` treats a match on ANY of them as protected. The
-- union, not a replacement, and the direction is deliberate: normalization can
-- only ADD protected classifications here, never remove one. If some future
-- Kong hands us an already-normalized path, normalizing again is idempotent and
-- the extra candidate is the same string; if a normalization here is WRONG in
-- the widening direction, the cost is that an unprotected request runs the
-- control loop and gets a decision it did not need. Both failure modes are
-- survivable. The one that is not — a protected request skipping the loop — is
-- the one this closes.
--
-- ============================== DECODE ONCE =============================
-- Percent-decoding is applied EXACTLY ONCE, which is what RFC 3986 §2.4 says
-- ("implementations must not percent-decode more than once") and what Kong's
-- own router does. So `%252f` decodes to the literal text "%2f" and stops; it
-- does not become "/". Decoding repeatedly would invent equivalences the
-- gateway does not honour, and the routing layer is the authority on which
-- spellings reach the same upstream.
--
-- Pure Lua 5.1+ — no ngx/Kong dependency, so it is unit-testable outside the
-- gateway image like matcher.lua and bundle.lua.

local _M = {}

--- Percent-decode a path, once.
-- Only well-formed `%XX` escapes are decoded; a stray "%" or a truncated escape
-- is left verbatim rather than guessed at.
function _M.percent_decode(s)
  if type(s) ~= "string" then
    return nil
  end
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

--- Remove dot segments per RFC 3986 §5.2.4.
--
-- "/a/./b"     -> "/a/b"
-- "/a/b/../c"  -> "/a/c"
-- "/../a"      -> "/a"   (a leading ".." cannot escape the root)
--
-- A trailing "." or ".." keeps the trailing slash the RFC's algorithm produces,
-- so "/a/b/.." is "/a/" and not "/a" — matching the reference algorithm rather
-- than a tidier-looking variant of it.
function _M.remove_dot_segments(s)
  if type(s) ~= "string" then
    return nil
  end
  local out = {}
  local trailing_slash = false
  -- Walk the segments in order. `out` is used as a stack: ".." pops, "." is
  -- dropped, anything else is pushed.
  --
  -- The leading "/" is removed BEFORE iterating and re-attached at the end.
  -- Left in place it produces an empty first segment, which is pushed like any
  -- other and then joined behind the re-attached slash — yielding "//mcp" for
  -- "/mcp". Under the union rule in handler.lua that would not have been
  -- exploitable (the raw spelling is always a candidate), but it would have made
  -- the normalized candidate useless for every absolute path, which is all of
  -- them.
  local leading_slash = s:sub(1, 1) == "/"
  local rest = leading_slash and s:sub(2) or s
  for segment, sep in rest:gmatch("([^/]*)(/?)") do
    if segment == "" and sep == "" then
      break
    end
    if segment == "." then
      trailing_slash = true
    elseif segment == ".." then
      if #out > 0 then
        table.remove(out)
      end
      trailing_slash = true
    else
      out[#out + 1] = segment
      trailing_slash = sep == "/"
    end
  end
  local joined = table.concat(out, "/")
  local result = (leading_slash and "/" or "") .. joined
  if trailing_slash and result:sub(-1) ~= "/" then
    result = result .. "/"
  end
  return result
end

--- Fully normalize one path: decode once, then resolve dot segments.
function _M.normalize(s)
  local decoded = _M.percent_decode(s)
  if decoded == nil then
    return nil
  end
  return _M.remove_dot_segments(decoded)
end

--- Strip the query and fragment from a request path.
--
-- Kong's `get_path()` already cuts at "?", so on the gateway this is a no-op.
-- It is here anyway because the SEGMENT-BOUNDARY rule below makes a trailing
-- query the difference between a match and a miss: `matches_prefix("/mcp?x=1",
-- "/mcp")` is false — "/mcp?" is neither "/mcp" nor "/mcp/". Under the old
-- lexical prefix test a query was harmless; under the correct test it would be
-- a bypass. The stripping is what keeps the tightening from opening a hole.
function _M.strip_query(s)
  if type(s) ~= "string" then
    return nil
  end
  return (s:gsub("[?#].*$", ""))
end

--- Normalize a CONFIGURED protected-path prefix, or say why it is unusable.
--
-- @return normalized prefix, or nil + reason
--
-- The operator writes these; a prefix whose meaning depends on normalization is
-- a prefix whose meaning the operator has not stated. So dot segments and
-- percent-escapes are REFUSED here rather than quietly resolved — `/mcp/../x`
-- and `/%6dcp` are told to be written as `/x` and `/mcp`. That is the opposite
-- of how a REQUEST path is treated (every spelling is considered, and the union
-- widens protection), and the asymmetry is deliberate: a hostile request should
-- be interpreted generously, a configuration file literally.
--
-- A trailing slash IS accepted and stripped, because `/mcp/` and `/mcp` are the
-- same surface under the canonical rule and rejecting one spelling of an
-- unambiguous intent would be pedantry rather than safety.
function _M.normalize_prefix(p)
  if type(p) ~= "string" or p == "" then
    return nil, "must be a non-empty string"
  end
  if p:sub(1, 1) ~= "/" then
    return nil, "must be an absolute path beginning with '/'"
  end
  if p:find("[?#]") then
    return nil, "must be a path only, with no query string or fragment"
  end
  if p:find("%%") then
    return nil, "must be written literally, without percent-escapes"
  end
  -- Trailing slashes carry no meaning under the canonical rule, so they are
  -- removed BEFORE the interior checks below. Order matters: the "//" check is
  -- about an empty segment in the MIDDLE of a path, and running it first would
  -- reject "/mcp///" — repeated trailing slashes, whose intent is not in doubt —
  -- with a message about empty segments.
  local stripped = p:gsub("/+$", "")
  if stripped == "" then
    return "/"  -- the whole surface; every path is a descendant of the root
  end
  if stripped:find("/%.%.?/") or stripped:match("/%.%.?$") then
    return nil, "must not contain '.' or '..' segments"
  end
  if stripped:find("//") then
    return nil, "must not contain empty segments ('//')"
  end
  return stripped
end

--- Does one request-path spelling fall under one configured prefix?
--
-- THE CANONICAL RULE (AUDIT-008 P1-3): the exact path, or a descendant
-- separated by "/". Nothing else.
--
--   prefix "/mcp"  matches  "/mcp", "/mcp/", "/mcp/tools", "/mcp//tools"
--                  MISSES   "/mcpfoo", "/mcp-evil", "/mcpevil/steal"
--
-- The old test was `candidate:sub(1, #p) == p` — a LEXICAL prefix, which does
-- not know that a path is made of segments. It protected `/mcpfoo` and
-- `/mcp-evil` too. That direction is fail-closed, so it was never an authority
-- bypass; what it was is a disagreement between the implementation and the
-- single-segment surface the deployment declares, which shows up as an
-- unrelated neighbouring route suddenly answering 405 or 400 because the MCP
-- control loop was applied to it.
function _M.matches_prefix(candidate, prefix)
  if type(candidate) ~= "string" or type(prefix) ~= "string" or prefix == "" then
    return false
  end
  if prefix == "/" then
    return candidate:sub(1, 1) == "/"
  end
  -- Tolerate an un-normalized prefix reaching here (the schema validator
  -- rejects them at config load, but this function is also called directly).
  prefix = prefix:gsub("/+$", "")
  if prefix == "" then
    return candidate:sub(1, 1) == "/"
  end
  if candidate == prefix then
    return true
  end
  return candidate:sub(1, #prefix + 1) == prefix .. "/"
end

--- Is `request_path` on one of the declared bundled surfaces?
--
-- THE PROTECTED-SURFACE PREDICATE ITSELF, and it lives here rather than in
-- handler.lua for the reason tenants.lua gives about its own selection rule:
-- handler.lua cannot be loaded without ngx/Kong, so a test asserting about a
-- copy of this logic asserts about the copy. The gate that decides whether the
-- entire control loop runs should be exercised directly, in the harness, by the
-- same function the gateway calls.
--
-- Two rules compose here and they pull in opposite directions on purpose:
--
--   * every SPELLING of the request path is considered (`candidates`), so an
--     encoded or dot-segmented path cannot slip past the gate — that direction
--     can only ADD protection;
--   * each spelling is tested at a SEGMENT BOUNDARY (`matches_prefix`), so a
--     neighbouring route that merely starts with the same characters is not
--     swept in — that direction can only REMOVE over-protection.
--
-- Together they mean: exactly the declared surface and its descendants, however
-- the request chooses to spell them.
function _M.is_protected(paths, request_path)
  if type(paths) ~= "table" then
    return false
  end
  local candidates = _M.candidates(request_path)
  for i = 1, #paths do
    for j = 1, #candidates do
      if _M.matches_prefix(candidates[j], paths[i]) then
        return true
      end
    end
  end
  return false
end

--- Every spelling of `s` the protected-surface test must consider.
--
-- Always includes `s` itself, so this can only widen the set of requests
-- classified as protected — never narrow it. Duplicates are collapsed so the
-- common case (an already-normal path) costs one comparison, as before.
function _M.candidates(s)
  if type(s) ~= "string" or s == "" then
    return {}
  end
  -- Query/fragment first: see strip_query for why the segment-boundary rule
  -- makes this load-bearing rather than cosmetic.
  s = _M.strip_query(s)
  if s == "" then
    return {}
  end
  local out, seen = { s }, { [s] = true }
  local decoded = _M.percent_decode(s)
  if decoded and not seen[decoded] then
    seen[decoded] = true
    out[#out + 1] = decoded
  end
  local normalized = _M.normalize(s)
  if normalized and not seen[normalized] then
    seen[normalized] = true
    out[#out + 1] = normalized
  end
  return out
end

return _M
