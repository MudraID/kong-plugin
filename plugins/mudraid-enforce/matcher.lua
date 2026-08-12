-- mudraid-enforce: canonical action matcher (EP-110-US-04, doc 03 A03-06/07).
--
-- Bundle schema 1.0 declares exactly one matcher kind: "mcp_tool_exact".
-- Matching is EXACT and case-sensitive on the JSON-RPC tools/call
-- params.name — never fuzzy, never normalized, never prefix/regex. An
-- ambiguous corpus (duplicate tool_name) is refused at build time so
-- runtime can never resolve ambiguity by table order (A03-06).
--
-- Pure Lua — unit-testable outside the gateway.

local _M = {}

-- Bounded action extraction (A03-07): params.name is a non-empty bounded
-- string; anything else is a deny, not a fallback.
local MAX_TOOL_NAME_LEN = 512
_M.MAX_TOOL_NAME_LEN = MAX_TOOL_NAME_LEN

--- Build an exact-lookup index from the verified bundle's action list.
-- @param actions  payload.content.matcher.actions (already schema-checked
--                 by bundle.verify: array of tables with string tool_name)
-- @return index table, or nil + error code
function _M.build(actions)
  local index = {}
  for i = 1, #actions do
    local action = actions[i]
    local name = action.tool_name
    if type(name) ~= "string" or name == "" or #name > MAX_TOOL_NAME_LEN then
      return nil, "BUNDLE_ACTION_TOOL_NAME_INVALID"
    end
    if index[name] ~= nil then
      -- Equal-specificity overlap: rejected before use, never resolved by
      -- iteration order (A03-06).
      return nil, "BUNDLE_MATCHER_AMBIGUOUS"
    end
    index[name] = action
  end
  return index
end

--- Resolve a tool invocation name to its canonical action.
-- @return action table on an exact match;
--         nil, "invalid_name" when the name is not a usable bounded string;
--         nil, "unmapped" when no exact mapping exists (deny, A03-08).
function _M.resolve(index, name)
  if type(name) ~= "string" or name == "" or #name > MAX_TOOL_NAME_LEN then
    return nil, "invalid_name"
  end
  local action = index[name]
  if action == nil then
    return nil, "unmapped"
  end
  return action
end

return _M
