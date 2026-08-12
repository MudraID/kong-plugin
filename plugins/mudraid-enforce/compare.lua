-- mudraid-enforce: constant-time comparison for authentication tags.
--
-- WHY THIS EXISTS. bundle.lua and containment.lua both decide whether to trust
-- a fetched artifact by comparing a computed HMAC against a served one. Written
-- as `computed ~= served`, that comparison is Lua's string equality, which
-- short-circuits at the first differing byte. The time it takes therefore leaks
-- how long a common prefix the two share, and an attacker who can submit
-- candidate signatures and observe the timing can recover a valid tag one byte
-- at a time without ever holding the secret.
--
-- HOW MUCH THIS MATTERS HERE, STATED HONESTLY. Both comparisons sit on a
-- BACKGROUND POLL against a server this gateway authenticates to, not on the
-- hot path, and an attacker would need to be the thing serving those responses
-- while measuring a poll loop over a network. That is a long way from
-- practical. This is defence in depth on a primitive whose correct form costs
-- nothing measurable, not a response to a reachable exploit — and the reason to
-- write it down that way is so nobody later reads the fix as evidence that the
-- attack was live.
--
-- THE CONSTRUCTION. XOR-accumulate every byte pair and test the accumulator
-- once at the end, so every byte of the shorter input is always read. Lengths
-- are compared first and returned early on a mismatch: a length difference is
-- not secret (the encoding fixes it — a SHA-256 hex digest is 64 characters,
-- always) and looping to a length the caller does not control would be the
-- worse property.
--
-- Pure Lua 5.1+ — no bitwise operators, which LuaJIT has and 5.1 does not; the
-- difference is accumulated arithmetically instead so this module runs
-- identically in the gateway and in the plain-Lua test harness.

local _M = {}

--- Constant-time equality over the shared length of two strings.
-- @return true when `a` and `b` are the same string, false otherwise.
function _M.equals(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then
    return false
  end
  local len = #a
  if len ~= #b then
    return false
  end
  -- `diff` stays 0 only if every byte pair matched. Accumulated with addition
  -- over absolute differences rather than a bitwise OR so this needs no bit
  -- library; the property that matters is that the loop never exits early and
  -- the result is inspected exactly once.
  local diff = 0
  for i = 1, len do
    local d = a:byte(i) - b:byte(i)
    if d < 0 then
      d = -d
    end
    diff = diff + d
  end
  return diff == 0
end

return _M
