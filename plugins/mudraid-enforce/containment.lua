-- mudraid-enforce: signed containment projection (doc 05 A05-06/A05-07).
--
-- WHAT THIS IS. The adapter half of the runtime containment index. A05-06
-- requires an enforcement adapter to
--
--   1. check a signed, scoped containment projection BEFORE any allow;
--   2. apply updates ATOMICALLY; and
--   3. ACKNOWLEDGE the active sequence.
--
-- This module owns (1) and (2) as pure, injected-crypto Lua, and mints the
-- authenticated body for (3). handler.lua owns the timers and the swap.
--
-- ============================ THE WIRE FORMAT ==========================
-- The producer is enforcement-service. The bytes this module verifies are
-- EXACTLY ContainmentFeedRecord.canonical_bytes() in
-- services/enforcement-service/app/domain/containment/feed/record.py:
--
--   head  = org \0 env \0 kind \0 sequence \0 issued_at
--   entry = target_type \0 target_id \0 scope \0 op \0 state_epoch \0
--           reason_code \0 effective_at
--   bytes = head .. \x1f .. table.concat(entries, "\x1f")
--
-- (NUL field separator, US entry separator — both excluded from every value
-- they join, which is what keeps the serialization injective. An EMPTY entry
-- list still emits the trailing \x1f, so an empty snapshot has stable bytes.)
--
-- The signature is FeedKeyring.sign(): HMAC-SHA256, lowercase hex, over those
-- bytes (feed/signing.py, FEED_SIGNATURE_ALGORITHM).
--
-- TIMESTAMPS ARE USED VERBATIM. Both instants are canonicalized by Python as
-- `datetime.isoformat()`, and FastAPI's encoder emits that same string into the
-- JSON. This module therefore signs over the string it was SERVED and never
-- reformats it — a re-rendered instant ("Z" for "+00:00", a dropped
-- microsecond) is different bytes and would fail a signature that is in fact
-- valid. Parsing happens only for the freshness arithmetic, on a copy.
--
-- ============================== DENY-CLOSED ============================
-- Every distinguishable cause is its own typed refusal, in bundle.verify's
-- style and for bundle.verify's reason: two of them —
-- CONTAINMENT_SIGNING_SECRET_UNCONFIGURED and CONTAINMENT_SIGNING_KEY_UNKNOWN
-- — are MISCONFIGURATIONS that will never clear on their own, and reporting
-- them as an ordinary fetch failure leaves an operator waiting for a poll that
-- is never going to fix it.
--
-- A refused record is NOT applied: the adapter keeps its last verified
-- projection (still bounded by max staleness) and, if it has none, protected
-- actions on the surface fail CLOSED. An unsigned or HMAC-failing projection is
-- never trusted, and "no projection" is never read as "nothing is contained".
--
-- ==================== WHAT THIS ADAPTER CAN EVALUATE ====================
-- A feed entry names (target_type, target_id, scope). A Kong request, before
-- /decide, knows only what the HMAC-verified BUNDLE binds it to — the surface
-- (platform id, environment, canonical resource uri) — plus the exactly matched
-- canonical action. It does not verify the presented bearer token and therefore
-- resolves no agent, client, grant or credential identity.
--
-- So this module evaluates EVALUABLE_TARGET_TYPES and nothing else, and it says
-- so rather than pretending: entries of any other type are COUNTED on the
-- projection (`unevaluable`) and left to the authoritative live path. That is
-- sound here and only here because this adapter is a LIVE adapter — the signed
-- bundle it runs under declares mode="live"/decide_required=true, bundle.lua
-- refuses any bundle that says otherwise, and enforcement-service's /decide
-- consults the authoritative containment source itself
-- (infrastructure/decision/seams.py, ContainmentStateFactSource). The local
-- projection is therefore a STRICTER pre-/decide gate plus the freshness
-- contract, never the only containment check standing between a request and an
-- allow. A snapshot-mode adapter could not make that argument and must not
-- reuse this reasoning.
--
-- BLOCK BEATS STALE, deliberately. A stale projection's silence is what cannot
-- be trusted; a block recorded in it is still a block, because containment does
-- not lift by the passage of time (A05-05: at expiry the safe default is remain
-- contained and escalate). So evaluate() reports a matching block even on a
-- projection that is past its freshness bound, and reports staleness only when
-- it found nothing — over-blocking is the safe direction, under-blocking is not.
--
-- SCOPE IS A QUALIFIER, NOT A FILTER. block/lift are applied per exact
-- (type, id, scope) identity, so a lift can never clear a block at a different
-- scope; but a LOOKUP matches on (type, id) across every scope, so a block
-- entered at any scope stops the request. Wrong direction is stricter.
--
-- Pure Lua 5.1+ — no ngx/Kong/OpenSSL dependency — so it is unit-testable
-- outside the gateway image, exactly like bundle.lua. Crypto is injected.

local compare = require "kong.plugins.mudraid-enforce.compare"

local _M = {}

-- Keep in sync with FEED_SIGNATURE_ALGORITHM in feed/signing.py. An unknown
-- algorithm is refused, never "best effort" verified with the one we have.
_M.SIGNATURE_ALGORITHM = "HMAC-SHA256"

_M.KIND_SNAPSHOT = "snapshot"
_M.KIND_DELTA = "delta"
_M.OP_BLOCK = "block"
_M.OP_LIFT = "lift"

-- Keep in sync with _FIELD_SEP / _ENTRY_SEP in feed/record.py.
_M.FIELD_SEP = "\0"
_M.ENTRY_SEP = "\31"

-- The target types this adapter can bind a pre-/decide request to. See the
-- header: everything else is counted and deferred to the live path.
_M.EVALUABLE_TARGET_TYPES = {
  platform = true,  -- content.surface.platform_id
  resource = true,  -- content.surface.canonical_resource_uri
  action = true,    -- the exactly matched canonical action_key
}

-- evaluate() outcome words.
_M.CLEAR = "clear"
_M.BLOCKED = "blocked"
_M.STALE = "stale"
_M.UNAVAILABLE = "unavailable"

local function fail(code, detail)
  return nil, code, detail
end

local function is_str(v)
  return type(v) == "string" and v ~= ""
end

--- Does `v` contain a byte that is load-bearing in the canonical serialization?
--
-- THE HEADER OF THIS MODULE CLAIMS INJECTIVITY AND NOTHING USED TO CHECK IT.
-- `canonical_bytes` joins fields with NUL and entries with US, and the comment
-- beside the format says both separators are "excluded from every value they
-- join, which is what keeps the serialization injective". That was a statement
-- about the PRODUCER's inputs, asserted on the verifying side and never tested
-- there — so the property the signature's meaning rests on was assumed.
--
-- If a value can carry a separator, the map from records to bytes stops being
-- injective, and a signature is a statement about BYTES. Two different records
-- that serialize identically are two records one signature authenticates: a
-- crafted `target_id` of the form `id\0scope\0lift\0...` can make the bytes of a
-- BLOCK entry read back as a different entry set entirely. Whether such a value
-- can reach the feed today is a question about every producer upstream and
-- about every name a customer can choose for a resource or an action — which is
-- exactly the kind of question a verifier should not have to answer.
--
-- So the verifier checks it. One `find`, plain (no pattern), per field.
local function has_separator(v)
  return v:find(_M.FIELD_SEP, 1, true) ~= nil or v:find(_M.ENTRY_SEP, 1, true) ~= nil
end

--- A field that is a usable, non-empty, unambiguously-serializable value.
local function is_canonical_str(v)
  return is_str(v) and not has_separator(v)
end

local function is_uint(v, min)
  return type(v) == "number" and v == math.floor(v) and v >= (min or 0)
end

local function is_hex(v)
  return type(v) == "string" and #v >= 32 and v:match("^[0-9a-f]+$") ~= nil
end

-- ---------------------------------------------------------------------------
-- Instants
-- ---------------------------------------------------------------------------

-- Days since 1970-01-01 from a proleptic-Gregorian civil date (Howard
-- Hinnant's days_from_civil). os.time() is deliberately NOT used: it
-- interprets its input in the HOST timezone, which would make freshness — a
-- security bound — depend on the container's TZ.
local function days_from_civil(y, m, d)
  if m <= 2 then
    y = y - 1
  end
  local era = math.floor((y >= 0 and y or (y - 399)) / 400)
  local yoe = y - era * 400
  local mp = (m + (m > 2 and -3 or 9))
  local doy = math.floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

--- Strict ISO-8601 -> epoch seconds. Anything else is nil (deny-closed): an
--- instant that cannot be placed on a timeline cannot bound freshness.
-- Accepts exactly the shapes Python's datetime.isoformat() emits for an
-- aware datetime, plus the "Z" spelling: YYYY-MM-DDTHH:MM:SS[.ffffff]
-- (Z | +HH:MM | -HH:MM | +HHMM | -HHMM).
function _M.parse_instant(s)
  if type(s) ~= "string" then
    return nil
  end
  local y, mo, d, h, mi, sec, rest =
    s:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt ](%d%d):(%d%d):(%d%d)(.*)$")
  if not y then
    return nil
  end
  -- Optional fractional seconds; discarded (whole-second freshness).
  local frac, tail = rest:match("^(%.%d+)(.*)$")
  if frac then
    rest = tail
  end
  local offset = 0
  if rest == "Z" or rest == "z" then
    offset = 0
  elseif rest == "" then
    -- A naive instant. Refused rather than assumed UTC: guessing a timezone
    -- for a freshness bound can only ever be wrong by whole hours.
    return nil
  else
    local sign, oh, om = rest:match("^([%+%-])(%d%d):?(%d%d)$")
    if not sign then
      return nil
    end
    offset = (tonumber(oh) * 3600 + tonumber(om) * 60) * (sign == "-" and -1 or 1)
  end
  mo, d, h, mi, sec = tonumber(mo), tonumber(d), tonumber(h), tonumber(mi), tonumber(sec)
  if mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or sec > 60 then
    return nil
  end
  return days_from_civil(tonumber(y), mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset
end

-- ---------------------------------------------------------------------------
-- Canonical bytes
-- ---------------------------------------------------------------------------

local function entry_parts(e)
  return table.concat({
    e.target_type,
    e.target_id,
    e.scope,
    e.op,
    string.format("%d", e.state_epoch),
    e.reason_code,
    e.effective_at,
  }, _M.FIELD_SEP)
end

--- The exact bytes enforcement-service signed. `record` must already have been
--- shape-checked (verify does that first).
function _M.canonical_bytes(record)
  local head = table.concat({
    record.organization_id,
    record.environment,
    record.kind,
    string.format("%d", record.sequence),
    record.issued_at,
  }, _M.FIELD_SEP)
  local body = {}
  for i = 1, #record.entries do
    body[i] = entry_parts(record.entries[i])
  end
  return head .. _M.ENTRY_SEP .. table.concat(body, _M.ENTRY_SEP)
end

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------

local function check_entries(raw)
  if type(raw) ~= "table" then
    return nil, "entries missing"
  end
  local entries = {}
  for i = 1, #raw do
    local e = raw[i]
    if type(e) ~= "table" then
      return nil, string.format("entry %d is not an object", i)
    end
    if not (is_str(e.target_type) and is_str(e.target_id) and is_str(e.scope)) then
      return nil, string.format("entry %d has an unbound target", i)
    end
    if not (is_canonical_str(e.target_type) and is_canonical_str(e.target_id)
      and is_canonical_str(e.scope)) then
      -- See has_separator: a field carrying a separator makes the signed bytes
      -- ambiguous, so the signature stops meaning this record in particular.
      return nil, string.format(
        "entry %d has a target field containing a canonical separator", i)
    end
    if e.op ~= _M.OP_BLOCK and e.op ~= _M.OP_LIFT then
      return nil, string.format("entry %d op %s is not block/lift", i, tostring(e.op))
    end
    if not is_uint(e.state_epoch, 1) then
      return nil, string.format("entry %d state_epoch is not a positive integer", i)
    end
    if not is_str(e.reason_code) then
      return nil, string.format("entry %d has no reason code", i)
    end
    if not is_str(e.effective_at) then
      return nil, string.format("entry %d has no effective_at", i)
    end
    if not (is_canonical_str(e.reason_code) and is_canonical_str(e.effective_at)) then
      return nil, string.format(
        "entry %d has a field containing a canonical separator", i)
    end
    entries[i] = {
      target_type = e.target_type,
      target_id = e.target_id,
      scope = e.scope,
      op = e.op,
      state_epoch = e.state_epoch,
      reason_code = e.reason_code,
      effective_at = e.effective_at,
    }
  end
  return entries
end

--- Verify one fetched containment record BEFORE any of it is trusted.
-- @param fetched decoded feed response:
--   { organization_id, environment, kind, sequence, issued_at,
--     entries = { { target_type, target_id, scope, op, state_epoch,
--                   reason_code, effective_at }, ... },
--     signature = { key_id, algorithm, digest } }
-- @param opts {
--   crypto = { hmac_sha256_hex(key, s) },
--   secret = containment feed signing secret (string),
--   key_id = expected signing key id (string) or nil to accept the named one,
--   active = the currently applied projection (from apply) or nil,
-- }
-- @return verified record { ..., digest, signing_key_id, issued_at_epoch,
--         no_change } or nil, error_code, error_detail
function _M.verify(fetched, opts)
  if type(fetched) ~= "table" then
    return fail("CONTAINMENT_RESPONSE_INVALID", "response is not an object")
  end
  if not (is_str(fetched.organization_id) and is_str(fetched.environment)) then
    return fail("CONTAINMENT_RESPONSE_INVALID", "record names no organization/environment")
  end
  -- The head is joined with the same separators as the entries and is subject to
  -- the same injectivity requirement. `kind` and `sequence` are constrained to
  -- closed vocabularies below and cannot carry one; `issued_at` is checked after
  -- its shape test, where a separator would already have failed the parse.
  if not (is_canonical_str(fetched.organization_id)
    and is_canonical_str(fetched.environment)) then
    return fail("CONTAINMENT_RESPONSE_INVALID",
      "organization/environment contains a canonical separator")
  end
  if fetched.kind ~= _M.KIND_SNAPSHOT and fetched.kind ~= _M.KIND_DELTA then
    return fail("CONTAINMENT_KIND_UNSUPPORTED",
      "record kind " .. tostring(fetched.kind) .. " is not supported")
  end
  if not is_uint(fetched.sequence, 1) then
    return fail("CONTAINMENT_RESPONSE_INVALID", "sequence is not a positive integer")
  end
  if not is_str(fetched.issued_at) then
    return fail("CONTAINMENT_RESPONSE_INVALID", "issued_at missing")
  end
  local issued_at_epoch = _M.parse_instant(fetched.issued_at)
  if not issued_at_epoch then
    -- Not merely cosmetic: without a placeable issue instant there is no
    -- freshness bound, and an unbounded projection is exactly what A05-06
    -- forbids a disconnected adapter from running on.
    return fail("CONTAINMENT_TIMESTAMP_INVALID",
      "issued_at is not a bounded ISO-8601 instant")
  end
  local entries, eerr = check_entries(fetched.entries)
  if not entries then
    return fail("CONTAINMENT_ENTRY_INVALID", eerr)
  end

  local sig = fetched.signature
  if type(sig) ~= "table" or not is_str(sig.key_id) or not is_hex(sig.digest) then
    return fail("CONTAINMENT_RESPONSE_INVALID", "signature envelope is not a usable HMAC")
  end

  local record = {
    organization_id = fetched.organization_id,
    environment = fetched.environment,
    kind = fetched.kind,
    sequence = fetched.sequence,
    issued_at = fetched.issued_at,
    entries = entries,
  }
  local canon = _M.canonical_bytes(record)

  -- Crypto, refusal-by-refusal. Order is deliberate: the two operator
  -- misconfigurations are named BEFORE the digest comparison, so an operator
  -- is never told "signature verification failed" about a secret that was
  -- never delivered or a key rotation this adapter was never given.
  if type(opts.secret) ~= "string" or opts.secret == "" then
    return fail("CONTAINMENT_SIGNING_SECRET_UNCONFIGURED",
      "no containment feed signing secret configured; unsigned trust is refused")
  end
  if is_str(opts.key_id) and sig.key_id ~= opts.key_id then
    -- This adapter holds exactly ONE verification key. A record signed under
    -- another key id is a rotation whose material never reached this gateway;
    -- it cannot start verifying by itself.
    return fail("CONTAINMENT_SIGNING_KEY_UNKNOWN",
      "record signed by key " .. tostring(sig.key_id) .. ", this adapter holds " .. opts.key_id)
  end
  if sig.algorithm ~= _M.SIGNATURE_ALGORITHM then
    return fail("CONTAINMENT_SIGNATURE_ALGORITHM_UNSUPPORTED",
      "unsupported signature algorithm " .. tostring(sig.algorithm))
  end
  -- Constant-time: see compare.lua.
  if not compare.equals(opts.crypto.hmac_sha256_hex(opts.secret, canon), sig.digest) then
    return fail("CONTAINMENT_SIGNATURE_INVALID", "HMAC signature verification failed")
  end

  -- Ordering rules against what is already applied. Everything below this
  -- point concerns a record that IS authentic.
  local active = opts.active
  local no_change = false
  if active ~= nil then
    if active.organization_id ~= record.organization_id
      or active.environment ~= record.environment then
      -- The stream identity changed underneath a live projection. Applying it
      -- would fold one tenant/environment's containment into another's.
      return fail("CONTAINMENT_STREAM_MISMATCH",
        "record stream " .. record.organization_id .. "/" .. record.environment
        .. " is not the applied stream " .. active.organization_id .. "/" .. active.environment)
    end
    if record.sequence < active.sequence then
      return fail("CONTAINMENT_SEQUENCE_REGRESSION",
        string.format("served sequence %d < applied sequence %d",
          record.sequence, active.sequence))
    end
    if record.sequence == active.sequence then
      if sig.digest ~= active.digest then
        return fail("CONTAINMENT_SEQUENCE_CONFLICT",
          "same sequence with a different signature digest")
      end
      no_change = true
    elseif record.kind == _M.KIND_DELTA and record.sequence ~= active.sequence + 1 then
      -- A delta is applicable only exactly one past the applied sequence
      -- (feed/record.py). Applying it over a gap would silently skip whatever
      -- the missing record contained — including a block.
      return fail("CONTAINMENT_DELTA_GAP",
        string.format("delta at sequence %d cannot follow applied sequence %d",
          record.sequence, active.sequence))
    end
  elseif record.kind == _M.KIND_DELTA then
    return fail("CONTAINMENT_DELTA_GAP",
      "a delta cannot establish a projection with no applied snapshot baseline")
  end

  record.digest = sig.digest
  record.signing_key_id = sig.key_id
  record.issued_at_epoch = issued_at_epoch
  record.no_change = no_change
  return record
end

-- ---------------------------------------------------------------------------
-- Atomic application
-- ---------------------------------------------------------------------------

local function identity_key(target_type, target_id, scope)
  return table.concat({ target_type, target_id, scope }, _M.FIELD_SEP)
end

_M.identity_key = identity_key

local function lookup_key(target_type, target_id)
  return table.concat({ target_type, target_id }, _M.FIELD_SEP)
end

--- Build the NEW projection a verified record implies.
--
-- Returns a fresh, self-contained table and NEVER mutates `active`. That is
-- what makes the swap in handler.lua atomic (A05-06 "apply updates
-- atomically"): the caller performs one table-reference assignment, so an
-- in-flight request either sees the whole old projection or the whole new one
-- and never a half-applied set of entries.
--
-- A snapshot RE-BASELINES (the served entries are the complete active set); a
-- delta is layered over the applied blocks in served order.
function _M.apply(active, verified)
  if type(verified) ~= "table" then
    return fail("CONTAINMENT_RESPONSE_INVALID", "nothing verified to apply")
  end
  local blocks = {}
  if verified.kind == _M.KIND_DELTA then
    if type(active) ~= "table" then
      return fail("CONTAINMENT_DELTA_GAP", "no baseline projection to apply a delta over")
    end
    for k, v in pairs(active.blocks) do
      blocks[k] = v
    end
  end

  local unevaluable = 0
  for i = 1, #verified.entries do
    local e = verified.entries[i]
    local key = identity_key(e.target_type, e.target_id, e.scope)
    if e.op == _M.OP_BLOCK then
      blocks[key] = e
    else
      blocks[key] = nil
    end
  end

  -- Lookup index: (type, id) -> list of blocking entries across every scope.
  local index, block_count = {}, 0
  for _, e in pairs(blocks) do
    block_count = block_count + 1
    if _M.EVALUABLE_TARGET_TYPES[e.target_type] then
      local lk = lookup_key(e.target_type, e.target_id)
      local bucket = index[lk]
      if not bucket then
        bucket = {}
        index[lk] = bucket
      end
      bucket[#bucket + 1] = e
    else
      unevaluable = unevaluable + 1
    end
  end

  return {
    organization_id = verified.organization_id,
    environment = verified.environment,
    sequence = verified.sequence,
    kind = verified.kind,
    issued_at = verified.issued_at,
    issued_at_epoch = verified.issued_at_epoch,
    digest = verified.digest,
    signing_key_id = verified.signing_key_id,
    blocks = blocks,
    index = index,
    block_count = block_count,
    -- Blocks this adapter cannot bind a pre-/decide request to. Surfaced, not
    -- swallowed: it is the measured size of what the live path alone covers.
    unevaluable = unevaluable,
    entry_count = #verified.entries,
  }
end

-- ---------------------------------------------------------------------------
-- The check that runs before any allow
-- ---------------------------------------------------------------------------

--- Decide whether a protected action may proceed past the local projection.
-- @param projection the applied projection (from apply) or nil
-- @param subject array of { target_type = , target_id = } candidates the
--        caller could bind from VERIFIED material only
-- @param opts { now = epoch seconds, max_staleness_seconds = n,
--               clock_skew_seconds = n (default 60) }
-- @return _M.CLEAR | _M.BLOCKED | _M.STALE | _M.UNAVAILABLE, detail
function _M.evaluate(projection, subject, opts)
  if type(projection) ~= "table" then
    -- "No projection" is never "nothing is contained".
    return _M.UNAVAILABLE, { reason = "no verified containment projection is applied" }
  end

  -- Blocks first: see the header. A stale projection's SILENCE is what cannot
  -- be trusted; a block written into it is still a block.
  for i = 1, #subject do
    local c = subject[i]
    if is_str(c.target_type) and is_str(c.target_id) then
      local bucket = projection.index[lookup_key(c.target_type, c.target_id)]
      if bucket and bucket[1] then
        local e = bucket[1]
        return _M.BLOCKED, {
          target_type = e.target_type,
          target_id = e.target_id,
          scope = e.scope,
          reason_code = e.reason_code,
          state_epoch = e.state_epoch,
          sequence = projection.sequence,
        }
      end
    end
  end

  local skew = opts.clock_skew_seconds or 60
  local age = opts.now - projection.issued_at_epoch
  if age > opts.max_staleness_seconds then
    -- A05-06: a disconnected adapter may use its last projection only within
    -- its configured maximum staleness. Past it the action denies; it does not
    -- continue indefinitely.
    return _M.STALE, {
      age_seconds = age,
      max_staleness_seconds = opts.max_staleness_seconds,
      sequence = projection.sequence,
    }
  end
  if age < -skew then
    -- Issued far enough in OUR future that the two clocks disagree about
    -- whether this projection has expired. An unplaceable freshness bound is
    -- not a freshness bound.
    return _M.STALE, {
      age_seconds = age,
      max_staleness_seconds = opts.max_staleness_seconds,
      sequence = projection.sequence,
      clock_skew = true,
    }
  end
  return _M.CLEAR, { sequence = projection.sequence }
end

-- ---------------------------------------------------------------------------
-- Acknowledgement (A05-06 item 3, A05-07 measurement)
-- ---------------------------------------------------------------------------

--- Mint the authenticated body for
--- POST /api/v2/containment/convergence/acknowledgements.
--
-- Signed bytes are SignedAdapterAcknowledgement.canonical_bytes()
-- (domain/containment/acknowledgement.py):
--
--   organization_id \0 environment \0 adapter_id \0 sequence \0 acknowledged_at
--
-- The server rebuilds them from ITS OWN operator-resolved organization/
-- environment and from `acknowledged_at` re-serialized as
-- `datetime.isoformat()` after pydantic parses it. `acknowledged_at` must
-- therefore be the "+00:00" spelling and second-resolution: pydantic renders a
-- parsed "…Z" back as "…+00:00", which would not be the bytes we signed.
-- iso_utc_offset() below is the only supported way to produce it.
--
-- @return body table, or nil, error_code, error_detail
function _M.acknowledgement(projection, opts)
  if type(projection) ~= "table" then
    return fail("CONTAINMENT_ACK_NOTHING_APPLIED", "no applied projection to acknowledge")
  end
  if not is_str(opts.adapter_id) then
    return fail("CONTAINMENT_ACK_ADAPTER_ID_UNCONFIGURED",
      "no containment adapter id configured; an unattributed acknowledgement "
      .. "cannot count toward a fleet convergence claim")
  end
  -- The acknowledgement's canonical bytes use the same NUL join, so the same
  -- injectivity requirement applies — here to values an OPERATOR supplies via
  -- plugin config rather than ones a server serves. Refusing to sign ambiguous
  -- bytes is cheaper than discovering later that a convergence measurement
  -- counted the wrong adapter.
  if not is_canonical_str(opts.adapter_id) then
    return fail("CONTAINMENT_ACK_ADAPTER_ID_INVALID",
      "containment adapter id contains a canonical separator")
  end
  if type(opts.secret) ~= "string" or opts.secret == "" then
    return fail("CONTAINMENT_ACK_SECRET_UNCONFIGURED",
      "no containment acknowledgement ingest secret configured; an unsigned "
      .. "acknowledgement is refused rather than sent")
  end
  if not is_canonical_str(opts.acknowledged_at) then
    return fail("CONTAINMENT_ACK_INSTANT_INVALID", "acknowledged_at missing or unserializable")
  end
  local canon = table.concat({
    projection.organization_id,
    projection.environment,
    opts.adapter_id,
    string.format("%d", projection.sequence),
    opts.acknowledged_at,
  }, _M.FIELD_SEP)
  return {
    adapter_id = opts.adapter_id,
    acknowledged_sequence = projection.sequence,
    acknowledged_at = opts.acknowledged_at,
    signature = {
      key_id = opts.key_id or "containment-ack-v1",
      algorithm = _M.SIGNATURE_ALGORITHM,
      digest = opts.crypto.hmac_sha256_hex(opts.secret, canon),
    },
  }
end

--- "%Y-%m-%dT%H:%M:%S+00:00" for an epoch-seconds UTC instant.
-- Spelled out rather than taken from os.date("!%Y-%m-%dT%H:%M:%SZ") because the
-- trailing "Z" does not survive the server's pydantic round-trip (see above).
function _M.iso_utc_offset(epoch_seconds)
  return os.date("!%Y-%m-%dT%H:%M:%S", epoch_seconds) .. "+00:00"
end

return _M
