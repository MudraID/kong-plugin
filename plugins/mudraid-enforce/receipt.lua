-- mudraid-enforce: boundary-execution receipt producer (EP-510 §11.5, step 3).
--
-- WHAT THIS IS: the half of a boundary-execution receipt that ONLY the
-- enforcement boundary can write. For each terminal path this plugin can
-- take, it states what the boundary actually did — the outcome word and the
-- forwarded count — bound to the decision, the signed bundle and the matched
-- action it did it under.
--
-- WHY IT IS HERE AND NOWHERE ELSE. Nothing downstream observes a forward.
-- The /decide envelope's `directive` is a ONE-WAY instruction to this plugin
-- and nothing closes the loop; RootDecision.to_envelope() emits a hardcoded
-- "action_executed": false with the comment that an allow authorizes but does
-- not assert the protected action ran. So "was it forwarded, and how many
-- times" is knowable at this file and at no other point in the architecture.
--
-- ============================ NOT WIRED ================================
-- handler.lua does NOT call this module. There is no ingest route for a
-- receipt, no table behind one, and no answer to open questions D1/D2/D3 of
-- the merged schema proposal (what identifies a receipt for a request killed
-- before /decide; what the named enforcement boundary is named by; who
-- signs). Adding a call site now would put a mint on the hot path whose
-- output has nowhere to go, and a producer whose output is discarded is a
-- performance cost pretending to be evidence.
--
-- What DOES bind this module to the real boundary is a gate, not a promise:
-- kong/tests/test_mudraid_enforce_contract.py extracts every deny(...) reason
-- code literal from handler.lua and asserts REASON_OUTCOMES covers exactly
-- that set, so a new refusal path in the handler fails the build until this
-- module knows what outcome it means.
--
-- ======================= HONEST INCOMPLETENESS =========================
-- A receipt minted here is STRUCTURALLY INCOMPLETE and the contract refuses
-- it. Two required fields have no producer at this boundary:
--
--   * organization_id — the gateway never sees a verified protected-action
--     token; the tenant is established inside enforcement-service. The
--     merged proposal marks it NOT NULL and also says the boundary never
--     learns it: both are true, which is the finding.
--   * proof_scope_digest — no ProofScopeSnapshot digest is distributed to an
--     adapter. The signed bundle carries no scope binding at all.
--
-- Also absent, and left absent rather than approximated: adapter_id and
-- enforcement_boundary_name (the plugin config carries neither, and the
-- /decide hop authenticates with a SHARED service secret, so no call is
-- attributable to an adapter instance), and policy_version /
-- evaluated_policies (this plugin parses only `decision` out of the /decide
-- response).
--
-- mint() therefore returns a receipt with those fields absent, and
-- mudraid_contracts.boundary_receipt.malformed_reasons() reports each one.
-- That refusal is the deliverable. A producer that filled them in would be
-- inventing the tenancy of a proof artifact.
--
-- Pure Lua 5.1+ — no ngx/Kong dependencies — so it is unit-testable outside
-- the gateway image (kong/tests/lua/).

local canonical = require "kong.plugins.mudraid-enforce.canonical"

local _M = {}

-- Shape version, carried INSIDE the digested document. Keep in sync with
-- mudraid_contracts.boundary_receipt.RECEIPT_SCHEMA_VERSION; the Python
-- contract test asserts the two are equal.
_M.SCHEMA_VERSION = "1.0.0"

_M.OUTCOME_FORWARDED_ONCE = "forwarded_once"
_M.OUTCOME_BLOCKED = "blocked"
_M.OUTCOME_FAILED_CLOSED = "failed_closed"

-- Every typed refusal handler.lua can terminate a protected request with,
-- and the single outcome word each one entails.
--
--   blocked       — the boundary evaluated and the answer was no.
--   failed_closed — something the boundary REQUIRES was not established
--                   (no signed bundle, no safe decision, no guarantee of
--                   forward-once), so it stopped rather than guessed.
--
-- The distinction is the same one §11.6 draws one layer up between
-- not_proven and unavailable: "we said no" and "we could not tell" are
-- different facts and collapsing them loses the more serious one.
--
-- forwarded_count is 0 for EVERY entry here. Exactly one path in this plugin
-- produces a 1, and it is the one with no reason code at all.
_M.REASON_OUTCOMES = {
  ENFORCE_ACTION_UNMAPPED = _M.OUTCOME_BLOCKED,
  ENFORCE_BATCH_UNSUPPORTED = _M.OUTCOME_BLOCKED,
  ENFORCE_BODY_TOO_LARGE = _M.OUTCOME_BLOCKED,
  ENFORCE_BODY_UNREADABLE = _M.OUTCOME_BLOCKED,
  ENFORCE_MALFORMED_REQUEST = _M.OUTCOME_BLOCKED,
  ENFORCE_MESSAGE_NOT_ALLOWED = _M.OUTCOME_BLOCKED,
  ENFORCE_METHOD_NOT_ALLOWED = _M.OUTCOME_BLOCKED,
  ENFORCE_DECISION_DENY = _M.OUTCOME_BLOCKED,
  ENFORCE_NO_VALID_BUNDLE = _M.OUTCOME_FAILED_CLOSED,
  ENFORCE_DECIDE_UNAVAILABLE = _M.OUTCOME_FAILED_CLOSED,
  ENFORCE_FORWARD_ONCE_UNAVAILABLE = _M.OUTCOME_FAILED_CLOSED,
  -- Multi-tenant step 3. Both are failed_closed rather than blocked, and the
  -- distinction is the one this table exists to make: `blocked` means the
  -- boundary EVALUATED the request and refused it, while `failed_closed` means
  -- it could not establish which policy even applied. A surface that is
  -- ambiguous or undeclared has no bundle the request can be judged against —
  -- exactly ENFORCE_NO_VALID_BUNDLE's situation, reached by a configuration
  -- route instead of a polling one. Recording them as `blocked` would assert a
  -- decision that was never made.
  ENFORCE_SURFACE_AMBIGUOUS = _M.OUTCOME_FAILED_CLOSED,
  ENFORCE_SURFACE_UNIDENTIFIED = _M.OUTCOME_FAILED_CLOSED,
  -- Containment (doc 05 A05-06). The split between the three is the same
  -- one this table exists to draw, and here it is at its sharpest:
  --
  --   BLOCKED     — the boundary evaluated the signed containment projection
  --                 and the answer was no. A real determination, on verified
  --                 material, so `blocked`.
  --   STALE       — the projection is past its configured maximum staleness.
  --                 The boundary did NOT determine that this action is
  --                 contained; it determined that it can no longer tell, which
  --                 is `failed_closed`. Recording it as blocked would assert a
  --                 containment finding nobody made, and recording a real
  --                 block as stale would lose the more serious fact.
  --   UNAVAILABLE — no verified projection at all. Same situation as
  --                 ENFORCE_NO_VALID_BUNDLE, reached by the containment feed
  --                 instead of the bundle channel.
  ENFORCE_CONTAINMENT_BLOCKED = _M.OUTCOME_BLOCKED,
  ENFORCE_CONTAINMENT_STALE = _M.OUTCOME_FAILED_CLOSED,
  ENFORCE_CONTAINMENT_UNAVAILABLE = _M.OUTCOME_FAILED_CLOSED,

  -- The request presented more headers than the PDK can enumerate (1000 is its
  -- ceiling, not our choice), so the A03-04 reserved-header strip cannot be
  -- shown to have covered them all.
  --
  -- `failed_closed`, and the distinction this table exists for is exactly the
  -- one at stake. The boundary made NO determination about this request — it
  -- did not evaluate an action, consult a projection or ask an authority. It
  -- established that one of its own preconditions could not be verified.
  -- Recording that as `blocked` would assert a refusal somebody decided on,
  -- when what actually happened is that the boundary could not see the request
  -- clearly enough to decide anything about it.
  ENFORCE_HEADER_SET_UNBOUNDED = _M.OUTCOME_FAILED_CLOSED,
}

-- Reasons that fire BEFORE /decide is called. A receipt for one of these
-- carries no decision id and no authoritative decision, because no decision
-- was made — rule R7. Note ENFORCE_BODY_UNREADABLE: it is in this set and is
-- NOT in the merged proposal's R7 enumeration, which lists seven codes. A
-- truthful receipt for a body the boundary could not read would be scored
-- MALFORMED under R7 as written.
_M.PRE_DECIDE_REASONS = {
  ENFORCE_ACTION_UNMAPPED = true,
  ENFORCE_BATCH_UNSUPPORTED = true,
  ENFORCE_BODY_TOO_LARGE = true,
  ENFORCE_BODY_UNREADABLE = true,
  ENFORCE_MALFORMED_REQUEST = true,
  ENFORCE_MESSAGE_NOT_ALLOWED = true,
  ENFORCE_METHOD_NOT_ALLOWED = true,
  ENFORCE_NO_VALID_BUNDLE = true,
  -- Multi-tenant step 3. These fire at the very first thing the hot path does
  -- on a protected request — selection — so they precede /decide by the widest
  -- margin of any refusal here.
  ENFORCE_SURFACE_AMBIGUOUS = true,
  ENFORCE_SURFACE_UNIDENTIFIED = true,
  -- Containment is checked BEFORE /decide, deliberately: A05-06 requires the
  -- projection to be consulted before any allow, and the earliest point at
  -- which the adapter holds the matched action is still above the decide call.
  -- So none of the three carries a decision id — no authoritative decision was
  -- ever obtained for a request the boundary stopped on containment.
  ENFORCE_CONTAINMENT_BLOCKED = true,
  ENFORCE_CONTAINMENT_STALE = true,
  ENFORCE_CONTAINMENT_UNAVAILABLE = true,
  -- Earlier than any of the above: the strip is the first thing the hot path
  -- does on a protected request, so a strip that cannot be verified refuses
  -- before selection has even been consulted for a bundle.
  ENFORCE_HEADER_SET_UNBOUNDED = true,
}

-- The authoritative decision each post-/decide refusal was made under. Read
-- off handler.lua: ENFORCE_DECISION_DENY fires on outcome == "deny";
-- ENFORCE_DECIDE_UNAVAILABLE fires on anything that is neither allow nor
-- deny, which is the three-valued not_safely_decided; and
-- ENFORCE_FORWARD_ONCE_UNAVAILABLE fires AFTER an allow — the decision
-- authorized and the boundary declined to execute, which the receipt must be
-- able to record without either fact contaminating the other (rule R5).
_M.REASON_DECISIONS = {
  ENFORCE_DECISION_DENY = "deny",
  ENFORCE_DECIDE_UNAVAILABLE = "not_safely_decided",
  ENFORCE_FORWARD_ONCE_UNAVAILABLE = "allow",
}

local DECISION_DIRECTIVES = {
  allow = "forward_once",
  deny = "block",
  not_safely_decided = "block",
}

local function present(v)
  return type(v) == "string" and v ~= ""
end

--- Mint one boundary-execution receipt.
--
-- @param ctx table:
--   receipt_id      (string, required) — identity of THIS record.
--   observed_at     (string, required) — the BOUNDARY's clock, ISO-8601 UTC.
--                   Never substitute the decision clock: decided_at is a
--                   different instant on a different machine measuring a
--                   different event, and a timestamp that does not mean what
--                   it says is worse than an absent one.
--   reason          (string or nil)   — a REASON_OUTCOMES key, or nil for the
--                   forwarded path. Anything else is refused.
--   decision_id     (string or nil)
--   correlation_id  (string or nil)   — client-supplied and NOT stripped
--                   (the reserved strip list is the x-mudraid- prefix only),
--                   so it is carried for correlation and must never be
--                   load-bearing for tenancy, scope or matching.
--   adapter_type / adapter_version (string)
--   surface         (table or nil)    — the VERIFIED signed bundle surface:
--                   platform_id, environment, canonical_resource_uri.
--   bundle          (table or nil)    — { version = <int>, payload_digest = }
--   action          (table or nil)    — { action_key = , action_version = }
--
-- @return receipt table, or nil + error. REFUSING rather than defaulting:
--   an unknown reason code would otherwise mint a receipt whose outcome word
--   was chosen by a fallback, and a fallback outcome is exactly the shape of
--   a refusal that reads as a pass.
function _M.mint(ctx)
  if type(ctx) ~= "table" then
    return nil, "receipt context must be a table"
  end
  if not present(ctx.receipt_id) then
    return nil, "receipt_id is required"
  end
  if not present(ctx.observed_at) then
    return nil, "observed_at is required (boundary clock)"
  end

  local reason, outcome = ctx.reason, nil
  if reason == nil or reason == "" then
    reason = ""
    outcome = _M.OUTCOME_FORWARDED_ONCE
  else
    outcome = _M.REASON_OUTCOMES[reason]
    if not outcome then
      return nil, "unknown boundary outcome reason: " .. tostring(reason)
    end
  end

  local forwarded_count = (outcome == _M.OUTCOME_FORWARDED_ONCE) and 1 or 0

  -- The authoritative decision, taken from the branch actually taken —
  -- never inferred from the outcome. A forward means an allow was returned;
  -- a pre-/decide refusal means no decision exists at all.
  local decision = ""
  if reason == "" then
    decision = "allow"
  elseif not _M.PRE_DECIDE_REASONS[reason] then
    decision = _M.REASON_DECISIONS[reason] or ""
  end
  local directive = DECISION_DIRECTIVES[decision] or ""

  -- R7: a pre-/decide receipt carries no decision id, even when the caller
  -- passes one. Honouring a decision id here would create the appearance of
  -- a decision for a request no decision was made about.
  local decision_id = ctx.decision_id or ""
  if _M.PRE_DECIDE_REASONS[reason] then
    decision_id = ""
  end

  local surface = ctx.surface or {}
  local bundle = ctx.bundle or {}
  local action = ctx.action or {}

  return {
    -- Scope binding. organization_id and proof_scope_digest are ABSENT and
    -- deliberately so — see HONEST INCOMPLETENESS above. They are emitted as
    -- empty strings rather than omitted so the canonical bytes have a stable
    -- key set and the reader's "required field absent" finding names them.
    organization_id = "",
    proof_scope_digest = "",
    environment = surface.environment or "",

    decision_id = decision_id,
    correlation_id = ctx.correlation_id or "",

    platform_id = surface.platform_id or "",
    adapter_type = ctx.adapter_type or "",
    adapter_version = ctx.adapter_version or "",
    enforcement_boundary_name = "",

    canonical_resource_uri = surface.canonical_resource_uri or "",
    action_id = action.action_key or "",
    -- STRINGIFIED, deliberately. The merged proposal types action_version as
    -- Integer, but the value a receipt must be matched against —
    -- ProofProtectedAction.protected_action_version in the scope contract — is
    -- a string. An integer receipt field compared to a string scope field never
    -- matches, and the failure mode is silence: every element reads uncovered
    -- and check 5 reports not_proven for a reason that is a type mismatch
    -- rather than a missing enforcement. The two contracts have to agree, and
    -- the scope digest is already published, so the receipt is the side that
    -- moves.
    action_version = action.action_version ~= nil and tostring(action.action_version) or "",

    bundle_version = bundle.version or 0,
    bundle_digest = bundle.payload_digest or "",

    authoritative_decision = decision,
    authoritative_directive = directive,
    boundary_outcome = outcome,
    boundary_outcome_reason = reason,

    forwarded_count = forwarded_count,

    observed_at = ctx.observed_at,

    receipt_id = ctx.receipt_id,
    receipt_schema_version = _M.SCHEMA_VERSION,
  }
end

--- Canonical bytes of a receipt — byte-identical to
--- mudraid_contracts.boundary_receipt.canonical_receipt_bytes().
-- The digest a signature would be over is sha256 of exactly this string.
-- The signature envelope is NOT part of the document (a signature cannot be
-- inside what it signs).
-- @return canonical string, or nil + error
function _M.canonical(receipt)
  return canonical.encode(receipt)
end

return _M
