-- mudraid-enforce: signed bundle verification (EP-110-US-04, doc 03 A03-05).
--
-- Verifies a bundle fetched from the adapter channel
-- (GET /api/v1/internal/enforcement/bundle) BEFORE any of it is trusted:
--
--   1. shape/type checks on the served envelope;
--   2. canonical re-serialization of the payload (canonical.lua — the same
--      bytes the control plane hashed and signed);
--   3. payload_digest  == SHA-256(canonical(payload));
--   4. signature       == HMAC-SHA256(signing secret, canonical(payload));
--   5. content re-hash (content_digest) for acknowledgement/log facts;
--   6. contract checks: schema version, surface binding (AUDIT-006 M4),
--      matcher kind (exact only, never fuzzy), deny-closed evaluation
--      contract, forward-once contract;
--   7. monotonic version rules against the currently active bundle.
--
-- ANY failure refuses the bundle: the caller keeps the last valid bundle
-- active, and if none exists the protected surface fails CLOSED (typed 503
-- from the handler). An unsigned or tampered bundle is never activated.
--
-- Crypto primitives are injected (opts.crypto) so this module stays pure
-- Lua and unit-testable; the gateway injects crypto.lua (resty/OpenSSL).

local canonical = require "kong.plugins.mudraid-enforce.canonical"
local matcher = require "kong.plugins.mudraid-enforce.matcher"
local compare = require "kong.plugins.mudraid-enforce.compare"
local base64 = require "kong.plugins.mudraid-enforce.base64"

local _M = {}

-- Pinned, not negotiated. Mirrors app/application/bundle_signature.py.
_M.SIGNATURE_PROFILE = "mudraid.bundle.signature/1"
_M.SIGNATURE_ALGORITHM = "RS256"

-- Must track BUNDLE_SCHEMA_VERSION in
-- services/platform-integration-service/app/application/bundle_compiler.py.
-- An unknown schema version is refused, not "best effort" parsed.
_M.SUPPORTED_SCHEMA_VERSIONS = { ["1.0"] = true }

-- The only evaluation contract this plugin implements (schema 1.0): live,
-- decide-required, deny-closed, forward-once. A bundle declaring anything
-- else (e.g. a future snapshot mode) is refused until this plugin ships
-- verified support for it — never silently downgraded (A03-08/10).
local REQUIRED_EVALUATION = {
  mode = "live",
  on_timeout = "deny",
  on_error = "deny",
  on_unmapped_action = "deny",
  on_stale_bundle = "deny",
  forward = "once",
}

-- AUDIT-006 M4 — surface binding contract.
--
-- handler.lua copies content.surface.{platform_id,environment,
-- canonical_resource_uri} verbatim onto the /decide envelope. Enforcement
-- reads them back as surface_platform_id / environment / resource_uri, and
-- AUDIT-006 M3 item 2 binds a grant to the EXACT environment + canonical
-- resource. A bundle that omits them (or carries JSON null, which the control
-- plane still emits for a pre-migration-014 surface row whose
-- canonical_resource_uri was never backfilled) therefore describes a surface
-- on which every protected request deny-closes with
-- authority_resource_unbound the moment binding is enabled.
--
-- That is a bundle this plugin cannot enforce as signed, so it is refused at
-- ACTIVATION rather than accepted and discovered at request time: the caller
-- keeps the last valid bundle, or — if none exists — the surface keeps failing
-- closed with the existing typed 503. Same posture as check_evaluation: an
-- evaluation contract the plugin cannot honour is refused, never downgraded.
--
-- Keep in sync with REQUIRED_SURFACE_FIELDS in
-- services/platform-integration-service/app/application/bundle_compiler.py.
-- ``domain`` is descriptive and is deliberately NOT required; ``platform_id``
-- identifies the surface the bundle speaks for and must be present.
local REQUIRED_SURFACE_FIELDS = { "platform_id", "environment", "canonical_resource_uri" }

--- Is `v` a usable, non-empty bundle string?
-- A JSON null decodes to the cjson null sentinel (a lightuserdata, which is
-- TRUTHY in Lua) rather than nil, so an explicit type check is required —
-- `if surface.canonical_resource_uri then` would wrongly accept it.
local function is_bound_string(v)
  return type(v) == "string" and v:match("^%s*$") == nil
end

local function check_surface(surface)
  if type(surface) ~= "table" then
    return false, "surface missing"
  end
  for i = 1, #REQUIRED_SURFACE_FIELDS do
    local key = REQUIRED_SURFACE_FIELDS[i]
    if not is_bound_string(surface[key]) then
      return false, string.format("surface.%s is not a bound value", key)
    end
  end
  return true
end

local function is_hex64(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

local function fail(code, detail)
  return nil, code, detail
end

local function check_evaluation(evaluation)
  if type(evaluation) ~= "table" then
    return false, "evaluation missing"
  end
  for key, expected in pairs(REQUIRED_EVALUATION) do
    if evaluation[key] ~= expected then
      return false, string.format("evaluation.%s must be %q", key, expected)
    end
  end
  if evaluation.decide_required ~= true then
    return false, "evaluation.decide_required must be true"
  end
  if evaluation.retry_forwarded_request ~= false then
    return false, "evaluation.retry_forwarded_request must be false"
  end
  return true
end


-- Treat the JSON library's null sentinel as absence. cjson decodes a JSON null
-- to a userdata sentinel rather than nil, so a field explicitly set to null
-- would otherwise read as PRESENT and be verified as a signature — turning an
-- honestly-unsigned legacy bundle into a refusal.
local function json_null(opts)
  return opts and opts.json and opts.json.null or nil
end

-- Verify the asymmetric signature. Returns nil on success, or a reason string.
--
-- The claims are verified as the signer serialized them and are then COMPARED
-- against the bundle in hand. A signature that verifies proves only that
-- MudraID produced those claims; it says nothing about whether those claims
-- describe THIS bundle, which is what the digest and version comparisons below
-- establish.
local function verify_asymmetric(fetched, canon, opts)
  if type(opts.verification_keys) ~= "table" then
    return "no verification keys configured; a signed bundle cannot be checked"
  end
  if fetched.signature_profile ~= _M.SIGNATURE_PROFILE then
    return "unsupported signature profile"
  end
  -- Compared against a pinned constant, never read from the signature and used.
  -- A verifier that trusts this field verifies whatever the attacker chose.
  if fetched.signature_algorithm ~= _M.SIGNATURE_ALGORITHM then
    return "unsupported signature algorithm"
  end
  local key_id = fetched.signature_key_id
  if type(key_id) ~= "string" or key_id == "" then
    return "signature names no key"
  end
  local public_pem = opts.verification_keys[key_id]
  if type(public_pem) ~= "string" or public_pem == "" then
    -- Unknown or retired key. A key that is no longer published is a key whose
    -- signatures are no longer trusted.
    return "signature names an unknown key"
  end
  local claims = fetched.signature_claims
  if type(claims) ~= "table" then
    return "signature carries no claims"
  end
  if claims.key_id ~= key_id then
    return "claims name a different key than the signature"
  end

  local claim_bytes, cerr = canonical.encode(claims, opts.json)
  if not claim_bytes then
    return "claims could not be canonicalized: " .. tostring(cerr)
  end
  local raw = base64.decode(fetched.signature_value)
  if not raw then
    return "signature is not valid base64"
  end
  local ok, verr = opts.crypto.verify_rs256(public_pem, claim_bytes, raw)
  if not ok then
    return verr or "signature does not verify"
  end

  -- Only now are the claims trustworthy enough to compare against the bundle.
  if claims.payload_digest ~= fetched.payload_digest then
    return "signature does not cover this payload"
  end
  if claims.bundle_version ~= fetched.bundle_version then
    return "signature covers a different bundle version"
  end
  if opts.expected_platform_id and claims.platform_id ~= opts.expected_platform_id then
    return "bundle is bound to another platform"
  end
  if opts.expected_environment and claims.environment ~= opts.expected_environment then
    return "bundle is bound to another environment"
  end
  return nil
end

--- Verify one fetched bundle.
-- @param fetched  decoded response of GET /internal/enforcement/bundle:
--                 { bundle_version, schema_version, payload, payload_digest,
--                   signing_key_id, signature }
-- @param opts     {
--                   crypto = { sha256_hex(s), hmac_sha256_hex(key, s) },
--                   secret = adapter bundle signing secret (string),
--                   json   = { null = ..., array_mt = ... }  -- canonical opts
--                   active = { bundle_version = n, payload_digest = s } | nil
--                 }
-- @return verified table { bundle_version, payload, payload_digest,
--         content_digest, signing_key_id, actions, matcher_index,
--         strip_prefixes, no_change }  or  nil, error_code, error_detail
function _M.verify(fetched, opts)
  if type(fetched) ~= "table" then
    return fail("BUNDLE_RESPONSE_INVALID", "response is not an object")
  end
  local version = fetched.bundle_version
  if type(version) ~= "number" or version < 1 or math.floor(version) ~= version then
    return fail("BUNDLE_RESPONSE_INVALID", "bundle_version is not a positive integer")
  end
  if _M.SUPPORTED_SCHEMA_VERSIONS[fetched.schema_version] == nil then
    return fail("BUNDLE_SCHEMA_UNSUPPORTED",
      "schema_version " .. tostring(fetched.schema_version) .. " is not supported")
  end
  if type(fetched.payload) ~= "table" then
    return fail("BUNDLE_RESPONSE_INVALID", "payload missing")
  end
  if not is_hex64(fetched.payload_digest) then
    return fail("BUNDLE_RESPONSE_INVALID", "payload_digest is not sha256 hex")
  end
  -- The HMAC fields are required only WHEN PRESENT, which is not a weakening.
  --
  -- These two were unconditional, and that made the HMAC retirement incomplete
  -- in a way no signature test would have found: the block below stopped
  -- requiring the SECRET, while this stayed requiring the FIELD. The moment the
  -- control plane stops emitting `signature`, every bundle — including one
  -- carrying a perfectly good RS256 signature — is refused here as
  -- BUNDLE_RESPONSE_INVALID, before any signature logic runs. A malformed
  -- envelope and an asymmetrically-signed bundle would have been reported as
  -- the same thing.
  --
  -- Present-but-malformed is still a refusal, and that is the half that must
  -- not move: absence and invalidity are different facts (see the rule below).
  local hmac_null = json_null(opts)
  local has_hmac_signature = fetched.signature ~= nil and fetched.signature ~= hmac_null
  if has_hmac_signature then
    if not is_hex64(fetched.signature) then
      return fail("BUNDLE_RESPONSE_INVALID", "signature is not hmac-sha256 hex")
    end
    if type(fetched.signing_key_id) ~= "string" or fetched.signing_key_id == "" then
      return fail("BUNDLE_RESPONSE_INVALID",
        "signature is present but signing_key_id is missing; nothing names the key "
        .. "it was produced with")
    end
  end

  local payload = fetched.payload
  -- Envelope/payload consistency: the signed payload is authoritative; the
  -- unsigned response wrapper must agree with it.
  if payload.schema_version ~= fetched.schema_version then
    return fail("BUNDLE_ENVELOPE_MISMATCH", "payload.schema_version disagrees with response")
  end
  if payload.bundle_version ~= version then
    return fail("BUNDLE_ENVELOPE_MISMATCH", "payload.bundle_version disagrees with response")
  end

  -- Canonical bytes: identical serialization to the signer or refuse.
  local canon, cerr = canonical.encode(payload, opts.json)
  if not canon then
    return fail("BUNDLE_CANONICALIZATION_FAILED", cerr)
  end

  -- Digest BEFORE signature: a digest mismatch is tampering/corruption
  -- regardless of key material, and is reported as its own typed fact.
  if opts.crypto.sha256_hex(canon) ~= fetched.payload_digest then
    return fail("BUNDLE_DIGEST_MISMATCH", "payload_digest does not match canonical payload")
  end

  -- ── Signature verification: at least one, and every one that is PRESENT ────
  --
  -- THE HMAC IS NO LONGER REQUIRED, and that is the point of this block.
  -- `bundle_signing_secret` is a SYMMETRIC key: anyone who can verify with it
  -- can also SIGN with it. A customer holding it could mint bundles for their
  -- own surface — grant themselves any action on any resource — and the
  -- gateway would verify them happily. It was never a credential we could ship,
  -- so a customer-installed adapter must be able to verify with the PUBLIC key
  -- alone.
  --
  -- The rule is therefore two-sided, and both sides matter:
  --
  --   1. AT LEAST ONE signature must verify. Neither available is not "nothing
  --      to check" — it is unsigned trust, which is refused (A03-05).
  --   2. EVERY signature that is PRESENT must verify. Absence and invalidity
  --      are different facts and collapsing them would undo the migration: a
  --      bundle published before asymmetric signing carries no signature_value
  --      and is still accepted on its HMAC, which is what makes the window a
  --      window. But present-but-invalid ALWAYS denies — otherwise an attacker
  --      holding either key could corrupt one field and downgrade every bundle
  --      to whichever check they can still satisfy.
  local verified_by = nil

  local sig = fetched.signature_value
  local has_asymmetric = sig ~= nil and sig ~= json_null(opts)
  if has_asymmetric then
    local aerr = verify_asymmetric(fetched, canon, opts)
    if aerr then
      return fail("BUNDLE_SIGNATURE_INVALID", aerr)
    end
    verified_by = "RS256"
  end

  -- BOTH halves are required to CHECK an HMAC — a secret to check with, and a
  -- signature to check. A configured secret alone is not a check.
  --
  -- The `has_hmac_signature` half is what lets a customer who still has the
  -- secret in their config keep working once the control plane stops emitting
  -- HMAC signatures. Without it, `compare.equals(expected, nil)` is false and
  -- every RS256-signed bundle is refused as HMAC failure — a deny attributed
  -- to the wrong signature, on a gateway whose configuration nobody touched.
  --
  -- This is not a downgrade path. Stripping the HMAC signature does not help an
  -- attacker: whatever remains must still verify on its own, and if nothing
  -- does, `verified_by` stays nil and the bundle is refused below.
  local has_hmac_secret = type(opts.secret) == "string" and opts.secret ~= ""
  if has_hmac_secret and has_hmac_signature then
    local expected_sig = opts.crypto.hmac_sha256_hex(opts.secret, canon)
    -- Constant-time: this is the authentication tag, and `~=` short-circuits on
    -- the first differing byte (see compare.lua for the honest scope of the risk).
    if not compare.equals(expected_sig, fetched.signature) then
      return fail("BUNDLE_SIGNATURE_INVALID", "HMAC signature verification failed")
    end
    verified_by = verified_by or "HMAC"
  end

  if not verified_by then
    -- Nothing about this bundle has been authenticated. Refuse; never "trust
    -- unsigned". The detail distinguishes the two ways to arrive here, because
    -- "configure a secret" is useless advice to someone who already has one and
    -- received a bundle carrying no signature at all.
    local detail
    if has_hmac_signature and not has_hmac_secret then
      detail = "bundle carries no verifiable asymmetric signature and no signing "
        .. "secret is configured to check its HMAC; unsigned trust is refused"
    elseif has_hmac_secret then
      detail = "bundle carries neither an asymmetric signature nor an HMAC "
        .. "signature, so the configured signing secret had nothing to check; "
        .. "unsigned trust is refused"
    else
      detail = "bundle carries no signature of any kind and no signing secret is "
        .. "configured; unsigned trust is refused"
    end
    return fail("BUNDLE_SIGNING_SECRET_UNCONFIGURED", detail)
  end

  -- Signed content contract checks.
  local content = payload.content
  if type(content) ~= "table" then
    return fail("BUNDLE_CONTENT_INVALID", "payload.content missing")
  end
  -- AUDIT-006 M4: the surface binding the adapter must forward on /decide.
  local ok_surface, serr = check_surface(content.surface)
  if not ok_surface then
    return fail("BUNDLE_SURFACE_UNBOUND", serr)
  end
  local ok_eval, eerr = check_evaluation(content.evaluation)
  if not ok_eval then
    return fail("BUNDLE_EVALUATION_UNSUPPORTED", eerr)
  end
  local m = content.matcher
  if type(m) ~= "table" or m.kind ~= "mcp_tool_exact" then
    -- Exact semantics only — an unknown matcher kind must never degrade to
    -- fuzzy/partial matching (A03-06/07).
    return fail("BUNDLE_MATCHER_UNSUPPORTED",
      "matcher.kind " .. tostring(type(m) == "table" and m.kind or nil) .. " is not supported")
  end
  local actions = m.actions
  if type(actions) ~= "table" or #actions == 0 then
    return fail("BUNDLE_CONTENT_INVALID", "matcher.actions is empty")
  end
  local index, merr = matcher.build(actions)
  if not index then
    return fail(merr, "matcher corpus rejected before activation")
  end

  -- Monotonic version rules against the active bundle (A03-05/14): a lower
  -- version is refused (control-plane rollback republished a NEWER version,
  -- never a lower number); the same version with different bytes is a
  -- conflict; the same version with the same digest is a no-op.
  local active = opts.active
  local no_change = false
  if active ~= nil then
    if version < active.bundle_version then
      return fail("BUNDLE_VERSION_REGRESSION",
        string.format("served version %d < active version %d", version, active.bundle_version))
    end
    if version == active.bundle_version then
      if fetched.payload_digest ~= active.payload_digest then
        return fail("BUNDLE_VERSION_CONFLICT",
          "same bundle_version with a different payload_digest")
      end
      no_change = true
    end
  end

  local content_canon, ccerr = canonical.encode(content, opts.json)
  if not content_canon then
    return fail("BUNDLE_CANONICALIZATION_FAILED", ccerr)
  end

  local trusted = content.trusted_context
  return {
    bundle_version = version,
    payload = payload,
    payload_digest = fetched.payload_digest,
    content_digest = opts.crypto.sha256_hex(content_canon),
    -- The key that AUTHENTICATED this bundle, which is not always the HMAC one.
    -- With no HMAC signature there is no HMAC key, and reporting the absent
    -- field would leave handler.lua logging a nil (ngx.log raises on one) and
    -- every acknowledgement unable to say which key vouched for what it
    -- applied.
    signing_key_id = fetched.signing_key_id or fetched.signature_key_id,
    actions = actions,
    matcher_index = index,
    strip_prefixes = type(trusted) == "table" and trusted.strip_request_header_prefixes or nil,
    no_change = no_change,
  }
end

return _M
