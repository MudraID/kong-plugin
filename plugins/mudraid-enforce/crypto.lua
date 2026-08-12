-- mudraid-enforce: crypto primitives for bundle verification (A03-05).
--
-- Thin wrapper over the OpenSSL bindings shipped with Kong (lua-resty-*).
-- Kept separate from bundle.lua so verification logic stays pure Lua and
-- unit-testable with injected fakes, while the gateway injects the real
-- implementations. Algorithm choices mirror the control-plane signer
-- (bundle_compiler.py): SHA-256 digests, HMAC-SHA256 signatures, lowercase
-- hex encoding.

local resty_sha256 = require "resty.sha256"
local openssl_hmac = require "resty.openssl.hmac"

local _M = {}

-- Pure-Lua hex (lowercase): resty.string.to_hex depends on the nginx C
-- symbol ngx_hex_dump, which does not exist when this module is exercised
-- by the test harness under plain LuaJIT. Digest inputs are 32 bytes, so
-- the gsub cost is irrelevant.
local function to_hex(bin)
  return (bin:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

function _M.sha256_hex(s)
  local digest = resty_sha256:new()
  digest:update(s)
  return to_hex(digest:final())
end

function _M.hmac_sha256_hex(key, s)
  local h = assert(openssl_hmac.new(key, "sha256"))
  assert(h:update(s))
  return to_hex(assert(h:final()))
end

-- ── Asymmetric bundle-signature verification ────────────────────────────────
--
-- RS256 (RSA PKCS#1 v1.5 + SHA-256) over the canonical JSON of the signature
-- CLAIMS, matching app/application/bundle_signature.py. `resty.openssl.pkey`
-- is the same rock as the HMAC above, so this introduces no new dependency —
-- kong/tests/lua/check_rsa_capability.lua proves the capability at image build
-- time, including that a TAMPERED message is refused.
--
-- Loaded lazily so a harness exercising only the HMAC paths does not need the
-- asymmetric half present.
function _M.verify_rs256(public_pem, message, signature_bin)
  if type(public_pem) ~= "string" or public_pem == "" then
    return false, "no verification key"
  end
  if type(signature_bin) ~= "string" or signature_bin == "" then
    return false, "no signature"
  end
  local ok, pkey = pcall(require, "resty.openssl.pkey")
  if not ok then
    -- The library is absent. REFUSE rather than fall through to "unverified":
    -- a missing verifier must never read as a valid signature.
    return false, "asymmetric verification unavailable"
  end
  local key, kerr = pkey.new(public_pem)
  if not key then
    return false, "verification key could not be loaded: " .. tostring(kerr)
  end
  local verified, verr = key:verify(signature_bin, message, "sha256")
  if not verified then
    return false, verr or "signature does not verify"
  end
  return true
end

return _M
