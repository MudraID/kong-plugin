-- Bounded OpenResty capability check: can this image verify an RS256 signature?
--
-- WHY THIS EXISTS, AND WHY IT IS A BUILD GATE RATHER THAN A NOTE
-- ==============================================================
-- Bundle signatures are moving from HMAC-SHA256 to RSA, because an HMAC secret
-- that can verify can also sign — unusable for a customer adapter. The Kong
-- plugin has to verify the new signature, and the instruction was explicit:
-- do NOT implement RSA by hand in Lua. Use a reviewed library.
--
-- The question is therefore narrow and answerable: does the supported Kong
-- image already ship a reviewed library that can do RSA-PKCS1v15-SHA256
-- verification, IN THE HOST THE PLUGIN ACTUALLY RUNS IN?
--
-- THAT LAST CLAUSE IS A CORRECTION, AND IT MATTERS. This line used to read
-- "and does it work under the same plain-LuaJIT harness the plugin's tests run
-- in?", and the Dockerfile duly ran it under `luajit`. Every build failed:
--
--     resty.openssl.pkey does not load: .../resty/openssl/include/dh.lua:37:
--     luajit: undefined symbol: OBJ_sn2nid
--
-- OBJ_sn2nid is an OpenSSL libcrypto symbol. `lua-resty-openssl` binds it via
-- LuaJIT FFI, which resolves symbols in the RUNNING PROCESS, and the
-- standalone luajit binary does not link libcrypto. The symbol is missing
-- there whether or not the image can do RSA — so that run measured the
-- luajit binary and reported the result as a fact about the image.
--
-- The plugin does not run under plain LuaJIT. It runs inside nginx, where
-- libcrypto is loaded. The tests run under plain LuaJIT, and conflating the
-- two is what made the original question unanswerable. This now runs under
-- `resty`, OpenResty's nginx-backed CLI.
--
-- The consequence for the TEST harness is worth stating rather than leaving
-- for someone to rediscover: `crypto.verify_rs256` pcalls the require and
-- returns "asymmetric verification unavailable" when it fails, which
-- deny-closes correctly. Under plain LuaJIT that branch is the one the unit
-- suite exercises — safely, but it means the suite never proves a real
-- signature verifies. THIS gate is what proves that, and it is the only place
-- that does.
--
-- It is a build gate rather than a one-off answer because the answer can
-- change. A Kong base-image bump could drop or move the library, and the
-- failure would otherwise appear at runtime as bundles failing to verify —
-- which the plugin correctly deny-closes, meaning the symptom would be a
-- total enforcement outage rather than an obvious missing dependency.
--
-- WHAT IT ESTABLISHES
-- -------------------
--   1. `resty.openssl.pkey` loads in the image's OpenResty runtime.
--   2. A public key in PEM can be loaded from that library.
--   3. A GENUINE signature verifies.
--   4. A TAMPERED message does NOT verify.
--
-- (4) is the one that matters. A library that returns success for everything
-- would pass (1) through (3) and would be worse than having no verification,
-- because the plugin would report bundles as verified.
--
-- The library is already a dependency of this plugin: crypto.lua uses
-- `resty.openssl.hmac` for the existing bundle HMAC. This check asks whether
-- the SAME rock's asymmetric half is present, so a pass means no new
-- dependency is introduced into the supported image.
--
-- Run inside the image (NOT with bare luajit — see above):
--     resty -I /usr/local/share/lua/5.1 kong/tests/lua/check_rsa_capability.lua
-- Exit 0 = capable. Exit 1 = NOT capable, with the reason printed.

local function fail(reason)
  io.stderr:write("RSA CAPABILITY: NOT AVAILABLE — " .. reason .. "\n")
  os.exit(1)
end

local ok, pkey = pcall(require, "resty.openssl.pkey")
if not ok then
  fail("resty.openssl.pkey does not load: " .. tostring(pkey))
end

-- Generating a keypair here rather than pinning one: the pinned PEM above is a
-- placeholder shape, and a check that depends on a hand-pasted key fails for
-- reasons that have nothing to do with the capability being measured. Key
-- generation costs ~100ms at 2048 bits, which is acceptable for a build gate
-- that runs once per image.
local key, err = pkey.new({ type = "RSA", bits = 2048 })
if not key then
  fail("could not generate an RSA key: " .. tostring(err))
end

local MESSAGE = '{"bundle_version":1,"payload_digest":"deadbeef"}'

local signature, sign_err = key:sign(MESSAGE, "sha256")
if not signature then
  fail("resty.openssl.pkey cannot SIGN with sha256: " .. tostring(sign_err))
end

-- (3) A genuine signature must verify.
local verified, verify_err = key:verify(signature, MESSAGE, "sha256")
if not verified then
  fail("a genuine RS256 signature did not verify: " .. tostring(verify_err))
end

-- (4) THE IMPORTANT ONE. A library that says yes to everything is worse than
-- no library at all, because the plugin would then report every bundle as
-- verified — including forged ones.
local tampered = '{"bundle_version":2,"payload_digest":"deadbeef"}'
local wrongly_verified = key:verify(signature, tampered, "sha256")
if wrongly_verified then
  fail("a TAMPERED message verified — this library cannot be trusted")
end

-- And a signature from an unrelated key must not verify either.
local other = pkey.new({ type = "RSA", bits = 2048 })
if other and other:verify(signature, MESSAGE, "sha256") then
  fail("a signature from an UNRELATED key verified")
end

-- Public-key-only verification, which is what the plugin will actually do: it
-- holds no private key and must verify from published PEM alone.
local public_pem = key:to_PEM("public")
if not public_pem then
  fail("could not export a public PEM")
end
local public_only, load_err = pkey.new(public_pem)
if not public_only then
  fail("a published public PEM could not be loaded: " .. tostring(load_err))
end
if not public_only:verify(signature, MESSAGE, "sha256") then
  fail("verification from a PUBLIC-KEY-ONLY handle failed")
end
if public_only:verify(signature, tampered, "sha256") then
  fail("public-key-only handle verified a TAMPERED message")
end

print("RSA CAPABILITY: AVAILABLE")
print("  library      : resty.openssl.pkey (lua-resty-openssl, already used by crypto.lua)")
print("  algorithm    : RSA PKCS#1 v1.5 with SHA-256 (RS256)")
print("  genuine sig  : verified")
print("  tampered msg : correctly REFUSED")
print("  foreign key  : correctly REFUSED")
print("  public-only  : verified from published PEM, refused tampered")
print("  new deps     : none")
os.exit(0)
