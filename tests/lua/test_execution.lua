-- Shared Python/Node vector, exercised through the actual pure Lua binder.
local execution = require "kong.plugins.mudraid-enforce.execution"
local raw = [=[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount_minor":1250,"recipient":"café-😀"}}}]=]
local expected = [=[{"action_key":"payments:send","action_version":2,"body_sha256":"d0c01e29f07d9e50d175d22d11c219cca81e0b37d26ef951c24ed4647727b370","bundle_payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bundle_version":4,"caller_token_sha256":"b994c394c56181b3a0fb307416c783a877b7c0b7faa6395f1cdac16f6eeb32d1","content_type":"application/json","environment":"staging","http_method":"POST","mapping_id":"mapping-1","mapping_version":3,"path":"/mcp?region=eu","platform_id":"platform-1","profile":"mudraid.execution.request/1","required_scopes":["payments:write"],"resource":"https://example.com/mcp"}]=]
local body_hash = "d0c01e29f07d9e50d175d22d11c219cca81e0b37d26ef951c24ed4647727b370"
local token_hash = "b994c394c56181b3a0fb307416c783a877b7c0b7faa6395f1cdac16f6eeb32d1"
local digest = "3f211153ec6580c30e12919e8fe61a90afc68e3b3d37750a0128af34f4f1ca1f"
local b = { bundle_version=4, payload_digest=string.rep("a",64), payload={content={surface={
  platform_id="platform-1", environment="staging", canonical_resource_uri="https://example.com/mcp"
}}}}
local action = { action_key="payments:send", action_version=2, mapping_id="mapping-1",
  mapping_revision=3, required_scopes={"payments:write"} }
local ctx = { body=raw, content_type="application/json", method="POST", path="/mcp?region=eu",
  authorization="Bearer synthetic-caller-token" }
local opts = { crypto={sha256_hex=function(bytes)
  if bytes == raw then return body_hash end
  if bytes == "synthetic-caller-token" then return token_hash end
  assert(bytes == expected, "Lua canonical binding differs from shared vector")
  return digest
end}, encode_base64=function(bytes) assert(bytes == raw); return "encoded-fixture" end }
local actual, snapshot = execution.bind(b,action,ctx,opts)
assert(actual == digest and snapshot.body_sha256 == body_hash)
assert(snapshot.body_base64 == "encoded-fixture")
for _, raw_bad in ipairs({"", string.rep("x",65537)}) do
  ctx.body=raw_bad
  assert(execution.bind(b,action,ctx,opts)==nil, "unbounded bytes were accepted")
end
ctx.body=raw
ctx.authorization=nil
assert(execution.bind(b,action,ctx,opts)==nil, "missing caller was accepted")
ctx.authorization="Bearer synthetic-caller-token"
ctx.content_type="application/json\r\nX: injected"
assert(execution.bind(b,action,ctx,opts)==nil, "header injection was accepted")
ctx.content_type="application/json"
action.mapping_revision=nil
assert(execution.bind(b,action,ctx,opts)==nil, "incomplete mapping binding was accepted")
print("PASS execution binding vector and four bounded refusal cases")
