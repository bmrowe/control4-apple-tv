-- Paste into the Apple TV driver's Lua tab in Composer. Blocks the driver ~3 s.
-- Reports where the per-frame AEAD floor goes.
local function upvalue(fn, want)
  for i = 1, 255 do
    local name, value = debug.getupvalue(fn, i)
    if name == nil then return nil end
    if name == want then return value end
  end
end
local C4D = upvalue(EC.CONNECT_COMPANION, "C4Driver")
local C = upvalue(C4D.init, "ChaCha20Poly1305Pure")
local O = upvalue(C4D.init, "OpenSSLCrypto")
local ossl = require("openssl")
local bn = ossl.bn
local function now() return C4:GetTime() end
local function time(fn)
  fn()
  local n, t0 = 0, now()
  repeat fn(); n = n + 1 until now() - t0 >= 100
  return (now() - t0) / n, n
end
local function bench(label, fn)
  local ms, n = time(fn)
  print(string.format("%-40s %9.4f ms  (n=%d)", label, ms, n))
end

local hook, mask, count = debug.gethook()
print("driver v" .. tostring(C4:GetDriverConfigInfo("version")) .. ", runtime: " .. tostring(_VERSION) ..
  ", jit=" .. tostring(jit and jit.version) .. " status=" .. tostring(jit and (jit.status())) ..
  ", chacha20=" .. C.keystream_backend() ..
  ", tag backend=" .. C.tag_backend() .. ", NATIVE_TAG_MIN_BYTES=" .. tostring(C.NATIVE_TAG_MIN_BYTES))
print("debug hook: " .. tostring(hook) .. " mask=" .. tostring(mask) .. " count=" .. tostring(count))
local key, nonce, aad = O.random_bytes(32), O.random_bytes(12), "aad!"
local pt1k = string.rep("p", 1024)
local ct1k = C.encrypt(key, nonce, pt1k, aad)

-- per-frame pieces
local zeros = string.rep("\0", 32)
local P = bn.text(string.char(3) .. string.rep("\255", 15) .. string.char(251))
local r = bn.text(string.rep("\7", 16))
local tag = ct1k:sub(-16)
local ct = ct1k:sub(1, -17)
bench("AEAD decrypt 1 KB (whole call)", function() C.decrypt(key, nonce, ct1k, aad) end)
bench("  native chacha20, 32 B (otk)", function() C.chacha20(key, nonce, 0, zeros) end)
bench("  native chacha20, 1 KB", function() C.chacha20(key, nonce, 1, ct) end)
if C._tag then
  bench("  forged-tag verify only", function() C._tag.verify(key, nonce, aad, ct, tag) end)
  bench("  forged-tag compute only", function() C._tag.tag(key, nonce, aad, ct) end)
end
bench("  bn.invmod (130-bit)", function() bn.invmod(r, P) end)
bench("  bn.mulmod (130-bit)", function() bn.mulmod(r, r, P) end)
bench("  bn.text (16 B)", function() bn.text(zeros:sub(1, 16)) end)
bench("  AEAD ctx: get+new+init+update+final", function()
  local e = ossl.cipher.get("chacha20-poly1305"):encrypt_new()
  e:init(key, nonce); e:update(zeros); e:final()
end)
bench("  Lua: concat 1 KB + pad + lengths", function()
  local s = aad .. string.rep("\0", 12) .. ct .. string.rep("\0", 8)
  return #s
end)
-- Lua Poly1305 vs the forged native tag, both including the native one-time key
print(string.format("%-8s %12s %12s", "ct", "Lua tag", "native tag"))
for _, size in ipairs({ 32, 64, 256, 1024, 2048 }) do
  local c = string.rep("c", size)
  local lua_ms = time(function() C.auth_tag(key, nonce, c, aad) end)
  local native_ms = C._tag and time(function() C._tag.tag(key, nonce, aad, c) end)
  print(string.format("%-8s %9.4f ms %s", size .. " B", lua_ms,
    native_ms and string.format("%9.4f ms", native_ms) or "  unavailable"))
end

bench("HKDF-SHA512 (Lua HMAC over C4:Hash)", function() O.hkdf_sha512("salt", "info", key) end)
bench("C4:Hash SHA512, 100 B", function()
  C4:Hash("SHA512", string.rep("y", 100), { return_encoding = "NONE", data_encoding = "NONE" })
end)
collectgarbage("collect")
print(string.format("lua heap %.0f KB", collectgarbage("count")))
