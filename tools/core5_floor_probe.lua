-- Paste into the Apple TV driver's Lua tab in Composer. Blocks the driver ~2 s.
-- Reports whether LuaJIT is actually compiling on the controller and where the
-- per-frame AEAD floor goes.
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
local function bench(label, fn)
  fn()
  local n, t0 = 0, now()
  repeat fn(); n = n + 1 until now() - t0 >= 100
  print(string.format("%-40s %9.4f ms  (n=%d)", label, (now() - t0) / n, n))
end

local hook, mask, count = debug.gethook()
print("debug hook: " .. tostring(hook) .. " mask=" .. tostring(mask) .. " count=" .. tostring(count))
print("jit: " .. tostring(jit and jit.version) .. " status=" .. tostring(jit and (jit.status())))

-- JIT health: a tight pure-Lua loop, then trace events while AEAD runs
bench("pure Lua loop, 10k iterations", function()
  local s = 0
  for i = 1, 10000 do s = s + i % 7 end
  return s
end)
local key, nonce, aad = O.random_bytes(32), O.random_bytes(12), "aad!"
local pt1k = string.rep("p", 1024)
local ct1k = C.encrypt(key, nonce, pt1k, aad)
local events, reasons = { start = 0, stop = 0, abort = 0 }, {}
local vmdef_ok, vmdef = pcall(require, "jit.vmdef")
local attached = jit and jit.attach and pcall(jit.attach, function(what, _, _, _, otr, oex)
  events[what] = (events[what] or 0) + 1
  if what == "abort" then
    local reason = tostring(otr)
    if vmdef_ok and type(otr) == "number" and vmdef.traceerr and vmdef.traceerr[otr] then
      reason = string.format(vmdef.traceerr[otr], tostring(oex))
    end
    reasons[reason] = (reasons[reason] or 0) + 1
  end
end, "trace")
for _ = 1, 300 do C.decrypt(key, nonce, ct1k, aad); C.encrypt(key, nonce, pt1k, aad) end
if attached then pcall(jit.attach, function() end) end
print(string.format("trace events during 600 AEAD calls: start=%d stop=%d abort=%d (attach %s)",
  events.start or 0, events.stop or 0, events.abort or 0, attached and "ok" or "unavailable"))
for reason, n in pairs(reasons) do print("  abort x" .. n .. ": " .. reason) end

-- per-frame pieces
local zeros = string.rep("\0", 32)
local P = bn.text(string.char(3) .. string.rep("\255", 15) .. string.char(251))
local r = bn.text(string.rep("\7", 16))
local tag = ct1k:sub(-16)
local ct = ct1k:sub(1, -17)
bench("AEAD decrypt 1 KB (whole call)", function() C.decrypt(key, nonce, ct1k, aad) end)
bench("  native chacha20, 32 B (otk)", function() C.chacha20(key, nonce, 0, zeros) end)
bench("  native chacha20, 1 KB", function() C.chacha20(key, nonce, 1, ct) end)
bench("  forged-tag verify only", function() C._tag.verify(key, nonce, aad, ct, tag) end)
bench("  forged-tag compute only", function() C._tag.tag(key, nonce, aad, ct) end)
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
bench("HKDF-SHA512 (Lua HMAC over C4:Hash)", function() O.hkdf_sha512("salt", "info", key) end)
bench("C4:Hash SHA512, 100 B", function()
  C4:Hash("SHA512", string.rep("y", 100), { return_encoding = "NONE", data_encoding = "NONE" })
end)
collectgarbage("collect")
print(string.format("lua heap %.0f KB", collectgarbage("count")))
