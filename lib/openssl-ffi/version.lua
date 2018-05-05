local ffi = require "ffi"

local C = ffi.C

local _M = {}

ffi.cdef[[
// OpenSSL 1.0
unsigned long SSLeay(void);

// OpenSSL 1.1
unsigned long OpenSSL_version_num();
]]

local _, ssl_lib = pcall(ffi.load, "ssl")

local lib
local ok, version_num = pcall(function()
  return C.OpenSSL_version_num();
end)
if ok then
  lib = C
end

if not ok and ssl_lib then
  ok, version_num = pcall(function()
    return ssl_lib.OpenSSL_version_num();
  end)
  if ok then
    lib = ssl_lib
  end
end

if not ok then
  ok, version_num = pcall(function()
    return C.SSLeay();
  end)
  if ok then
    lib = C
  end
end

if not ok and ssl_lib then
  ok, version_num = pcall(function()
    return ssl_lib.SSLeay();
  end)
  if ok then
    lib = ssl_lib
  end
end

if not ok then
  error("Could not determine OpenSSL version. " .. (tostring(version_num) or ""))
end

_M.lib = lib
_M.version_num = version_num

_M.gte_11 = (_M.version_num >= 0x1010000f)
_M.lt_11 = (not _M.gte_11)

return _M
