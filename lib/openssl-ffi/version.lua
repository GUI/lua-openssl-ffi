local ffi = require "ffi"

local C = ffi.C

local _M = {}

ffi.cdef[[
// OpenSSL 1.0
unsigned long SSLeay(void);
void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);

// OpenSSL 1.1
unsigned long OpenSSL_version_num();
]]

-- First, try to detect OpenResty with OpenSSL 1.1 (in OpenResty, the OpenSSL
-- library is statically compiled with the nginx binary, so it's available on
-- the global "C" library).
local lib = C
local ok, version_num = pcall(function()
  return lib.OpenSSL_version_num();
end)

-- Next, try to detect OpenResty with OpenSSL 1.0.
if not ok then
  ok, version_num = pcall(function()
    return lib.SSLeay();
  end)
end

-- If not using OpenResty, then load libcrypto, and then try to detect the
-- version again. Note, that we only load this external module if necessary,
-- since loading an external version of libcrypto into OpenResty (which already
-- has OpenSSL compiled into nginx) causes problems.
if not ok then
  lib = ffi.load("crypto")

  -- OpenSSL 1.1
  ok, version_num = pcall(function()
    return lib.OpenSSL_version_num();
  end)

  -- OpenSSL 1.0
  if not ok then
    ok, version_num = pcall(function()
      return lib.SSLeay();
    end)
  end
end

if not ok then
  error("Could not determine OpenSSL version. " .. (tostring(version_num) or ""))
end

_M.lib = lib
_M.version_num = version_num

_M.gte_11 = (_M.version_num >= 0x1010000f)
_M.lt_11 = (not _M.gte_11)

-- OpenSSL 1.0 requires loading ciphers and digests (this happens automatically
-- in 1.1+).
if _M.lt_11 then
  lib.OpenSSL_add_all_ciphers()
  lib.OpenSSL_add_all_digests()
end

return _M
