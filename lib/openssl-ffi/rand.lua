local ffi = require "ffi"
local version = require "openssl-ffi.version"

local ffi_new = ffi.new
local ffi_str = ffi.string
local lib = version.lib

local _M = {}

ffi.cdef[[
int RAND_bytes(unsigned char *buf, int num);
int RAND_pseudo_bytes(unsigned char *buf, int num);
]]

function _M.bytes(len)
  local buf = ffi_new("char[?]", len)
  if lib.RAND_bytes(buf, len) ~= 1 then
    return error("rand: RAND_bytes error")
  end

  return ffi_str(buf, len)
end

function _M.pseudo_bytes(len)
  local buf = ffi_new("char[?]", len)
  local status = lib.RAND_pseudo_bytes(buf, len)
  if status ~= 1 and status ~= 0 then
    return error("rand: RAND_pseudo_bytes error")
  end

  return ffi_str(buf, len)
end

return _M
