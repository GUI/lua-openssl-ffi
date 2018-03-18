local ffi = require "ffi"

local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new

local _M = {}
local mt = { __index = _M }

function _M.new(key, digest)
  local ctx = C.EVP_PKEY_new()
  ffi_gc(pk, C.EVP_PKEY_free)
end

function _M.sign(self, digest, data)
end

function _M.verify(self, digest, signature, data)
end

return _M
