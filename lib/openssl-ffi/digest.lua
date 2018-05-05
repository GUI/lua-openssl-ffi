local ffi = require "ffi"
local version = require "openssl-ffi.version"

local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local lib = version.lib
local version_gte_11 = version.gte_11

local _M = {}
local mt = { __index = _M }

ffi.cdef[[
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;
typedef struct engine_st ENGINE;

// OpenSSL 1.0
EVP_MD_CTX *EVP_MD_CTX_create(void);
// OpenSSL 1.1
EVP_MD_CTX *EVP_MD_CTX_new(void);

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

// OpenSSL 1.0
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
// OpenSSL 1.1
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

int EVP_MD_size(const EVP_MD *md);

const EVP_MD *EVP_get_digestbyname(const char *name);
]]

function _M.new(name)
  local digest = lib.EVP_get_digestbyname(name)
  if digest == nil then
    return error("invalid digest type: " .. (name or ""))
  end

  local ctx
  if version_gte_11 then
    ctx = lib.EVP_MD_CTX_new()
    ffi_gc(ctx, lib.EVP_MD_CTX_free)
  else
    ctx = lib.EVP_MD_CTX_create()
    ffi_gc(ctx, lib.EVP_MD_CTX_destroy)
  end

  if lib.EVP_DigestInit_ex(ctx, digest, nil) ~= 1 then
    return error("digest: EVP_DigestInit_ex error")
  end

  local digest_len = lib.EVP_MD_size(digest)
  local buf = ffi_new("char[?]", digest_len)

  return setmetatable({
    _ctx = ctx,
    _buf = buf,
    _digest = digest,
    _digest_len = digest_len,
  }, mt)
end

function _M.update(self, string)
  if lib.EVP_DigestUpdate(self._ctx, string, #string) ~= 1 then
    return error("digest: EVP_DigestUpdate error")
  end
end

function _M.final(self)
  if lib.EVP_DigestFinal_ex(self._ctx, self._buf, nil) ~= 1 then
    return error("digest: EVP_DigestFinal_ex error")
  end

  return ffi_str(self._buf, self._digest_len)
end

function _M.reset(self)
  if lib.EVP_DigestInit_ex(self._ctx, self._digest, nil) ~= 1 then
    return error("digest: EVP_DigestInit_ex error")
  end
end

return _M
