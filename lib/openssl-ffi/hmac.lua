local ffi = require "ffi"
local version = require "openssl-ffi.version"

local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_typeof = ffi.typeof
local lib = version.lib
local version_gte_11 = version.gte_11

local _M = {}
local mt = { __index = _M }

ffi.cdef[[
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct env_md_st EVP_MD;
typedef struct engine_st ENGINE;
struct env_md_ctx_st {
  const EVP_MD *digest;
  ENGINE *engine;
  unsigned long flags;
  void *md_data;
  EVP_PKEY_CTX *pctx;
  int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
};
typedef struct hmac_ctx_st {
  const EVP_MD *md;
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX i_ctx;
  EVP_MD_CTX o_ctx;
  unsigned int key_length;
  unsigned char key[128];
} HMAC_CTX;

// OpenSSL 1.0
void HMAC_CTX_init(HMAC_CTX *ctx);
// OpenSSL 1.1
HMAC_CTX *HMAC_CTX_new(void);

int HMAC_Init(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);

// OpenSSL 1.0
void HMAC_CTX_cleanup(HMAC_CTX *ctx);
// OpenSSL 1.1
void HMAC_CTX_free(HMAC_CTX *ctx);
]]

local function new_ctx()
  local ctx
  if version_gte_11 then
    ctx = lib.HMAC_CTX_new()
    ffi_gc(ctx, lib.HMAC_CTX_free)
  else
    ctx = ffi_new(ffi_typeof("HMAC_CTX[1]"))
    ffi_gc(ctx, lib.HMAC_CTX_cleanup)
    lib.HMAC_CTX_init(ctx)
  end

  return ctx
end

function _M.new(key, digest)
  local ctx = new_ctx()
  if lib.HMAC_Init_ex(ctx, key, #key, digest._digest, nil) ~= 1 then
    return error("hmac: HMAC_Init_ex error")
  end

  local digest_len = lib.EVP_MD_size(digest._digest)
  local buf = ffi_new("char[?]", digest_len)

  return setmetatable({
    _ctx = ctx,
    _buf = buf,
    _digest_len = digest_len,
  }, mt)
end

function _M.update(self, string)
  if lib.HMAC_Update(self._ctx, string, #string) ~= 1 then
    return error("hmac: HMAC_Update error")
  end
end

function _M.final(self)
  local final_ctx = new_ctx()
  if lib.HMAC_CTX_copy(final_ctx, self._ctx) ~= 1 then
    return error("digest: HMAC_CTX_copy error")
  end

  if lib.HMAC_Final(final_ctx, self._buf, nil) ~= 1 then
    return error("digest: HMAC_Final error")
  end

  return ffi_str(self._buf, self._digest_len)
end

function _M.reset(self)
  if lib.HMAC_Init_ex(self._ctx, nil, 0, nil, nil) ~= 1 then
    return error("hmac: HMAC_Init_ex error")
  end
end

return _M
