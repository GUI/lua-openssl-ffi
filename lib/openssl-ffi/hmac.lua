local ffi = require "ffi"

local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_typeof = ffi.typeof

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

void HMAC_CTX_init(HMAC_CTX *ctx);

int HMAC_Init(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

void HMAC_CTX_cleanup(HMAC_CTX *ctx);
]]

function _M.new(key, digest)
  local ctx = ffi_new(ffi_typeof("HMAC_CTX[1]"))
  ffi_gc(ctx, C.HMAC_CTX_cleanup)

  C.HMAC_CTX_init(ctx)

  if C.HMAC_Init_ex(ctx, key, #key, digest._digest, nil) ~= 1 then
    return error("hmac: HMAC_Init_ex error")
  end

  local digest_len = C.EVP_MD_size(digest._digest)
  local buf = ffi_new("char[?]", digest_len)

  return setmetatable({
    _ctx = ctx,
    _buf = buf,
    _digest_len = digest_len,
  }, mt)
end

function _M.update(self, string)
  return C.HMAC_Update(self._ctx, string, #string) == 1
end

function _M.final(self)
  if C.HMAC_Final(self._ctx, self._buf, nil) ~= 1 then
    return error("digest: EVP_DigestFinal_ex error")
  end

  return ffi_str(self._buf, self._digest_len)
end

function _M.reset(self)
  return C.HMAC_Init_ex
end

return _M
