local ffi = require "ffi"
local version = require "openssl-ffi.version"

local ffi_gc = ffi.gc
local ffi_str = ffi.string
local lib = version.lib

local _M = {}
local mt = { __index = _M }

ffi.cdef[[
struct asn1_string_st {
  int length;
  int type;
  unsigned char *data;
  long flags;
};

typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_TIME;
typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);
typedef struct bignum_st BIGNUM;

void CRYPTO_free(void *ptr);
void ASN1_INTEGER_free(void *ptr);

BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
char *BN_bn2dec(const BIGNUM *a);
int BN_dec2bn(BIGNUM **a, const char *str);

X509 *X509_new(void);
void X509_free(X509 *a);
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
ASN1_INTEGER *X509_get_serialNumber(X509 *x);
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
const ASN1_TIME * X509_get0_notBefore(const X509 *x);
int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
const ASN1_TIME *X509_get0_notAfter(const X509 *x);
int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
]]

local function asn1_integer_to_string(value)
  local bn = lib.ASN1_INTEGER_to_BN(value, nil)
  if bn == nil then
    return error("ASN1_INTEGER_to_BN error")
  end
  ffi_gc(bn, lib.BN_free)

  local dec = lib.BN_bn2dec(bn)
  if dec == nil then
    return error("BN_bn2dec error")
  end
  ffi_gc(dec, lib.CRYPTO_free)

  return ffi_str(dec)
end

local function string_to_asn1_integer(value)
  local bn = ffi.new("BIGNUM *[1]")
  ffi_gc(bn, function(p) lib.BN_free(p[0]) end)

  if lib.BN_dec2bn(bn, tostring(value)) == 0 then
    return error("BN_dec2bn error")
  end

  local asn1 = lib.BN_to_ASN1_INTEGER(bn[0], nil)
  if asn1 == nil then
    return error("BN_to_ASN1_INTEGER error")
  end
  ffi_gc(asn1, lib.ASN1_INTEGER_free)

  return asn1
end

function _M.new()
  local cert = lib.X509_new()
  ffi_gc(cert, lib.X509_free)

  -- local cert = lib.PEM_read_bio_X509(data, nil, nil, nil)

  return setmetatable({
    _cert = cert,
  }, mt)
end

function _M.get_not_before(self)
  return lib.X509_get0_notBefore(self._cert)
end

function _M.set_not_before(self, not_before)
  if lib.X509_set1_notBefore(self._cert, not_before) ~= 1 then
    return error("x509.certificate: X509_set1_notBefore error")
  end
end

function _M.get_not_after(self)
  return lib.X509_get0_notAfter(self._cert)
end

function _M.set_not_after(self, not_after)
  if lib.X509_set1_notAfter(self._cert, not_after) ~= 1 then
    return error("x509.certificate: X509_set1_notAfter error")
  end
end

function _M.get_serial_number(self)
  return asn1_integer_to_string(lib.X509_get_serialNumber(self._cert))
end

function _M.set_serial_number(self, serial_number)
  if lib.X509_set_serialNumber(self._cert, string_to_asn1_integer(serial_number)) ~= 1 then
    return error("x509.certificate: X509_set_serialNumber error")
  end
end

return _M
