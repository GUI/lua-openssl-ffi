package = "openssl-ffi"
version = "git-1"
source = {
  url = "git://github.com/GUI/lua-openssl-ffi.git",
}
description = {
  summary = "",
  detailed = "",
  homepage = "https://github.com/GUI/lua-openssl-ffi",
  license = "MIT",
}
build = {
  type = "builtin",
  modules = {
    ["openssl-ffi"] = "lib/openssl-ffi.lua",
    ["openssl-ffi.cipher"] = "lib/openssl-ffi/cipher.lua",
    ["openssl-ffi.digest"] = "lib/openssl-ffi/digest.lua",
    ["openssl-ffi.hmac"] = "lib/openssl-ffi/hmac.lua",
    ["openssl-ffi.pkey"] = "lib/openssl-ffi/pkey.lua",
    ["openssl-ffi.rand"] = "lib/openssl-ffi/rand.lua",
    ["openssl-ffi.x509"] = "lib/openssl-ffi/x509.lua",
  },
}
