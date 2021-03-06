describe("hmac", function()
  local Digest = require "openssl-ffi.digest"
  local HMAC = require "openssl-ffi.hmac"
  local to_hex = require "spec.support.to_hex"

  it("md4", function()
    local hmac = HMAC.new("Jefe", Digest.new("md4"))
    hmac:update("what do ya want for nothing?")
    assert.equal("be192c588a8e914d8a59b474a828128f", to_hex(hmac:final()))
  end)

  it("md5", function()
    local hmac = HMAC.new("Jefe", Digest.new("md5"))
    hmac:update("what do ya want for nothing?")
    assert.equal("750c783e6ab0b503eaa86e310a5db738", to_hex(hmac:final()))
  end)

  it("ripemd160", function()
    local hmac = HMAC.new("Jefe", Digest.new("ripemd160"))
    hmac:update("what do ya want for nothing?")
    assert.equal("dda6c0213a485a9e24f4742064a7f033b43c4069", to_hex(hmac:final()))
  end)

  it("sha1", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha1"))
    hmac:update("what do ya want for nothing?")
    assert.equal("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", to_hex(hmac:final()))
  end)

  it("sha224", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha224"))
    hmac:update("what do ya want for nothing?")
    assert.equal("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44", to_hex(hmac:final()))
  end)

  it("sha256", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    hmac:update("what do ya want for nothing?")
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
  end)

  it("sha384", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha384"))
    hmac:update("what do ya want for nothing?")
    assert.equal("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", to_hex(hmac:final()))
  end)

  it("sha512", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha512"))
    hmac:update("what do ya want for nothing?")
    assert.equal("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", to_hex(hmac:final()))
  end)

  it("whirlpool", function()
    local digest = Digest.new("whirlpool")
    digest:update("hello")
    assert.equal("0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73", to_hex(digest:final()))
  end)

  it("incremental updates", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    hmac:update("what do ya want ")
    hmac:update("for nothing?")
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
  end)

  it("no update", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    assert.equal("923598ca6d64af2a5dba79dcd021a8a0fe5c5f557519adaaf0ad532d4506dd30", to_hex(hmac:final()))
  end)

  it("empty string", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    hmac:update("")
    assert.equal("923598ca6d64af2a5dba79dcd021a8a0fe5c5f557519adaaf0ad532d4506dd30", to_hex(hmac:final()))
  end)

  it("repeated final calls", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    hmac:update("what do ya want for nothing?")
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
  end)

  it("reset", function()
    local hmac = HMAC.new("Jefe", Digest.new("sha256"))
    hmac:update("what do ya want for nothing?")
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
    hmac:reset()
    assert.equal("923598ca6d64af2a5dba79dcd021a8a0fe5c5f557519adaaf0ad532d4506dd30", to_hex(hmac:final()))
    hmac:update("what do ya want for nothing?")
    assert.equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(hmac:final()))
  end)
end)
