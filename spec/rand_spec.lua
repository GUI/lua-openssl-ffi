describe("rand", function()
  local rand = require "openssl-ffi.rand"
  local to_hex = require "spec.support.to_hex"

  it("bytes", function()
    local str = rand.bytes(5)
    assert.equal(5, #str)
    assert.equal(10, #to_hex(str))
  end)

  it("pseudo_bytes", function()
    local str = rand.pseudo_bytes(5)
    assert.equal(5, #str)
    assert.equal(10, #to_hex(str))
  end)

  it("bytes differ", function()
    local str1 = rand.bytes(5)
    local str2 = rand.bytes(5)
    assert.is_not.equal(to_hex(str1), to_hex(str2))
  end)

  it("pseudo_bytes differ", function()
    local str1 = rand.pseudo_bytes(5)
    local str2 = rand.pseudo_bytes(5)
    assert.is_not.equal(to_hex(str1), to_hex(str2))
  end)
end)
