describe("x509.certificate", function()
  local Certificate = require "openssl-ffi.x509.certificate"

  it("get_serial_number", function()
    local cert = Certificate.new()
    assert.equal("0", cert:get_serial_number())
  end)

  it("set_serial_number with string", function()
    local cert = Certificate.new()
    cert:set_serial_number("99")
    assert.equal("99", cert:get_serial_number())
  end)

  it("set_serial_number with normal integer", function()
    local cert = Certificate.new()
    cert:set_serial_number(99)
    assert.equal("99", cert:get_serial_number())
  end)

  it("set_serial_number with 64bit signed integer", function()
    local cert = Certificate.new()
    cert:set_serial_number(18446744073709551615ULL)
    assert.equal("18446744073709551615", cert:get_serial_number())
  end)

  it("set_serial_number with 64bit unsigned integer", function()
    local cert = Certificate.new()
    cert:set_serial_number(9223372036854775807LL)
    assert.equal("9223372036854775807", cert:get_serial_number())
  end)

  it("set_serial_number with 64bit integer", function()
    local cert = Certificate.new()
    cert:set_serial_number("730750818665451459101842416358141509827966271488")
    cert:get_serial_number()
    assert.equal("730750818665451459101842416358141509827966271488", cert:get_serial_number())
  end)
end)
