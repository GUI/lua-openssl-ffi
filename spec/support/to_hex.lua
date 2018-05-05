return function(str)
  return (str:gsub('.', function(c)
    return string.format('%02x', string.byte(c))
  end))
end
