.PHONY: test

test:
	luarocks make --local openssl-ffi-git-1.rockspec
	env LUA_PATH="${HOME}/.luarocks/share/lua/5.1/?.lua;;" busted spec
