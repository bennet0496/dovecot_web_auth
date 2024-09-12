-- MIT License
--
-- Copyright (c) 2024 Bennet Becker <dev@bennet.cc>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--

function script_init()
    return 0
end

function script_deinit()
end


local json = require "cjson"

local http_client = dovecot.http.client {
    timeout = 10000;
    max_attempts = 3;
    debug = true;
}

-- base64 encoder from https://github.com/iskolbin/lbase64 (MIT/X11)
function extract( v, from, width )
    return ( v >> from ) & ((1 << width) - 1)
end

function base64_makeencoder()
	local encoder = {}
	for b64code, char in pairs{[0]='A','B','C','D','E','F','G','H','I','J',
		'K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y',
		'Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n',
		'o','p','q','r','s','t','u','v','w','x','y','z','0','1','2',
		'3','4','5','6','7','8','9','+','/','='} do
		encoder[b64code] = char:byte()
	end
	return encoder
end

local char, concat = string.char, table.concat

function base64_encode( str, encoder, usecaching )
	encoder = base64_makeencoder()
	local t, k, n = {}, 1, #str
	local lastn = n % 3
	local cache = {}
	for i = 1, n-lastn, 3 do
		local a, b, c = str:byte( i, i+2 )
		local v = a*0x10000 + b*0x100 + c
		local s
		if usecaching then
			s = cache[v]
			if not s then
				s = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[extract(v,0,6)])
				cache[v] = s
			end
		else
			s = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[extract(v,0,6)])
		end
		t[k] = s
		k = k + 1
	end
	if lastn == 2 then
		local a, b = str:byte( n-1, n )
		local v = a*0x10000 + b*0x100
		t[k] = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[64])
	elseif lastn == 1 then
		local v = str:byte( n )*0x10000
		t[k] = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[64], encoder[64])
	end
	return concat( t )
end

function auth_password_verify(request, password)
  local auth_request = http_client:request {
    url = "http://127.0.0.1:8000/auth";
    method = "POST";
  }
  local req = {
    username = request.user,
    password = base64_encode(password),
    service = request.service,
    remote_ip = request.remote_ip,
  }
  --print(json.encode(req))
  auth_request:set_payload(json.encode(req))
  local auth_response = auth_request:submit()

  local resp_status = auth_response:status()
  local resp_msg = auth_response:payload()

  local resp_map = {
      -- CONTINUE
      [100] = dovecot.auth.PASSDB_RESULT_NEXT,
      -- OK
      [200] = dovecot.auth.PASSDB_RESULT_OK,
      -- BAD REQUEST
      [400] = dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE,
      -- UNAUTHORIZED
      [401] = dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH,
      -- FORBIDDEN
      [403] = dovecot.auth.PASSDB_RESULT_USER_DISABLED,
      -- NOT FOUND
      [404] = dovecot.auth.PASSDB_RESULT_USER_UNKNOWN,
      -- METHOD NOT ALLOWED
      [405] = dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE,
      -- NOT ACCEPTABLE
      [406] = dovecot.auth.PASSDB_RESULT_SCHEME_NOT_AVAILABLE,
      -- GONE
      [410] = dovecot.auth.PASSDB_RESULT_PASS_EXPIRED,
      -- UNPROCESSABLE CONTENT (invalid request payload)
      [422] = dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE,
      -- INTERNAL SERVER ERROR (crash)
      [500] = dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE,
  }

  dovecot.i_debug(resp_status .. " " .. resp_msg)
  local response_json, error = pcall(json.decode, resp_msg)

  local response_text = ""
  if not error then
      response_text = response_json["status"] or ""
  end

  if resp_map[resp_status] ~= nil
  then
    dovecot.i_debug(response_text)
    return resp_map[resp_status], response_text
  else
    return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "unexpected return value"
  end
end