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
}


function auth_passdb_lookup(request, password)
  local auth_request = http_client:request {
    url = "http://127.0.0.1:8000/audit";
    method = "POST";
  }
  local req = {
    username = request.user,
    service = request.service,
    remote_ip = request.remote_ip,
    skip_password_check = request.skip_password_check,
    passdbs_seen_user_unknown = request.passdbs_seen_user_unknown
  }
  --print(json.encode(req))
  auth_request:set_payload(json.encode(req))
  local auth_response = auth_request:submit()

  local resp_status = auth_response:status()
  local resp_msg = auth_response:payload()

  local resp_map = {
      -- OK
      [200] = dovecot.auth.PASSDB_RESULT_OK,
      -- FOUND
      [307] = dovecot.auth.PASSDB_RESULT_NEXT,
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

  local response_json, error = pcall(json.decode, resp_msg)

  local response_text = ""
  if not error then
      response_text = response_json["status"] or ""
  end

  if resp_map[resp_status] ~= nil
  then
    return resp_map[resp_status], response_text
  else
    return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "unexpected return value"
  end
end