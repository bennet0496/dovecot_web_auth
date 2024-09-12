dovecot = {
    ["auth"] = {
        ["PASSDB_RESULT_INTERNAL_FAILURE"] = "dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE",
        ["PASSDB_RESULT_SCHEME_NOT_AVAILABLE"] = "dovecot.auth.PASSDB_RESULT_SCHEME_NOT_AVAILABLE",
        ["PASSDB_RESULT_USER_UNKNOWN"] = "dovecot.auth.PASSDB_RESULT_USER_UNKNOWN",
        ["PASSDB_RESULT_USER_DISABLED"] = "dovecot.auth.PASSDB_RESULT_USER_DISABLED",
        ["PASSDB_RESULT_PASS_EXPIRED"] = "dovecot.auth.PASSDB_RESULT_PASS_EXPIRED",
        ["PASSDB_RESULT_NEXT"] = "dovecot.auth.PASSDB_RESULT_NEXT",
        ["PASSDB_RESULT_PASSWORD_MISMATCH"] = "dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH",
        ["PASSDB_RESULT_OK"] = "dovecot.auth.PASSDB_RESULT_OK"
    },
    ["i_info"] = print,
    ["i_warning"] = print,
    ["i_error"] = print,
}
package.path = package.path .. ";/home/bbecker/.luarocks/share/lua/5.4/?.lua"
require "login"

print(script_init())

print(auth_passdb_lookup({remote_ip = '109.42.242.226', user = 'test', service = 'imap', password = 'tGj6-fzAp-6vcF-ZkLu'}))