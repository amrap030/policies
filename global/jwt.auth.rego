# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets role mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., role mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package global.jwt.auth

certificate = `-----BEGIN CERTIFICATE-----
MIICxzCCAa+gAwIBAgIEHP9VkjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwls
b2NhbGhvc3QwHhcNMTgwNDI3MDAzNTAyWhcNMTgwNzI2MDAzNTAyWjAUMRIwEAYD
VQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD5
ZwGM+ysW8Y7CpUl3y+lX6A3HmidPIuNjHzria0i9TE7wPibABpimNcmCyt7Z1xeN
DTcE4sl1yNjk1z0pyV5rT2eEUgQkMbehvDGb2BDDk6nVNKEI/fRep/xvsjvfwQcM
VPqoAG6XuK0jFKvP4CpS+P0tJQoTD9x1esl67pvvWod39iISVQgDR+NXCUVy1vDt
ERuLdLLedZ2b3KTszcYgqRrvuPHDUzAgGDaSV8MmCcTvZ8+Q+LcWZolMkDj72wqB
+eIWp0w1+TItVs6L0TcOVqgbESK3p8pMj0ZHVJZfjQWGGAt1PJZ27bP1FLYE6n7d
31YUxN11pvz593gvaZgJAgMBAAGjITAfMB0GA1UdDgQWBBRvOfq/9vqyjGZay5cx
O/FFUdfH+TANBgkqhkiG9w0BAQsFAAOCAQEAVPl27J8nYnbRlL2FtUieu5afVLi2
Xg7XRn80wcbx/1zH4zjgZLyV3PRw99BKDerxdObeDWhWBnHHylrY2bi4XHRhxbGl
6n7Mi7NNGtYxb8fpi7IMKZrnLGxmXE2s+yGcX8ksmw1axQDJJ6VIKrspeUZ+5Bgd
kIj0Q0Ia1I707BI5wHz4UBylPDQ0XHamR4u7Mj30+rSZVIk/sPhiLo9gAis3E5+4
oWgYufC89m2ROc2G877DNdlcKQF5bO1dC9zMB3ZNBDleRjL/op18k5C6uay2rLEb
5Amlg9MMzHR0Yt/WNsewUmhwZi+oArfEl5XONZmtBYTs5jIgkOwsDPcZVg==
-----END CERTIFICATE-----`

payload[state] {
	[valid, header, payload] := io.jwt.decode_verify(bearer_token, {"cert": certificate})
	state := header
}

bearer_token := bearer {
	bearer := input.headers.authorization
}

#bearerPrefix := substring(authHeader, 0, count("Bearer "))
#lower(bearerPrefix) == "bearer "
#bearer := substring(authHeader, count("Bearer "), -1)
