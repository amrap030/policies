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

certificate = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAk0+OaWKOgbha3xM/3FSTH5+MulOjsBdsexc2nws1gtfb90Cj/lpP
nzs0dp8r2A/jvRpRKvwFOlZANd0MVSMTlSTs37g7ilGOci1VQdShY185JRhEIhiN
mtckiPMEsc4i5mpcdnCNV6+q/Cucni9aiOlypG3Wzk/SOxnsLGLrvs9mnqPY89Ev
qqwKzm/iBMiJI08DwudjjYPUCtMRgNL1ilhzVTlKWN7XkBJYTkVIYlgnE6yFqOL1
G/6nyubN1uqIuc4JneSNOY2H8LxbgMRgHZOrjVes5JAS2T4cpR656s4+n8mkSxfF
B6j1PLk4uGAhNBLy7swIt+doEkkbYtuxMwIDAQAB
-----END RSA PUBLIC KEY-----`

payload[valid] {
	[valid, header, payload] := io.jwt.decode_verify(bearer_token, {"cert": certificate})
}

bearer_token := bearer {
	bearer := input.headers.authorization
}

#bearerPrefix := substring(authHeader, 0, count("Bearer "))
#lower(bearerPrefix) == "bearer "
#bearer := substring(authHeader, count("Bearer "), -1)
