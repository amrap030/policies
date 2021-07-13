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

jwks = `{
    "keys": [
                {
                    "kid": "AI8TrYcBFlFMDizKBxRPv-qYTUfB5U4TZ6h_uoTOagM",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "k0-OaWKOgbha3xM_3FSTH5-MulOjsBdsexc2nws1gtfb90Cj_lpPnzs0dp8r2A_jvRpRKvwFOlZANd0MVSMTlSTs37g7ilGOci1VQdShY185JRhEIhiNmtckiPMEsc4i5mpcdnCNV6-q_Cucni9aiOlypG3Wzk_SOxnsLGLrvs9mnqPY89EvqqwKzm_iBMiJI08DwudjjYPUCtMRgNL1ilhzVTlKWN7XkBJYTkVIYlgnE6yFqOL1G_6nyubN1uqIuc4JneSNOY2H8LxbgMRgHZOrjVes5JAS2T4cpR656s4-n8mkSxfFB6j1PLk4uGAhNBLy7swIt-doEkkbYtuxMw",
                    "e": "AQAB",
                    "x5c": [
                        "MIICnTCCAYUCBgF4FRtFXTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdQUk9DRUVEMB4XDTIxMDMwOTAzNDgzMloXDTMxMDMwOTAzNTAxMlowEjEQMA4GA1UEAwwHUFJPQ0VFRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJNPjmlijoG4Wt8TP9xUkx+fjLpTo7AXbHsXNp8LNYLX2/dAo/5aT587NHafK9gP470aUSr8BTpWQDXdDFUjE5Uk7N+4O4pRjnItVUHUoWNfOSUYRCIYjZrXJIjzBLHOIuZqXHZwjVevqvwrnJ4vWojpcqRt1s5P0jsZ7Cxi677PZp6j2PPRL6qsCs5v4gTIiSNPA8LnY42D1ArTEYDS9YpYc1U5Slje15ASWE5FSGJYJxOshaji9Rv+p8rmzdbqiLnOCZ3kjTmNh/C8W4DEYB2Tq41XrOSQEtk+HKUeuerOPp/JpEsXxQeo9Ty5OLhgITQS8u7MCLfnaBJJG2LbsTMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAZyrcmUMCTPPKVCpSRgVP5MBlq18lHzcF4olo2fgbNO65KrKtK6+QLgt0fn1/x4Il2HjuTR17pusEnLxB7Gk8RUh+XOvrAcDZuesQaZL/5Fs/jSetC+8s9I7Fe9Q+MRala+duOjc5QcfHAaSBvfMgzi2NnykGEAJ02zn6yvlu+eWu0lYxJfYYoOyvVElsgzG+jvteariuxYQ5TiYpUtlgglgnmLr8EAz0IBzT3nNjKxNIxFKEi/w1gAY8CX2thhLNGkik0+lmvcFFqYjVJdQrjoqHEkyBoM9aRUxGnZg/w+0WDIu6wYwLyuOBrTjceFnnUAOroRqdQnBRnHsRih2YYg=="
                    ],
                    "x5t": "KuPlsh2e-Gptax8r97hKWm4EfdQ",
                    "x5t#S256": "0j6lpEYycvRZBPnMHqazQRu5_jQdeFbFTofUMVsaOIA"
                }
            ]
}`

payload[valid] {
	[valid, header, payload] := io.jwt.decode_verify(bearer_token, {"cert": jwks})
}

bearer_token := bearer {
	bearer := input.headers.authorization
}

#bearerPrefix := substring(authHeader, 0, count("Bearer "))
#lower(bearerPrefix) == "bearer "
#bearer := substring(authHeader, count("Bearer "), -1)
