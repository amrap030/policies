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
MIICnTCCAYUCBgF4FRtFXTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdQUk9D
RUVEMB4XDTIxMDMwOTAzNDgzMloXDTMxMDMwOTAzNTAxMlowEjEQMA4GA1UEAwwH
UFJPQ0VFRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJNPjmlijoG4
Wt8TP9xUkx+fjLpTo7AXbHsXNp8LNYLX2/dAo/5aT587NHafK9gP470aUSr8BTpW
QDXdDFUjE5Uk7N+4O4pRjnItVUHUoWNfOSUYRCIYjZrXJIjzBLHOIuZqXHZwjVev
qvwrnJ4vWojpcqRt1s5P0jsZ7Cxi677PZp6j2PPRL6qsCs5v4gTIiSNPA8LnY42D
1ArTEYDS9YpYc1U5Slje15ASWE5FSGJYJxOshaji9Rv+p8rmzdbqiLnOCZ3kjTmN
h/C8W4DEYB2Tq41XrOSQEtk+HKUeuerOPp/JpEsXxQeo9Ty5OLhgITQS8u7MCLfn
aBJJG2LbsTMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAZyrcmUMCTPPKVCpSRgVP
5MBlq18lHzcF4olo2fgbNO65KrKtK6+QLgt0fn1/x4Il2HjuTR17pusEnLxB7Gk8
RUh+XOvrAcDZuesQaZL/5Fs/jSetC+8s9I7Fe9Q+MRala+duOjc5QcfHAaSBvfMg
zi2NnykGEAJ02zn6yvlu+eWu0lYxJfYYoOyvVElsgzG+jvteariuxYQ5TiYpUtlg
glgnmLr8EAz0IBzT3nNjKxNIxFKEi/w1gAY8CX2thhLNGkik0+lmvcFFqYjVJdQr
joqHEkyBoM9aRUxGnZg/w+0WDIu6wYwLyuOBrTjceFnnUAOroRqdQnBRnHsRih2Y
Yg==
-----END CERTIFICATE-----`

payload[valid] {
	[valid, header, payload] := io.jwt.decode_verify(bearer_token, {"cert": certificate})
}

bearer_token := bearer {
	bearer := input.headers.authorization
}

#bearerPrefix := substring(authHeader, 0, count("Bearer "))
#lower(bearerPrefix) == "bearer "
#bearer := substring(authHeader, count("Bearer "), -1)
