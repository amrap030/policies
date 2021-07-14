package tenants.tenant1.access_control

import data.global.jwt.auth

default allow = false

allow {
	dataa := auth.payload_data
	1 = 1
}

#access[_] == input.access
