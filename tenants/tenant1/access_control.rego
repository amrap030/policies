package tenants.tenant1.access_control

import data.global.jwt.auth

#default allow = false

allow[dataa] {
	dataa := auth.payload_data
}

#access[_] == input.access