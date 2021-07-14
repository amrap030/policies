package global.access_control

import data.global.jwt.auth

default allow = false

allow[dataa] {
	dataa := json.unmarshal(auth.payload_data)
}

#access[_] == input.access
