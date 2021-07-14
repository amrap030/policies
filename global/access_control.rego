package global.access_control

import data.global.jwt.auth

default allow = false

allow {
	dataa := json.unmarshal(auth.payload_data)
	dataa.preferred_username == "amrap030"
}

#access[_] == input.access
