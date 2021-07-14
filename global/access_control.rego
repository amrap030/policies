package global.access_control

import data.global.jwt.auth

default allow = false

allow {
	access == auth.payload_data.preferred_username == "amrap030"
}

#access[_] == input.access
