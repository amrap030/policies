package global.access_control

import data.global.jwt.auth

default allow = false

allow {
	1 == 1
}

#access[_] == input.access
