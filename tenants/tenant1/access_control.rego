package tenants.tenant1.access_control

import data.global.jwt.auth

default allow = false

# allow {
# 	auth.payload_data.sub == "2862dda7-7e40-4a70-a3fe-917fd9a2ac97"
# }
#access[_] == input.access
