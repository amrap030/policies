# The "system" namespace is reserved for internal use
# by OPA. Authorization policy must be defined under
# system.authz as follows:
package system.authz

default allow = false # Reject requests by default.

allow = true

# Logic to authorize request goes here.
