package proxy.policy

import rego.v1

default allow := false

allow if {
	input.method == "GET"
	net.cidr_contains("0.0.0.0/0", input.remoteaddr)
}
