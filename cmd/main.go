package main

import netfilterlsm "github.com/hrntknr/netfilter-lsm/pkg/netfilter-lsm"

func main() {
	if err := netfilterlsm.Attach(); err != nil {
		panic(err)
	}

	if err := netfilterlsm.AddWhitelist("user.slice"); err != nil {
		panic(err)
	}

	if err := netfilterlsm.ProtectBpf(); err != nil {
		panic(err)
	}
}
