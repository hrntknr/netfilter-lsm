package main

import netfilterlsm "github.com/hrntknr/netfilter-lsm/pkg/netfilter-lsm"

func main() {
	nflsm, err := netfilterlsm.NewNetfilterLsm("/sys/fs/bpf/netfilter_lsm")
	if err != nil {
		panic(err)
	}
	defer nflsm.Close()

	if err := nflsm.ProtectNftables(); err != nil {
		panic(err)
	}

	// sudo systemd-run --scope --slice=test bash -c "nft list ruleset"
	if err := nflsm.AllowNftables("test.slice", []string{"/usr/bin/bash"}); err != nil {
		panic(err)
	}

	if err := nflsm.ProtectCgroupExec(); err != nil {
		panic(err)
	}

	if err := nflsm.ProtectBpf(); err != nil {
		panic(err)
	}
}
