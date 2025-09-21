package netfilterlsm

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"

	_ "embed"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	ProtectNftablesAllowedCgroupMap  = "protect_nftables_allowed_cg"
	ProtectCgroupExecAllowedPathsMap = "protect_cgroup_exec_allowed_paths"
	ProtectNftablesProg              = []string{"protect_nftables"}
	ProtectCgroupExecProg            = []string{"protect_cgroup_exec_alloc", "protect_cgroup_exec_check"}
	ProtectBpfProg                   = []string{"protect_bpf_unlink", "protect_bpf_rename", "protect_bpf_rmdir", "protect_bpf_remount", "protect_bpf_umount", "protect_bpf"}
)

//go:embed ebpf/netfilter_lsm.bpf.o
var netfilterLsmObj []byte

type NetfilterLsm struct {
	pinPath string
	objects *ebpf.Collection
	links   map[string]link.Link
	cgIdx   uint32
}

const (
	ALLOWED_CG_SIZE    = 16
	ALLOWED_PATHS_SIZE = 16
)

func NewNetfilterLsm(pinPath string) (*NetfilterLsm, error) {
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("create pin dir %q: %v", pinPath, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netfilterLsmObj))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %v", err)
	}

	objs, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load and assign: %v", err)
	}

	return &NetfilterLsm{
		pinPath: pinPath,
		objects: objs,
		links:   make(map[string]link.Link),
		cgIdx:   0,
	}, nil
}

func (n *NetfilterLsm) Close() {
	n.objects.Close()
	for _, l := range n.links {
		l.Close()
	}
}

func (n *NetfilterLsm) ProtectNftables() error {
	return n.linkAndPinLSM(ProtectNftablesProg)
}

func (n *NetfilterLsm) ProtectCgroupExec() error {
	return n.linkAndPinLSM(ProtectCgroupExecProg)
}

func (n *NetfilterLsm) ProtectBpf() error {
	return n.linkAndPinLSM(ProtectBpfProg)
}

func (n *NetfilterLsm) AllowNftables(cgPath string, allowExec []string) error {
	cgAbs := filepath.Join("/sys/fs/cgroup", cgPath)
	cgfd, err := unix.Open(cgAbs, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %q: %v", cgAbs, err)
	}
	defer unix.Close(cgfd)

	if n.cgIdx >= ALLOWED_CG_SIZE {
		return fmt.Errorf("exceeded max allowed cgroup size: %d", ALLOWED_CG_SIZE)
	}
	cg := n.cgIdx
	n.cgIdx++

	m1, ok := n.objects.Maps[ProtectNftablesAllowedCgroupMap]
	if !ok {
		return fmt.Errorf("map %q not found", ProtectNftablesAllowedCgroupMap)
	}
	if err := m1.Put(uint32(cg), uint32(cgfd)); err != nil {
		return fmt.Errorf("put cgroup fd to map: %v", err)
	}

	m2, ok := n.objects.Maps[ProtectCgroupExecAllowedPathsMap]
	if !ok {
		return fmt.Errorf("map %q not found", ProtectCgroupExecAllowedPathsMap)
	}
	for i, p := range allowExec {
		if i >= ALLOWED_PATHS_SIZE {
			return fmt.Errorf("exceeded max allowed paths size: %d", ALLOWED_PATHS_SIZE)
		}
		key := uint64(cg)*ALLOWED_PATHS_SIZE + uint64(i)
		var val [256]byte
		if len(p) >= len(val) {
			return fmt.Errorf("path too long: %q", p)
		}
		copy(val[:], p)
		if err := m2.Put(key, &val); err != nil {
			return fmt.Errorf("put allowed path to map: %v", err)
		}
	}
	return nil
}

func (n *NetfilterLsm) linkAndPinLSM(targets []string) error {
	for _, target := range targets {
		prog, ok := n.objects.Programs[target]
		if !ok {
			return fmt.Errorf("program %q not found", target)
		}
		if prog.Type() != ebpf.LSM {
			return fmt.Errorf("program %q has wrong type: %v", target, prog.Type())
		}
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			return fmt.Errorf("attach lsm %q: %v", target, err)
		}
		n.links[target] = l
		if err := l.Pin(path.Join(n.pinPath, target)); err != nil {
			return fmt.Errorf("pin link: %v", err)
		}
	}
	return nil
}
