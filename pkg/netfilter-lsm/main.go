package netfilterlsm

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	_ "embed"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	pinPath          = "/sys/fs/bpf/netfilter_lsm"
	allowedCgPath    = pinPath + "/allowed_cg"
	protectBpfPrefix = "protect_bpf"
)

//go:embed ebpf/netfilter_lsm.bpf.o
var netfilterLsmObj []byte

func AddWhitelist(cgPath string) error {
	cgAbs := filepath.Join("/sys/fs/cgroup", cgPath)
	cgfd, err := unix.Open(cgAbs, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %q: %v", cgAbs, err)
	}
	defer unix.Close(cgfd)

	m, err := ebpf.LoadPinnedMap(allowedCgPath, nil)
	if err != nil {
		return fmt.Errorf("load pinned map %q: %v", allowedCgPath, err)
	}
	defer m.Close()

	idx := uint32(0)
	val := uint32(cgfd)
	if err := m.Update(idx, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update map %q: %v", allowedCgPath, err)
	}
	return nil
}

func Attach() error {
	filter := func(name string) bool {
		return !strings.HasPrefix(name, protectBpfPrefix)
	}
	if err := loadBpf(filter); err != nil {
		return fmt.Errorf("load bpf: %v", err)
	}
	return nil
}

func ProtectBpf() error {
	filter := func(name string) bool {
		return strings.HasPrefix(name, protectBpfPrefix)
	}
	if err := loadBpf(filter); err != nil {
		return fmt.Errorf("load bpf: %v", err)
	}
	return nil
}

func loadBpf(filter func(string) bool) error {
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("create pin dir %q: %v", pinPath, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netfilterLsmObj))
	if err != nil {
		return fmt.Errorf("load collection spec: %v", err)
	}

	objs, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load and assign: %v", err)
	}
	defer objs.Close()

	allowedCg := objs.Maps["allowed_cg"]
	if allowedCg == nil {
		return fmt.Errorf("map 'allowed_cg' not found")
	}

	links := map[string]link.Link{}
	for name, prog := range objs.Programs {
		if !filter(name) {
			continue
		}
		if prog.Type() != ebpf.LSM {
			return fmt.Errorf("program %q has wrong type: %v", name, prog.Type())
		}
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			return fmt.Errorf("attach lsm %q: %v", name, err)
		}
		links[name] = l
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	for name, l := range links {
		if err := l.Pin(path.Join(pinPath, name)); err != nil {
			return fmt.Errorf("pin link: %v", err)
		}
	}

	for name, m := range objs.Maps {
		if !filter(name) {
			continue
		}
		if err := m.Pin(path.Join(pinPath, name)); err != nil {
			return fmt.Errorf("pin map: %v", err)
		}
	}
	return nil
}
