CLANG        ?= clang
LLVM_STRIP   ?= llvm-strip
SRC          := netfilter_lsm.c
OBJ          := netfilter_lsm.bpf.o
PROG_PIN     := /sys/fs/bpf/netfilter_lsm

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  BPF_ARCH := arm64
else
  BPF_ARCH := $(UNAME_M)
endif

CFLAGS = -O2 -g -Wall -target bpf \
	-D__TARGET_ARCH_$(BPF_ARCH) \
	-I. \
	-fno-asynchronous-unwind-tables

all: $(OBJ)

$(OBJ): vmlinux.h $(SRC)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@
	$(LLVM_STRIP) -g $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(OBJ) vmlinux.h

attach: $(OBJ)
	bpftool prog loadall $(OBJ) $(PROG_PIN) autoattach

detach:
	@if [ -e "$(PROG_PIN)" ]; then rm -rf $(PROG_PIN); fi
