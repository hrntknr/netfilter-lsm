#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif
#ifndef EPERM
#define EPERM 1
#endif
#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

char LICENSE[] SEC("license") = "GPL";

#define ALLOWED_CG_SIZE 256

struct
{
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __uint(max_entries, ALLOWED_CG_SIZE);
  __type(key, __u32);
  __type(value, __u32);
} allowed_cg SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u8);
  __uint(max_entries, 4096);
} protected_links SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(deny_nf_sock_create, int family, int type, int protocol, int kern)
{
  if (family != AF_NETLINK)
    return 0;
  if (protocol != NETLINK_NETFILTER)
    return 0;
  for (__u32 i = 0; i < ALLOWED_CG_SIZE; i++)
  {
    if (bpf_current_task_under_cgroup(&allowed_cg, i) == 1)
    {
      return 0;
    }
  }
  return -EPERM;
}

static __always_inline bool is_bpffs(const struct super_block *sb)
{
  __u64 magic = BPF_CORE_READ(sb, s_magic);
  if (magic == BPF_FS_MAGIC)
    return true;
  return false;
}

static __always_inline bool under_protected_dir(struct dentry *d)
{
  struct super_block *sb = BPF_CORE_READ(d, d_sb);
  if (is_bpffs(sb))
    return true;
  return false;
}

SEC("lsm/path_unlink")
int BPF_PROG(protect_bpf_unlink, const struct path *dir, struct dentry *dentry)
{
  if (under_protected_dir(dentry))
    return -EPERM;
  return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(protect_bpf_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
  if (under_protected_dir(old_dentry))
    return -EPERM;
  return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(protect_bpf_rmdir, const struct path *dir, struct dentry *dentry)
{
  if (under_protected_dir(dentry))
    return -EPERM;
  return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(protect_bpf_remount, struct super_block *sb, void *mnt_opts)
{
  if (is_bpffs(sb))
    return -EPERM;
  return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(protect_bpf_umount, struct vfsmount *mnt, int flags)
{
  struct super_block *sb = BPF_CORE_READ(mnt, mnt_sb);
  if (is_bpffs(sb))
    return -EPERM;
  return 0;
}

SEC("lsm/bpf")
int BPF_PROG(protect_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
  if (cmd == BPF_PROG_DETACH)
    return -EPERM;
  if (cmd == BPF_LINK_DETACH)
    return -EPERM;
  if (cmd == BPF_MAP_UPDATE_ELEM)
    return -EPERM;
  return 0;
}
