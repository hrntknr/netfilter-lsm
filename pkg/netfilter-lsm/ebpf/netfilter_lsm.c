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

// protect netfilter socket section

#define ALLOWED_CG_SIZE 16

struct
{
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __uint(max_entries, ALLOWED_CG_SIZE);
  __type(key, __u32);
  __type(value, __u32);
} protect_nftables_allowed_cg SEC(".maps");

static __always_inline int allowed_cg_idx(void)
{
  for (__u32 i = 0; i < ALLOWED_CG_SIZE; i++)
  {
    if (bpf_current_task_under_cgroup(&protect_nftables_allowed_cg, i) == 1)
    {
      return i;
    }
  }
  return -1;
}

SEC("lsm/socket_create")
int BPF_PROG(protect_nftables, int family, int type, int protocol, int kern)
{
  if (family != AF_NETLINK)
    return 0;
  if (protocol != NETLINK_NETFILTER)
    return 0;
  if (allowed_cg_idx() >= 0)
    return 0;
  return -EPERM;
}

// protect cgroup exec section

#define ALLOWED_PATHS_SIZE 16
#define MAXP 256

struct
{
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u8);
} protect_cgroup_exec_allowed_task SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, char[MAXP]);
  __uint(max_entries, ALLOWED_CG_SIZE *ALLOWED_PATHS_SIZE);
} protect_cgroup_exec_allowed_paths SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(protect_cgroup_exec_alloc, struct task_struct *task, unsigned long clone_flags)
{
  if (allowed_cg_idx() < 0)
    return 0;

  __u8 *pflag = bpf_task_storage_get(&protect_cgroup_exec_allowed_task, bpf_get_current_task_btf(), 0, 0);
  __u8 val = pflag ? *pflag : 0;
  if (val)
  {
    __u8 *cflag = bpf_task_storage_get(&protect_cgroup_exec_allowed_task, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (cflag)
      *cflag = 1;
  }
  return 0;
}
static __always_inline int str_eq(const char *a, const char *b)
{
  for (int i = 0; i < MAXP; i++)
  {
    if (a[i] != b[i])
      return 0;
    if (a[i] == '\0')
      return 1;
  }
  return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(protect_cgroup_exec_check, struct linux_binprm *bprm, int ret)
{
  __u32 cg = allowed_cg_idx();
  if (cg == -1)
    return 0;

  __u8 *flag = bpf_task_storage_get(&protect_cgroup_exec_allowed_task, bpf_get_current_task_btf(), 0, 0);
  if (flag && *flag)
    return 0;

  struct file *f = BPF_CORE_READ(bprm, file);
  if (!f)
    return -EPERM;

  struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
  const unsigned char *kname = BPF_CORE_READ(d, d_name.name);

  char path_buf[MAXP];
  long n = bpf_probe_read_kernel_str(path_buf, MAXP, kname);
  if (n <= 0)
    return -EPERM;

  for (__u32 i = 0; i < ALLOWED_PATHS_SIZE; i++)
  {
    __u64 key = cg * ALLOWED_PATHS_SIZE + i;
    char *allowed = bpf_map_lookup_elem(&protect_cgroup_exec_allowed_paths, &key);
    if (!allowed)
      break;
    if (str_eq(allowed, path_buf))
    {
      __u8 *m = bpf_task_storage_get(&protect_cgroup_exec_allowed_task, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
      if (m)
        *m = 1;
      return 0;
    }
  }
  return -EPERM;
}

// protect bpf section

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
