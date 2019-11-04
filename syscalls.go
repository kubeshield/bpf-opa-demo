package main

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

/*
#include <linux/types.h>
#include <bits/types.h>
#include <linux/unistd.h>

#define SYSCALL_TABLE_ID0 0
#define SYSCALL_TABLE_SIZE 512

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;

#define PPM_MAX_AUTOFILL_ARGS (1 << 2)
#define _packed __attribute__((packed))


#define FILLER_LIST_MAPPER(FN)			\
	FN(sys_autofill)			\
	FN(sys_generic)				\
	FN(sys_empty)				\
	FN(sys_single)				\
	FN(sys_single_x)			\
	FN(sys_open_x)				\
	FN(sys_read_x)				\
	FN(sys_write_x)				\
	FN(sys_execve_e)			\
	FN(proc_startupdate)			\
	FN(proc_startupdate_2)			\
	FN(proc_startupdate_3)			\
	FN(sys_socketpair_x)			\
	FN(sys_setsockopt_x)			\
	FN(sys_getsockopt_x)			\
	FN(sys_connect_x)			\
	FN(sys_accept4_e)			\
	FN(sys_accept_x)			\
	FN(sys_send_e)				\
	FN(sys_send_x)				\
	FN(sys_sendto_e)			\
	FN(sys_sendmsg_e)			\
	FN(sys_sendmsg_x)			\
	FN(sys_recv_x)				\
	FN(sys_recvfrom_x)			\
	FN(sys_recvmsg_x)			\
	FN(sys_recvmsg_x_2)			\
	FN(sys_shutdown_e)			\
	FN(sys_creat_x)				\
	FN(sys_pipe_x)				\
	FN(sys_eventfd_e)			\
	FN(sys_futex_e)				\
	FN(sys_lseek_e)				\
	FN(sys_llseek_e)			\
	FN(sys_socket_bind_x)			\
	FN(sys_poll_e)				\
	FN(sys_poll_x)				\
	FN(sys_pread64_e)			\
	FN(sys_preadv64_e)			\
	FN(sys_writev_e)			\
	FN(sys_pwrite64_e)			\
	FN(sys_readv_preadv_x)			\
	FN(sys_writev_pwritev_x)		\
	FN(sys_pwritev_e)			\
	FN(sys_nanosleep_e)			\
	FN(sys_getrlimit_setrlimit_e)		\
	FN(sys_getrlimit_setrlrimit_x)		\
	FN(sys_prlimit_e)			\
	FN(sys_prlimit_x)			\
	FN(sched_switch_e)			\
	FN(sched_drop)				\
	FN(sys_fcntl_e)				\
	FN(sys_ptrace_e)			\
	FN(sys_ptrace_x)			\
	FN(sys_mmap_e)				\
	FN(sys_brk_munmap_mmap_x)		\
	FN(sys_renameat_x)			\
	FN(sys_symlinkat_x)			\
	FN(sys_procexit_e)			\
	FN(sys_sendfile_e)			\
	FN(sys_sendfile_x)			\
	FN(sys_quotactl_e)			\
	FN(sys_quotactl_x)			\
	FN(sys_sysdigevent_e)			\
	FN(sys_getresuid_and_gid_x)		\
	FN(sys_signaldeliver_e)			\
	FN(sys_pagefault_e)			\
	FN(sys_setns_e)				\
	FN(sys_unshare_e)			\
	FN(sys_flock_e)				\
	FN(cpu_hotplug_e)			\
	FN(sys_semop_x)				\
	FN(sys_semget_e)			\
	FN(sys_semctl_e)			\
	FN(sys_ppoll_e)				\
	FN(sys_mount_e)				\
	FN(sys_access_e)			\
	FN(sys_socket_x)			\
	FN(sys_bpf_x)				\
	FN(sys_unlinkat_x)			\
	FN(sys_fchmodat_x)			\
	FN(sys_chmod_x)				\
	FN(sys_fchmod_x)			\
	FN(sys_mkdirat_x)			\
	FN(sys_openat_x)			\
	FN(sys_linkat_x)			\
	FN(terminate_filler)

#define FILLER_ENUM_FN(x) PPM_FILLER_##x,
enum ppm_filler_id {
	FILLER_LIST_MAPPER(FILLER_ENUM_FN)
	PPM_FILLER_MAX
};
#undef FILLER_ENUM_FN


enum ppm_event_type {
	PPME_GENERIC_E = 0,
	PPME_GENERIC_X = 1,
	PPME_SYSCALL_OPEN_E = 2,
	PPME_SYSCALL_OPEN_X = 3,
	PPME_SYSCALL_CLOSE_E = 4,
	PPME_SYSCALL_CLOSE_X = 5,
	PPME_SYSCALL_READ_E = 6,
	PPME_SYSCALL_READ_X = 7,
	PPME_SYSCALL_WRITE_E = 8,
	PPME_SYSCALL_WRITE_X = 9,
	PPME_SYSCALL_BRK_1_E = 10,
	PPME_SYSCALL_BRK_1_X = 11,
	PPME_SYSCALL_EXECVE_8_E = 12,
	PPME_SYSCALL_EXECVE_8_X = 13,
	PPME_SYSCALL_CLONE_11_E = 14,
	PPME_SYSCALL_CLONE_11_X = 15,
	PPME_PROCEXIT_E = 16,
	PPME_PROCEXIT_X = 17,
	PPME_SOCKET_SOCKET_E = 18,
	PPME_SOCKET_SOCKET_X = 19,
	PPME_SOCKET_BIND_E = 20,
	PPME_SOCKET_BIND_X = 21,
	PPME_SOCKET_CONNECT_E = 22,
	PPME_SOCKET_CONNECT_X = 23,
	PPME_SOCKET_LISTEN_E = 24,
	PPME_SOCKET_LISTEN_X = 25,
	PPME_SOCKET_ACCEPT_E = 26,
	PPME_SOCKET_ACCEPT_X = 27,
	PPME_SOCKET_SEND_E = 28,
	PPME_SOCKET_SEND_X = 29,
	PPME_SOCKET_SENDTO_E = 30,
	PPME_SOCKET_SENDTO_X = 31,
	PPME_SOCKET_RECV_E = 32,
	PPME_SOCKET_RECV_X = 33,
	PPME_SOCKET_RECVFROM_E = 34,
	PPME_SOCKET_RECVFROM_X = 35,
	PPME_SOCKET_SHUTDOWN_E = 36,
	PPME_SOCKET_SHUTDOWN_X = 37,
	PPME_SOCKET_GETSOCKNAME_E = 38,
	PPME_SOCKET_GETSOCKNAME_X = 39,
	PPME_SOCKET_GETPEERNAME_E = 40,
	PPME_SOCKET_GETPEERNAME_X = 41,
	PPME_SOCKET_SOCKETPAIR_E = 42,
	PPME_SOCKET_SOCKETPAIR_X = 43,
	PPME_SOCKET_SETSOCKOPT_E = 44,
	PPME_SOCKET_SETSOCKOPT_X = 45,
	PPME_SOCKET_GETSOCKOPT_E = 46,
	PPME_SOCKET_GETSOCKOPT_X = 47,
	PPME_SOCKET_SENDMSG_E = 48,
	PPME_SOCKET_SENDMSG_X = 49,
	PPME_SOCKET_SENDMMSG_E = 50,
	PPME_SOCKET_SENDMMSG_X = 51,
	PPME_SOCKET_RECVMSG_E = 52,
	PPME_SOCKET_RECVMSG_X = 53,
	PPME_SOCKET_RECVMMSG_E = 54,
	PPME_SOCKET_RECVMMSG_X = 55,
	PPME_SOCKET_ACCEPT4_E = 56,
	PPME_SOCKET_ACCEPT4_X = 57,
	PPME_SYSCALL_CREAT_E = 58,
	PPME_SYSCALL_CREAT_X = 59,
	PPME_SYSCALL_PIPE_E = 60,
	PPME_SYSCALL_PIPE_X = 61,
	PPME_SYSCALL_EVENTFD_E = 62,
	PPME_SYSCALL_EVENTFD_X = 63,
	PPME_SYSCALL_FUTEX_E = 64,
	PPME_SYSCALL_FUTEX_X = 65,
	PPME_SYSCALL_STAT_E = 66,
	PPME_SYSCALL_STAT_X = 67,
	PPME_SYSCALL_LSTAT_E = 68,
	PPME_SYSCALL_LSTAT_X = 69,
	PPME_SYSCALL_FSTAT_E = 70,
	PPME_SYSCALL_FSTAT_X = 71,
	PPME_SYSCALL_STAT64_E = 72,
	PPME_SYSCALL_STAT64_X = 73,
	PPME_SYSCALL_LSTAT64_E = 74,
	PPME_SYSCALL_LSTAT64_X = 75,
	PPME_SYSCALL_FSTAT64_E = 76,
	PPME_SYSCALL_FSTAT64_X = 77,
	PPME_SYSCALL_EPOLLWAIT_E = 78,
	PPME_SYSCALL_EPOLLWAIT_X = 79,
	PPME_SYSCALL_POLL_E = 80,
	PPME_SYSCALL_POLL_X = 81,
	PPME_SYSCALL_SELECT_E = 82,
	PPME_SYSCALL_SELECT_X = 83,
	PPME_SYSCALL_NEWSELECT_E = 84,
	PPME_SYSCALL_NEWSELECT_X = 85,
	PPME_SYSCALL_LSEEK_E = 86,
	PPME_SYSCALL_LSEEK_X = 87,
	PPME_SYSCALL_LLSEEK_E = 88,
	PPME_SYSCALL_LLSEEK_X = 89,
	PPME_SYSCALL_IOCTL_2_E = 90,
	PPME_SYSCALL_IOCTL_2_X = 91,
	PPME_SYSCALL_GETCWD_E = 92,
	PPME_SYSCALL_GETCWD_X = 93,
	PPME_SYSCALL_CHDIR_E = 94,
	PPME_SYSCALL_CHDIR_X = 95,
	PPME_SYSCALL_FCHDIR_E = 96,
	PPME_SYSCALL_FCHDIR_X = 97,
	PPME_SYSCALL_MKDIR_E = 98,
	PPME_SYSCALL_MKDIR_X = 99,
	PPME_SYSCALL_RMDIR_E = 100,
	PPME_SYSCALL_RMDIR_X = 101,
	PPME_SYSCALL_OPENAT_E = 102,
	PPME_SYSCALL_OPENAT_X = 103,
	PPME_SYSCALL_LINK_E = 104,
	PPME_SYSCALL_LINK_X = 105,
	PPME_SYSCALL_LINKAT_E = 106,
	PPME_SYSCALL_LINKAT_X = 107,
	PPME_SYSCALL_UNLINK_E = 108,
	PPME_SYSCALL_UNLINK_X = 109,
	PPME_SYSCALL_UNLINKAT_E = 110,
	PPME_SYSCALL_UNLINKAT_X = 111,
	PPME_SYSCALL_PREAD_E = 112,
	PPME_SYSCALL_PREAD_X = 113,
	PPME_SYSCALL_PWRITE_E = 114,
	PPME_SYSCALL_PWRITE_X = 115,
	PPME_SYSCALL_READV_E = 116,
	PPME_SYSCALL_READV_X = 117,
	PPME_SYSCALL_WRITEV_E = 118,
	PPME_SYSCALL_WRITEV_X = 119,
	PPME_SYSCALL_PREADV_E = 120,
	PPME_SYSCALL_PREADV_X = 121,
	PPME_SYSCALL_PWRITEV_E = 122,
	PPME_SYSCALL_PWRITEV_X = 123,
	PPME_SYSCALL_DUP_E = 124,
	PPME_SYSCALL_DUP_X = 125,
	PPME_SYSCALL_SIGNALFD_E = 126,
	PPME_SYSCALL_SIGNALFD_X = 127,
	PPME_SYSCALL_KILL_E = 128,
	PPME_SYSCALL_KILL_X = 129,
	PPME_SYSCALL_TKILL_E = 130,
	PPME_SYSCALL_TKILL_X = 131,
	PPME_SYSCALL_TGKILL_E = 132,
	PPME_SYSCALL_TGKILL_X = 133,
	PPME_SYSCALL_NANOSLEEP_E = 134,
	PPME_SYSCALL_NANOSLEEP_X = 135,
	PPME_SYSCALL_TIMERFD_CREATE_E = 136,
	PPME_SYSCALL_TIMERFD_CREATE_X = 137,
	PPME_SYSCALL_INOTIFY_INIT_E = 138,
	PPME_SYSCALL_INOTIFY_INIT_X = 139,
	PPME_SYSCALL_GETRLIMIT_E = 140,
	PPME_SYSCALL_GETRLIMIT_X = 141,
	PPME_SYSCALL_SETRLIMIT_E = 142,
	PPME_SYSCALL_SETRLIMIT_X = 143,
	PPME_SYSCALL_PRLIMIT_E = 144,
	PPME_SYSCALL_PRLIMIT_X = 145,
	PPME_SCHEDSWITCH_1_E = 146,
	PPME_SCHEDSWITCH_1_X = 147,
	PPME_DROP_E = 148,
	PPME_DROP_X = 149,
	PPME_SYSCALL_FCNTL_E = 150,
	PPME_SYSCALL_FCNTL_X = 151,
	PPME_SCHEDSWITCH_6_E = 152,
	PPME_SCHEDSWITCH_6_X = 153,
	PPME_SYSCALL_EXECVE_13_E = 154,
	PPME_SYSCALL_EXECVE_13_X = 155,
	PPME_SYSCALL_CLONE_16_E = 156,
	PPME_SYSCALL_CLONE_16_X = 157,
	PPME_SYSCALL_BRK_4_E = 158,
	PPME_SYSCALL_BRK_4_X = 159,
	PPME_SYSCALL_MMAP_E = 160,
	PPME_SYSCALL_MMAP_X = 161,
	PPME_SYSCALL_MMAP2_E = 162,
	PPME_SYSCALL_MMAP2_X = 163,
	PPME_SYSCALL_MUNMAP_E = 164,
	PPME_SYSCALL_MUNMAP_X = 165,
	PPME_SYSCALL_SPLICE_E = 166,
	PPME_SYSCALL_SPLICE_X = 167,
	PPME_SYSCALL_PTRACE_E = 168,
	PPME_SYSCALL_PTRACE_X = 169,
	PPME_SYSCALL_IOCTL_3_E = 170,
	PPME_SYSCALL_IOCTL_3_X = 171,
	PPME_SYSCALL_EXECVE_14_E = 172,
	PPME_SYSCALL_EXECVE_14_X = 173,
	PPME_SYSCALL_RENAME_E = 174,
	PPME_SYSCALL_RENAME_X = 175,
	PPME_SYSCALL_RENAMEAT_E = 176,
	PPME_SYSCALL_RENAMEAT_X = 177,
	PPME_SYSCALL_SYMLINK_E = 178,
	PPME_SYSCALL_SYMLINK_X = 179,
	PPME_SYSCALL_SYMLINKAT_E = 180,
	PPME_SYSCALL_SYMLINKAT_X = 181,
	PPME_SYSCALL_FORK_E = 182,
	PPME_SYSCALL_FORK_X = 183,
	PPME_SYSCALL_VFORK_E = 184,
	PPME_SYSCALL_VFORK_X = 185,
	PPME_PROCEXIT_1_E = 186,
	PPME_PROCEXIT_1_X = 187,
	PPME_SYSCALL_SENDFILE_E = 188,
	PPME_SYSCALL_SENDFILE_X = 189,
	PPME_SYSCALL_QUOTACTL_E = 190,
	PPME_SYSCALL_QUOTACTL_X = 191,
	PPME_SYSCALL_SETRESUID_E = 192,
	PPME_SYSCALL_SETRESUID_X = 193,
	PPME_SYSCALL_SETRESGID_E = 194,
	PPME_SYSCALL_SETRESGID_X = 195,
	PPME_SYSDIGEVENT_E = 196,
	PPME_SYSDIGEVENT_X = 197,
	PPME_SYSCALL_SETUID_E = 198,
	PPME_SYSCALL_SETUID_X = 199,
	PPME_SYSCALL_SETGID_E = 200,
	PPME_SYSCALL_SETGID_X = 201,
	PPME_SYSCALL_GETUID_E = 202,
	PPME_SYSCALL_GETUID_X = 203,
	PPME_SYSCALL_GETEUID_E = 204,
	PPME_SYSCALL_GETEUID_X = 205,
	PPME_SYSCALL_GETGID_E = 206,
	PPME_SYSCALL_GETGID_X = 207,
	PPME_SYSCALL_GETEGID_E = 208,
	PPME_SYSCALL_GETEGID_X = 209,
	PPME_SYSCALL_GETRESUID_E = 210,
	PPME_SYSCALL_GETRESUID_X = 211,
	PPME_SYSCALL_GETRESGID_E = 212,
	PPME_SYSCALL_GETRESGID_X = 213,
	PPME_SYSCALL_EXECVE_15_E = 214,
	PPME_SYSCALL_EXECVE_15_X = 215,
	PPME_SYSCALL_CLONE_17_E = 216,
	PPME_SYSCALL_CLONE_17_X = 217,
	PPME_SYSCALL_FORK_17_E = 218,
	PPME_SYSCALL_FORK_17_X = 219,
	PPME_SYSCALL_VFORK_17_E = 220,
	PPME_SYSCALL_VFORK_17_X = 221,
	PPME_SYSCALL_CLONE_20_E = 222,
	PPME_SYSCALL_CLONE_20_X = 223,
	PPME_SYSCALL_FORK_20_E = 224,
	PPME_SYSCALL_FORK_20_X = 225,
	PPME_SYSCALL_VFORK_20_E = 226,
	PPME_SYSCALL_VFORK_20_X = 227,
	PPME_CONTAINER_E = 228,
	PPME_CONTAINER_X = 229,
	PPME_SYSCALL_EXECVE_16_E = 230,
	PPME_SYSCALL_EXECVE_16_X = 231,
	PPME_SIGNALDELIVER_E = 232,
	PPME_SIGNALDELIVER_X = 233,
	PPME_PROCINFO_E = 234,
	PPME_PROCINFO_X = 235,
	PPME_SYSCALL_GETDENTS_E = 236,
	PPME_SYSCALL_GETDENTS_X = 237,
	PPME_SYSCALL_GETDENTS64_E = 238,
	PPME_SYSCALL_GETDENTS64_X = 239,
	PPME_SYSCALL_SETNS_E = 240,
	PPME_SYSCALL_SETNS_X = 241,
	PPME_SYSCALL_FLOCK_E = 242,
	PPME_SYSCALL_FLOCK_X = 243,
	PPME_CPU_HOTPLUG_E = 244,
	PPME_CPU_HOTPLUG_X = 245,
	PPME_SOCKET_ACCEPT_5_E = 246,
	PPME_SOCKET_ACCEPT_5_X = 247,
	PPME_SOCKET_ACCEPT4_5_E = 248,
	PPME_SOCKET_ACCEPT4_5_X = 249,
	PPME_SYSCALL_SEMOP_E = 250,
	PPME_SYSCALL_SEMOP_X = 251,
	PPME_SYSCALL_SEMCTL_E = 252,
	PPME_SYSCALL_SEMCTL_X = 253,
	PPME_SYSCALL_PPOLL_E = 254,
	PPME_SYSCALL_PPOLL_X = 255,
	PPME_SYSCALL_MOUNT_E = 256,
	PPME_SYSCALL_MOUNT_X = 257,
	PPME_SYSCALL_UMOUNT_E = 258,
	PPME_SYSCALL_UMOUNT_X = 259,
	PPME_K8S_E = 260,
	PPME_K8S_X = 261,
	PPME_SYSCALL_SEMGET_E = 262,
	PPME_SYSCALL_SEMGET_X = 263,
	PPME_SYSCALL_ACCESS_E = 264,
	PPME_SYSCALL_ACCESS_X = 265,
	PPME_SYSCALL_CHROOT_E = 266,
	PPME_SYSCALL_CHROOT_X = 267,
	PPME_TRACER_E = 268,
	PPME_TRACER_X = 269,
	PPME_MESOS_E = 270,
	PPME_MESOS_X = 271,
	PPME_CONTAINER_JSON_E = 272,
	PPME_CONTAINER_JSON_X = 273,
	PPME_SYSCALL_SETSID_E = 274,
	PPME_SYSCALL_SETSID_X = 275,
	PPME_SYSCALL_MKDIR_2_E = 276,
	PPME_SYSCALL_MKDIR_2_X = 277,
	PPME_SYSCALL_RMDIR_2_E = 278,
	PPME_SYSCALL_RMDIR_2_X = 279,
	PPME_NOTIFICATION_E = 280,
	PPME_NOTIFICATION_X = 281,
	PPME_SYSCALL_EXECVE_17_E = 282,
	PPME_SYSCALL_EXECVE_17_X = 283,
	PPME_SYSCALL_UNSHARE_E = 284,
	PPME_SYSCALL_UNSHARE_X = 285,
	PPME_INFRASTRUCTURE_EVENT_E = 286,
	PPME_INFRASTRUCTURE_EVENT_X = 287,
	PPME_SYSCALL_EXECVE_18_E = 288,
	PPME_SYSCALL_EXECVE_18_X = 289,
	PPME_PAGE_FAULT_E = 290,
	PPME_PAGE_FAULT_X = 291,
	PPME_SYSCALL_EXECVE_19_E = 292,
	PPME_SYSCALL_EXECVE_19_X = 293,
	PPME_SYSCALL_SETPGID_E = 294,
	PPME_SYSCALL_SETPGID_X = 295,
	PPME_SYSCALL_BPF_E = 296,
	PPME_SYSCALL_BPF_X = 297,
	PPME_SYSCALL_SECCOMP_E = 298,
	PPME_SYSCALL_SECCOMP_X = 299,
	PPME_SYSCALL_UNLINK_2_E = 300,
	PPME_SYSCALL_UNLINK_2_X = 301,
	PPME_SYSCALL_UNLINKAT_2_E = 302,
	PPME_SYSCALL_UNLINKAT_2_X = 303,
	PPME_SYSCALL_MKDIRAT_E = 304,
	PPME_SYSCALL_MKDIRAT_X = 305,
	PPME_SYSCALL_OPENAT_2_E = 306,
	PPME_SYSCALL_OPENAT_2_X = 307,
	PPME_SYSCALL_LINK_2_E = 308,
	PPME_SYSCALL_LINK_2_X = 309,
	PPME_SYSCALL_LINKAT_2_E = 310,
	PPME_SYSCALL_LINKAT_2_X = 311,
	PPME_SYSCALL_FCHMODAT_E = 312,
	PPME_SYSCALL_FCHMODAT_X = 313,
	PPME_SYSCALL_CHMOD_E = 314,
	PPME_SYSCALL_CHMOD_X = 315,
	PPME_SYSCALL_FCHMOD_E = 316,
	PPME_SYSCALL_FCHMOD_X = 317,
	PPM_EVENT_MAX = 318
};

//
// syscall table map
//
enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
	UF_ALWAYS_DROP = (1 << 2),
	UF_SIMPLEDRIVER_KEEP = (1 << 3),
};

struct syscall_evt_pair {
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
} _packed;

const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_brk - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
	[__NR_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_EXECVE_19_E, PPME_SYSCALL_EXECVE_19_X},
	[__NR_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLONE_20_E, PPME_SYSCALL_CLONE_20_X},
	[__NR_fork - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FORK_20_E, PPME_SYSCALL_FORK_20_X},
	[__NR_vfork - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_VFORK_20_E, PPME_SYSCALL_VFORK_20_X},
	[__NR_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
	[__NR_stat - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
	[__NR_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
	[__NR_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
	[__NR_poll - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
#endif
	[__NR_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
	[__NR_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_IOCTL_3_E, PPME_SYSCALL_IOCTL_3_X},
	[__NR_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
	[__NR_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
	[__NR_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
	[__NR_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MKDIR_2_E, PPME_SYSCALL_MKDIR_2_X},
	[__NR_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_RMDIR_2_E, PPME_SYSCALL_RMDIR_2_X},
	[__NR_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X},
	[__NR_mkdirat - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_MKDIRAT_E, PPME_SYSCALL_MKDIRAT_X},
	[__NR_link - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_LINK_2_E, PPME_SYSCALL_LINK_2_X},
	[__NR_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_LINKAT_2_E, PPME_SYSCALL_LINKAT_2_X},
	[__NR_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_UNLINK_2_E, PPME_SYSCALL_UNLINK_2_X},
	[__NR_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_UNLINKAT_2_E, PPME_SYSCALL_UNLINKAT_2_X},
	[__NR_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
	[__NR_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
	[__NR_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
	[__NR_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
	[__NR_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
	[__NR_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
	[__NR_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
	[__NR_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
	[__NR_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
	[__NR_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_fchmodat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_FCHMODAT_E, PPME_SYSCALL_FCHMODAT_X},
	[__NR_fchmod - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_FCHMOD_E, PPME_SYSCALL_FCHMOD_X},
#ifdef __NR_getrlimit
	[__NR_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#endif
	[__NR_pselect6 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_uselib - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_syslog - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_CHMOD_E, PPME_SYSCALL_CHMOD_X},
	[__NR_lchown - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#ifdef __NR_utime
	[__NR_utime - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
	[__NR_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MOUNT_E, PPME_SYSCALL_MOUNT_X},
	[__NR_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_UMOUNT_E, PPME_SYSCALL_UMOUNT_X},
	[__NR_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PTRACE_E, PPME_SYSCALL_PTRACE_X},
#ifdef __NR_alarm
	[__NR_alarm - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
	[__NR_pause - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},

#ifndef __NR_socketcall
	[__NR_socket - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
	[__NR_bind - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
	[__NR_connect - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
	[__NR_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
	[__NR_accept - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT_5_E, PPME_SOCKET_ACCEPT_5_X},
	[__NR_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
	[__NR_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
	[__NR_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
	[__NR_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
	[__NR_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
	[__NR_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
	[__NR_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
	[__NR_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT4_5_E, PPME_SOCKET_ACCEPT4_5_X},
#endif

#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X},
#endif
#ifdef __NR_mmap
	[__NR_mmap - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP_E, PPME_SYSCALL_MMAP_X},
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP2_E, PPME_SYSCALL_MMAP2_X},
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MUNMAP_E, PPME_SYSCALL_MUNMAP_X},
	[__NR_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SPLICE_E, PPME_SYSCALL_SPLICE_X},
#ifdef __NR_process_vm_readv
	[__NR_process_vm_readv - SYSCALL_TABLE_ID0] =           {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_process_vm_writev
	[__NR_process_vm_writev - SYSCALL_TABLE_ID0] =          {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
	[__NR_rename - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_RENAME_E, PPME_SYSCALL_RENAME_X},
	[__NR_renameat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_RENAMEAT_E, PPME_SYSCALL_RENAMEAT_X},
	[__NR_symlink - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SYMLINK_E, PPME_SYSCALL_SYMLINK_X},
	[__NR_symlinkat - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SYMLINKAT_E, PPME_SYSCALL_SYMLINKAT_X},
	[__NR_sendfile - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#endif
#ifdef __NR_quotactl
	[__NR_quotactl - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_QUOTACTL_E, PPME_SYSCALL_QUOTACTL_X},
#endif
#ifdef __NR_setresuid
	[__NR_setresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresuid32
	[__NR_setresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresgid
	[__NR_setresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setresgid32
[__NR_setresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setuid
[__NR_setuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setuid32
[__NR_setuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setgid
[__NR_setgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_setgid32
[__NR_setgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_getuid
[__NR_getuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_getuid32
[__NR_getuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_geteuid
[__NR_geteuid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_geteuid32
[__NR_geteuid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_getgid
[__NR_getgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getgid32
[__NR_getgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getegid
[__NR_getegid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getegid32
[__NR_getegid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getresuid
[__NR_getresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresuid32
[__NR_getresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresgid
[__NR_getresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_getresgid32
[__NR_getresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
[__NR_getdents - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS_E, PPME_SYSCALL_GETDENTS_X},
[__NR_getdents64 - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS64_E, PPME_SYSCALL_GETDENTS64_X},
#ifdef __NR_setns
[__NR_setns - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_SETNS_E, PPME_SYSCALL_SETNS_X},
#endif
#ifdef __NR_unshare
[__NR_unshare - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_UNSHARE_E, PPME_SYSCALL_UNSHARE_X},
#endif
[__NR_flock - SYSCALL_TABLE_ID0] =			{UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FLOCK_E, PPME_SYSCALL_FLOCK_X},
#ifdef __NR_semop
[__NR_semop - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMOP_E, PPME_SYSCALL_SEMOP_X},
#endif
#ifdef __NR_semget
[__NR_semget - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMGET_E, PPME_SYSCALL_SEMGET_X},
#endif
#ifdef __NR_semctl
[__NR_semctl - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMCTL_E, PPME_SYSCALL_SEMCTL_X},
#endif
[__NR_ppoll - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_PPOLL_E, PPME_SYSCALL_PPOLL_X},
#ifdef __NR_access
[__NR_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_ACCESS_E, PPME_SYSCALL_ACCESS_X},
#endif
#ifdef __NR_chroot
[__NR_chroot - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHROOT_E, PPME_SYSCALL_CHROOT_X},
#endif
[__NR_setsid - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETSID_E, PPME_SYSCALL_SETSID_X},
[__NR_setpgid - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETPGID_E, PPME_SYSCALL_SETPGID_X},
#ifdef __NR_bpf
[__NR_bpf - SYSCALL_TABLE_ID0] =                        {UF_USED, PPME_SYSCALL_BPF_E, PPME_SYSCALL_BPF_X},
#endif
#ifdef __NR_seccomp
[__NR_seccomp - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SECCOMP_E, PPME_SYSCALL_SECCOMP_X},
#endif
};


//
// fillers table map
//

enum autofill_paramtype {
	APT_REG,
	APT_SOCK,
};

struct ppm_autofill_arg {
#define AF_ID_RETVAL -1
#define AF_ID_USEDEFAULT -2
	int16_t id;
	long default_val;
} _packed;

struct ppm_event_entry {
	enum ppm_filler_id filler_id;
	int n_autofill_args;
	enum autofill_paramtype paramtype;
	struct ppm_autofill_arg autofill_args[PPM_MAX_AUTOFILL_ARGS];
} _packed;

#define FILLER_REF(x) PPM_FILLER_##x

const struct ppm_event_entry g_ppm_events[PPM_EVENT_MAX] = {
	[PPME_SYSCALL_OPEN_X] = {FILLER_REF(sys_open_x)},
	[PPME_SYSCALL_OPENAT_2_X] = {FILLER_REF(sys_openat_x)},
	[PPME_SYSCALL_EXECVE_19_X] = {FILLER_REF(proc_startupdate)},
	[PPME_PROCEXIT_1_E] = {FILLER_REF(sys_procexit_e)},
	[PPME_SYSCALL_RENAME_X] = {FILLER_REF(sys_autofill), 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[PPME_SYSCALL_RENAMEAT_X] = {FILLER_REF(sys_renameat_x)},
	[PPME_SYSCALL_MKDIR_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_MKDIRAT_X] = {FILLER_REF(sys_mkdirat_x)},
	[PPME_SYSCALL_RMDIR_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_UNLINK_2_X] = {FILLER_REF(sys_autofill), 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_UNLINKAT_2_X] = {FILLER_REF(sys_unlinkat_x)},
	[PPME_SYSCALL_SYMLINK_X] = {FILLER_REF(sys_autofill), 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[PPME_SYSCALL_SYMLINKAT_X] = {FILLER_REF(sys_symlinkat_x)},
	[PPME_SYSCALL_CHMOD_X] = {FILLER_REF(sys_chmod_x)},
	[PPME_SYSCALL_FCHMOD_X] = {FILLER_REF(sys_fchmod_x)},
	[PPME_SYSCALL_FCHMODAT_X] = {FILLER_REF(sys_fchmodat_x)},
	[PPME_SOCKET_SOCKET_X] = {FILLER_REF(sys_socket_x), 3, APT_SOCK, {{0}, {1}, {2} } },
};


//
// event info table
//
#define PPM_MAX_EVENT_PARAMS (1 << 5)
#define PPM_MAX_PATH_SIZE 256
#define PPM_MAX_NAME_LEN 32

#define PPM_SOCKOPT_IDX_MAX 5
#define PPM_PTRACE_IDX_MAX 2
#define PPM_BPF_IDX_MAX 2


//
// Event information enums
//
enum ppm_event_category {
	EC_UNKNOWN = 0,	// unknown
	EC_OTHER = 1,	// No specific category
	EC_FILE = 2,	// File operation (open, close...) or file I/O
	EC_NET = 3,		// Network operation (socket, bind...) or network I/O
	EC_IPC = 4,		// IPC operation (pipe, futex...) or IPC I/O (e.g. on a pipe)
	EC_MEMORY = 5,	// Memory-related operation (e.g. brk)
	EC_PROCESS = 6,	// Process-related operation (fork, clone...)
	EC_SLEEP = 7,	// Plain sleep
	EC_SYSTEM = 8,	// System-related operations (e.g. reboot)
	EC_SIGNAL = 9,	// Signal-related operations (e.g. signal)
	EC_USER = 10,	// User-related operations (e.g. getuid)
	EC_TIME = 11,	// Time-related syscalls (e.g. gettimeofday)
	EC_PROCESSING = 12,	// User level processing. Never used for system calls
	EC_IO_BASE = 32, // used for masking
	EC_IO_READ = 32,// General I/O read (can be file, socket, IPC...)
	EC_IO_WRITE = 33,// General I/O write (can be file, socket, IPC...)
	EC_IO_OTHER = 34,// General I/O that is neither read not write (can be file, socket, IPC...)
	EC_WAIT = 64,	// General wait (can be file, socket, IPC...)
	EC_SCHEDULER = 128,	// Scheduler event (e.g. context switch)
	EC_INTERNAL = 256,	// Internal event that shouldn't be shown to the user
};

enum ppm_event_flags {
	EF_NONE = 0,
	EF_CREATES_FD = (1 << 0), // This event creates an FD (e.g. open)
	EF_DESTROYS_FD = (1 << 1), // This event destroys an FD (e.g. close)
	EF_USES_FD = (1 << 2), // This event operates on an FD.
	EF_READS_FROM_FD = (1 << 3), // This event reads data from an FD.
	EF_WRITES_TO_FD = (1 << 4), // This event writes data to an FD.
	EF_MODIFIES_STATE = (1 << 5), // This event causes the machine state to change and should not be dropped by the filtering engine.
	EF_UNUSED = (1 << 6), // This event is not used
	EF_WAITS = (1 << 7), // This event reads data from an FD.
	EF_SKIPPARSERESET = (1 << 8), // This event shouldn't pollute the parser lastevent state tracker.
	EF_OLD_VERSION = (1 << 9), // This event is kept for backward compatibility
	EF_DROP_FALCO = (1 << 10) // This event should not be passed up to Falco
};
//
// types of event parameters
//
enum ppm_param_type {
	PT_NONE = 0,
	PT_INT8 = 1,
	PT_INT16 = 2,
	PT_INT32 = 3,
	PT_INT64 = 4,
	PT_UINT8 = 5,
	PT_UINT16 = 6,
	PT_UINT32 = 7,
	PT_UINT64 = 8,
	PT_CHARBUF = 9,	// A printable buffer of bytes, NULL terminated //
	PT_BYTEBUF = 10, // A raw buffer of bytes not suitable for printing //
	PT_ERRNO = 11,	// this is an INT64, but will be interpreted as an error code //
	PT_SOCKADDR = 12, // A sockaddr structure, 1byte family + data //
	PT_SOCKTUPLE = 13, // A sockaddr tuple,1byte family + 12byte data + 12byte data //
	PT_FD = 14, // An fd, 64bit //
	PT_PID = 15, // A pid/tid, 64bit //
	PT_FDLIST = 16, // A list of fds, 16bit count + count * (64bit fd + 16bit flags) //
	PT_FSPATH = 17,	// A string containing a relative or absolute file system path, null terminated //
	PT_SYSCALLID = 18, // A 16bit system call ID. Can be used as a key for the g_syscall_info_table table. //
	PT_SIGTYPE = 19, // An 8bit signal number //
	PT_RELTIME = 20, // A relative time. Seconds * 10^9  + nanoseconds. 64bit. //
	PT_ABSTIME = 21, // An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit. //
	PT_PORT = 22, // A TCP/UDP prt. 2 bytes. //
	PT_L4PROTO = 23, // A 1 byte IP protocol type. //
	PT_SOCKFAMILY = 24, // A 1 byte socket family. //
	PT_BOOL = 25, // A boolean value, 4 bytes. //
	PT_IPV4ADDR = 26, // A 4 byte raw IPv4 address. //
	PT_DYN = 27, // Type can vary depending on the context. Used for filter fields like evt.rawarg. //
	PT_FLAGS8 = 28, // this is an UINT8, but will be interpreted as 8 bit flags. //
	PT_FLAGS16 = 29, // this is an UINT16, but will be interpreted as 16 bit flags. //
	PT_FLAGS32 = 30, // this is an UINT32, but will be interpreted as 32 bit flags. //
	PT_UID = 31, // this is an UINT32, MAX_UINT32 will be interpreted as no value. //
	PT_GID = 32, // this is an UINT32, MAX_UINT32 will be interpreted as no value. //
	PT_DOUBLE = 33, // this is a double precision floating point number. //
	PT_SIGSET = 34, // sigset_t. I only store the lower UINT32 of it //
	PT_CHARBUFARRAY = 35,	// Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only. //
	PT_CHARBUF_PAIR_ARRAY = 36,	// Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only. //
	PT_IPV4NET = 37, // An IPv4 network. //
	PT_IPV6ADDR = 38, // A 16 byte raw IPv6 address. //
	PT_IPV6NET = 39, // An IPv6 network. //
	PT_IPADDR = 40,  // Either an IPv4 or IPv6 address. The length indicates which one it is. //
	PT_IPNET = 41,  // Either an IPv4 or IPv6 network. The length indicates which one it is. //
	PT_MODE = 42, // a 32 bit bitmask to represent file modes. //
	PT_MAX = 43 //ray size //
};

enum ppm_print_format {
	PF_NA = 0,
	PF_DEC = 1,	// decimal //
	PF_HEX = 2,	// hexadecimal //
	PF_10_PADDED_DEC = 3, // decimal padded to 10 digits, useful to print the fractional part of a ns timestamp //
	PF_ID = 4,
	PF_DIR = 5,
	PF_OCT = 6,	// octal //
};
//
// brief Name-value pair, used to store flags information.
//
struct ppm_name_value {
	const char *name;
	uint32_t value;
};

//
// brief Event parameter information.
//
struct ppm_param_info {
	char name[PPM_MAX_NAME_LEN];
	enum ppm_param_type type;
	enum ppm_print_format fmt;
	const void *info;
	uint8_t ninfo;
} _packed;

extern const struct ppm_name_value socket_families[];
extern const struct ppm_name_value file_flags[];
extern const struct ppm_name_value flock_flags[];
extern const struct ppm_name_value clone_flags[];
extern const struct ppm_name_value futex_operations[];
extern const struct ppm_name_value lseek_whence[];
extern const struct ppm_name_value poll_flags[];
extern const struct ppm_name_value mount_flags[];
extern const struct ppm_name_value umount_flags[];
extern const struct ppm_name_value shutdown_how[];
extern const struct ppm_name_value rlimit_resources[];
extern const struct ppm_name_value fcntl_commands[];
extern const struct ppm_name_value sockopt_levels[];
extern const struct ppm_name_value sockopt_options[];
extern const struct ppm_name_value ptrace_requests[];
extern const struct ppm_name_value prot_flags[];
extern const struct ppm_name_value mmap_flags[];
extern const struct ppm_name_value splice_flags[];
extern const struct ppm_name_value quotactl_cmds[];
extern const struct ppm_name_value quotactl_types[];
extern const struct ppm_name_value quotactl_dqi_flags[];
extern const struct ppm_name_value quotactl_quota_fmts[];
extern const struct ppm_name_value semop_flags[];
extern const struct ppm_name_value semget_flags[];
extern const struct ppm_name_value semctl_commands[];
extern const struct ppm_name_value access_flags[];
extern const struct ppm_name_value pf_flags[];
extern const struct ppm_name_value unlinkat_flags[];
extern const struct ppm_name_value linkat_flags[];
extern const struct ppm_name_value chmod_mode[];

extern const struct ppm_param_info sockopt_dynamic_param[];
extern const struct ppm_param_info ptrace_dynamic_param[];
extern const struct ppm_param_info bpf_dynamic_param[];

//
//Socket families
//
#define PPM_AF_UNSPEC       0
#define PPM_AF_UNIX         1
#define PPM_AF_LOCAL        1
#define PPM_AF_INET         2
#define PPM_AF_AX25         3
#define PPM_AF_IPX          4
#define PPM_AF_APPLETALK    5
#define PPM_AF_NETROM       6
#define PPM_AF_BRIDGE       7
#define PPM_AF_ATMPVC       8
#define PPM_AF_X25          9
#define PPM_AF_INET6        10
#define PPM_AF_ROSE         11
#define PPM_AF_DECnet       12
#define PPM_AF_NETBEUI      13
#define PPM_AF_SECURITY     14
#define PPM_AF_KEY          15
#define PPM_AF_NETLINK      16
#define PPM_AF_ROUTE        PPM_AF_NETLINK
#define PPM_AF_PACKET       17
#define PPM_AF_ASH          18
#define PPM_AF_ECONET       19
#define PPM_AF_ATMSVC       20
#define PPM_AF_RDS          21
#define PPM_AF_SNA          22
#define PPM_AF_IRDA         23
#define PPM_AF_PPPOX        24
#define PPM_AF_WANPIPE      25
#define PPM_AF_LLC          26
#define PPM_AF_CAN          29
#define PPM_AF_TIPC         30
#define PPM_AF_BLUETOOTH    31
#define PPM_AF_IUCV         32
#define PPM_AF_RXRPC        33
#define PPM_AF_ISDN         34
#define PPM_AF_PHONET       35
#define PPM_AF_IEEE802154   36
#define PPM_AF_CAIF         37
#define PPM_AF_ALG          38
#define PPM_AF_NFC          39

//
//File flags
//
#define PPM_O_NONE	0
#define PPM_O_RDONLY	(1 << 0)
#define PPM_O_WRONLY	(1 << 1)
#define PPM_O_RDWR	(PPM_O_RDONLY | PPM_O_WRONLY)
#define PPM_O_CREAT	(1 << 2)
#define PPM_O_APPEND	(1 << 3)
#define PPM_O_DSYNC	(1 << 4)
#define PPM_O_EXCL	(1 << 5)
#define PPM_O_NONBLOCK	(1 << 6)
#define PPM_O_SYNC	(1 << 7)
#define PPM_O_TRUNC	(1 << 8)
#define PPM_O_DIRECT	(1 << 9)
#define PPM_O_DIRECTORY (1 << 10)
#define PPM_O_LARGEFILE (1 << 11)
#define PPM_O_CLOEXEC	(1 << 12)

//
//File modes
//
#define PPM_S_NONE  0
#define PPM_S_IXOTH (1 << 0)
#define PPM_S_IWOTH (1 << 1)
#define PPM_S_IROTH (1 << 2)
#define PPM_S_IXGRP (1 << 3)
#define PPM_S_IWGRP (1 << 4)
#define PPM_S_IRGRP (1 << 5)
#define PPM_S_IXUSR (1 << 6)
#define PPM_S_IWUSR (1 << 7)
#define PPM_S_IRUSR (1 << 8)
#define PPM_S_ISVTX (1 << 9)
#define PPM_S_ISGID (1 << 10)
#define PPM_S_ISUID (1 << 11)

//flock() flags
#define PPM_LOCK_NONE 0
#define PPM_LOCK_SH (1 << 0)
#define PPM_LOCK_EX (1 << 1)
#define PPM_LOCK_NB (1 << 2)
#define PPM_LOCK_UN (1 << 3)

//Clone flags
#define PPM_CL_NONE 0
#define PPM_CL_CLONE_FILES (1 << 0)
#define PPM_CL_CLONE_FS (1 << 1)
#define PPM_CL_CLONE_IO (1 << 2)
#define PPM_CL_CLONE_NEWIPC (1 << 3)
#define PPM_CL_CLONE_NEWNET (1 << 4)
#define PPM_CL_CLONE_NEWNS (1 << 5)
#define PPM_CL_CLONE_NEWPID (1 << 6)
#define PPM_CL_CLONE_NEWUTS (1 << 7)
#define PPM_CL_CLONE_PARENT (1 << 8)
#define PPM_CL_CLONE_PARENT_SETTID (1 << 9)
#define PPM_CL_CLONE_PTRACE (1 << 10)
#define PPM_CL_CLONE_SIGHAND (1 << 11)
#define PPM_CL_CLONE_SYSVSEM (1 << 12)
#define PPM_CL_CLONE_THREAD (1 << 13)
#define PPM_CL_CLONE_UNTRACED (1 << 14)
#define PPM_CL_CLONE_VM (1 << 15)
#define PPM_CL_CLONE_INVERTED (1 << 16)
#define PPM_CL_NAME_CHANGED (1 << 17)
#define PPM_CL_CLOSED (1 << 18)
#define PPM_CL_ACTIVE (1 << 19)
#define PPM_CL_CLONE_NEWUSER (1 << 20)
#define PPM_CL_PIPE_SRC (1 << 21)
#define PPM_CL_PIPE_DST (1 << 22)
#define PPM_CL_CLONE_CHILD_CLEARTID (1 << 23)
#define PPM_CL_CLONE_CHILD_SETTID (1 << 24)
#define PPM_CL_CLONE_SETTLS (1 << 25)
#define PPM_CL_CLONE_STOPPED (1 << 26)
#define PPM_CL_CLONE_VFORK (1 << 27)
#define PPM_CL_CLONE_NEWCGROUP (1 << 28)
#define PPM_CL_CHILD_IN_PIDNS (1<<29)

//Futex Operations
#define PPM_FU_FUTEX_WAIT 0
#define PPM_FU_FUTEX_WAKE 1
#define PPM_FU_FUTEX_FD 2
#define PPM_FU_FUTEX_REQUEUE 3
#define PPM_FU_FUTEX_CMP_REQUEUE 4
#define PPM_FU_FUTEX_WAKE_OP 5
#define PPM_FU_FUTEX_LOCK_PI 6
#define PPM_FU_FUTEX_UNLOCK_PI 7
#define PPM_FU_FUTEX_TRYLOCK_PI 8
#define PPM_FU_FUTEX_WAIT_BITSET 9
#define PPM_FU_FUTEX_WAKE_BITSET 10
#define PPM_FU_FUTEX_WAIT_REQUEUE_PI 11
#define PPM_FU_FUTEX_CMP_REQUEUE_PI 12
#define PPM_FU_FUTEX_PRIVATE_FLAG	128
#define PPM_FU_FUTEX_CLOCK_REALTIME 256

//lseek() and llseek() whence
#define PPM_SEEK_SET 0
#define PPM_SEEK_CUR 1
#define PPM_SEEK_END 2

//poll() flags
#define PPM_POLLIN (1 << 0)
#define PPM_POLLPRI (1 << 1)
#define PPM_POLLOUT (1 << 2)
#define PPM_POLLRDHUP (1 << 3)
#define PPM_POLLERR (1 << 4)
#define PPM_POLLHUP (1 << 5)
#define PPM_POLLNVAL (1 << 6)
#define PPM_POLLRDNORM (1 << 7)
#define PPM_POLLRDBAND (1 << 8)
#define PPM_POLLWRNORM (1 << 9)
#define PPM_POLLWRBAND (1 << 10)

//mount() flags
#define PPM_MS_RDONLY       (1<<0)
#define PPM_MS_NOSUID       (1<<1)
#define PPM_MS_NODEV        (1<<2)
#define PPM_MS_NOEXEC       (1<<3)
#define PPM_MS_SYNCHRONOUS  (1<<4)
#define PPM_MS_REMOUNT      (1<<5)
#define PPM_MS_MANDLOCK     (1<<6)
#define PPM_MS_DIRSYNC      (1<<7)

#define PPM_MS_NOATIME      (1<<10)
#define PPM_MS_NODIRATIME   (1<<11)
#define PPM_MS_BIND         (1<<12)
#define PPM_MS_MOVE         (1<<13)
#define PPM_MS_REC          (1<<14)
#define PPM_MS_SILENT       (1<<15)
#define PPM_MS_POSIXACL     (1<<16)
#define PPM_MS_UNBINDABLE   (1<<17)
#define PPM_MS_PRIVATE      (1<<18)
#define PPM_MS_SLAVE        (1<<19)
#define PPM_MS_SHARED       (1<<20)
#define PPM_MS_RELATIME     (1<<21)
#define PPM_MS_KERNMOUNT    (1<<22)
#define PPM_MS_I_VERSION    (1<<23)
#define PPM_MS_STRICTATIME  (1<<24)
#define PPM_MS_LAZYTIME     (1<<25)

#define PPM_MS_NOSEC        (1<<28)
#define PPM_MS_BORN         (1<<29)
#define PPM_MS_ACTIVE       (1<<30)
#define PPM_MS_NOUSER       (1<<31)

//umount() flags
#define PPM_MNT_FORCE       1
#define PPM_MNT_DETACH      2
#define PPM_MNT_EXPIRE      4
#define PPM_UMOUNT_NOFOLLOW 8

//shutdown() how
#define PPM_SHUT_RD 0
#define PPM_SHUT_WR 1
#define PPM_SHUT_RDWR 2

//fs *at() flags
#define PPM_AT_FDCWD -100

//unlinkat() flags
#define PPM_AT_REMOVEDIR 0x200

//linkat() flags
#define PPM_AT_SYMLINK_FOLLOW	0x400
#define PPM_AT_EMPTY_PATH       0x1000

//rlimit resources
#define PPM_RLIMIT_CPU 0
#define PPM_RLIMIT_FSIZE 1
#define PPM_RLIMIT_DATA 2
#define PPM_RLIMIT_STACK 3
#define PPM_RLIMIT_CORE 4
#define PPM_RLIMIT_RSS 5
#define PPM_RLIMIT_NPROC 6
#define PPM_RLIMIT_NOFILE 7
#define PPM_RLIMIT_MEMLOCK 8
#define PPM_RLIMIT_AS 9
#define PPM_RLIMIT_LOCKS 10
#define PPM_RLIMIT_SIGPENDING 11
#define PPM_RLIMIT_MSGQUEUE 12
#define PPM_RLIMIT_NICE 13
#define PPM_RLIMIT_RTPRIO 14
#define PPM_RLIMIT_RTTIME 15
#define PPM_RLIMIT_UNKNOWN 255

 //fcntl commands
#define PPM_FCNTL_UNKNOWN 0
#define PPM_FCNTL_F_DUPFD 1
#define PPM_FCNTL_F_GETFD 2
#define PPM_FCNTL_F_SETFD 3
#define PPM_FCNTL_F_GETFL 4
#define PPM_FCNTL_F_SETFL 5
#define PPM_FCNTL_F_GETLK 6
#define PPM_FCNTL_F_SETLK 8
#define PPM_FCNTL_F_SETLKW 9
#define PPM_FCNTL_F_SETOWN 10
#define PPM_FCNTL_F_GETOWN 12
#define PPM_FCNTL_F_SETSIG 13
#define PPM_FCNTL_F_GETSIG 15
#ifndef CONFIG_64BIT
#define PPM_FCNTL_F_GETLK64 17
#define PPM_FCNTL_F_SETLK64 18
#define PPM_FCNTL_F_SETLKW64 19
#endif
#define PPM_FCNTL_F_SETOWN_EX 21
#define PPM_FCNTL_F_GETOWN_EX 22
#define PPM_FCNTL_F_SETLEASE 23
#define PPM_FCNTL_F_GETLEASE 24
#define PPM_FCNTL_F_CANCELLK 25
#define PPM_FCNTL_F_DUPFD_CLOEXEC 26
#define PPM_FCNTL_F_NOTIFY 27
#define PPM_FCNTL_F_SETPIPE_SZ 28
#define PPM_FCNTL_F_GETPIPE_SZ 29
#define PPM_FCNTL_F_OFD_GETLK 30
#define PPM_FCNTL_F_OFD_SETLK 31
#define PPM_FCNTL_F_OFD_SETLKW 32

 //getsockopt/setsockopt levels
#define PPM_SOCKOPT_LEVEL_UNKNOWN 0
#define PPM_SOCKOPT_LEVEL_SOL_SOCKET 1
#define PPM_SOCKOPT_LEVEL_SOL_TCP 2

 //getsockopt/setsockopt options
 //SOL_SOCKET only currently
#define PPM_SOCKOPT_UNKNOWN	0
#define PPM_SOCKOPT_SO_DEBUG	1
#define PPM_SOCKOPT_SO_REUSEADDR	2
#define PPM_SOCKOPT_SO_TYPE		3
#define PPM_SOCKOPT_SO_ERROR	4
#define PPM_SOCKOPT_SO_DONTROUTE	5
#define PPM_SOCKOPT_SO_BROADCAST	6
#define PPM_SOCKOPT_SO_SNDBUF	7
#define PPM_SOCKOPT_SO_RCVBUF	8
#define PPM_SOCKOPT_SO_SNDBUFFORCE	32
#define PPM_SOCKOPT_SO_RCVBUFFORCE	33
#define PPM_SOCKOPT_SO_KEEPALIVE	9
#define PPM_SOCKOPT_SO_OOBINLINE	10
#define PPM_SOCKOPT_SO_NO_CHECK	11
#define PPM_SOCKOPT_SO_PRIORITY	12
#define PPM_SOCKOPT_SO_LINGER	13
#define PPM_SOCKOPT_SO_BSDCOMPAT	14
#define PPM_SOCKOPT_SO_REUSEPORT	15
#define PPM_SOCKOPT_SO_PASSCRED	16
#define PPM_SOCKOPT_SO_PEERCRED	17
#define PPM_SOCKOPT_SO_RCVLOWAT	18
#define PPM_SOCKOPT_SO_SNDLOWAT	19
#define PPM_SOCKOPT_SO_RCVTIMEO	20
#define PPM_SOCKOPT_SO_SNDTIMEO	21
#define PPM_SOCKOPT_SO_SECURITY_AUTHENTICATION		22
#define PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK		24
#define PPM_SOCKOPT_SO_BINDTODEVICE	25
#define PPM_SOCKOPT_SO_ATTACH_FILTER	26
#define PPM_SOCKOPT_SO_DETACH_FILTER	27
#define PPM_SOCKOPT_SO_PEERNAME		28
#define PPM_SOCKOPT_SO_TIMESTAMP		29
#define PPM_SOCKOPT_SO_ACCEPTCONN		30
#define PPM_SOCKOPT_SO_PEERSEC		31
#define PPM_SOCKOPT_SO_PASSSEC		34
#define PPM_SOCKOPT_SO_TIMESTAMPNS		35
#define PPM_SOCKOPT_SO_MARK			36
#define PPM_SOCKOPT_SO_TIMESTAMPING		37
#define PPM_SOCKOPT_SO_PROTOCOL		38
#define PPM_SOCKOPT_SO_DOMAIN		39
#define PPM_SOCKOPT_SO_RXQ_OVFL             40
#define PPM_SOCKOPT_SO_WIFI_STATUS		41
#define PPM_SOCKOPT_SO_PEEK_OFF		42
#define PPM_SOCKOPT_SO_NOFCS		43
#define PPM_SOCKOPT_SO_LOCK_FILTER		44
#define PPM_SOCKOPT_SO_SELECT_ERR_QUEUE	45
#define PPM_SOCKOPT_SO_BUSY_POLL		46
#define PPM_SOCKOPT_SO_MAX_PACING_RATE	47
#define PPM_SOCKOPT_SO_BPF_EXTENSIONS	48
#define PPM_SOCKOPT_SO_INCOMING_CPU		49
#define PPM_SOCKOPT_SO_ATTACH_BPF		50
#define PPM_SOCKOPT_SO_PEERGROUPS		51
#define PPM_SOCKOPT_SO_MEMINFO		52
#define PPM_SOCKOPT_SO_COOKIE		53

 //getsockopt/setsockopt dynamic params
#define PPM_SOCKOPT_IDX_UNKNOWN 0
#define PPM_SOCKOPT_IDX_ERRNO 1
#define PPM_SOCKOPT_IDX_UINT32 2
#define PPM_SOCKOPT_IDX_UINT64 3
#define PPM_SOCKOPT_IDX_TIMEVAL 4
#define PPM_SOCKOPT_IDX_MAX 5

 //ptrace requests
#define PPM_PTRACE_UNKNOWN 0
#define PPM_PTRACE_TRACEME 1
#define PPM_PTRACE_PEEKTEXT 2
#define PPM_PTRACE_PEEKDATA 3
#define PPM_PTRACE_PEEKUSR 4
#define PPM_PTRACE_POKETEXT 5
#define PPM_PTRACE_POKEDATA 6
#define PPM_PTRACE_POKEUSR 7
#define PPM_PTRACE_CONT 8
#define PPM_PTRACE_KILL 9
#define PPM_PTRACE_SINGLESTEP 10
#define PPM_PTRACE_ATTACH 11
#define PPM_PTRACE_DETACH 12
#define PPM_PTRACE_SYSCALL 13
#define PPM_PTRACE_SETOPTIONS 14
#define PPM_PTRACE_GETEVENTMSG 15
#define PPM_PTRACE_GETSIGINFO 16
#define PPM_PTRACE_SETSIGINFO 17
#define PPM_PTRACE_GETREGSET 18
#define PPM_PTRACE_SETREGSET 19
#define PPM_PTRACE_SEIZE 20
#define PPM_PTRACE_INTERRUPT 21
#define PPM_PTRACE_LISTEN 22
#define PPM_PTRACE_PEEKSIGINFO 23
#define PPM_PTRACE_GETSIGMASK 24
#define PPM_PTRACE_SETSIGMASK 25
#define PPM_PTRACE_GETREGS 26
#define PPM_PTRACE_SETREGS 27
#define PPM_PTRACE_GETFPREGS 28
#define PPM_PTRACE_SETFPREGS 29
#define PPM_PTRACE_GETFPXREGS 30
#define PPM_PTRACE_SETFPXREGS 31
#define PPM_PTRACE_OLDSETOPTIONS 32
#define PPM_PTRACE_GET_THREAD_AREA 33
#define PPM_PTRACE_SET_THREAD_AREA 34
#define PPM_PTRACE_ARCH_PRCTL 35
#define PPM_PTRACE_SYSEMU 36
#define PPM_PTRACE_SYSEMU_SINGLESTEP 37
#define PPM_PTRACE_SINGLEBLOCK 38

 //ptrace dynamic table indexes
#define PPM_PTRACE_IDX_UINT64 0
#define PPM_PTRACE_IDX_SIGTYPE 1

#define PPM_PTRACE_IDX_MAX 2

#define PPM_BPF_IDX_FD 0
#define PPM_BPF_IDX_RES 1

#define PPM_BPF_IDX_MAX 2

 //memory protection flags
#define PPM_PROT_NONE		0
#define PPM_PROT_READ		(1 << 0)
#define PPM_PROT_WRITE		(1 << 1)
#define PPM_PROT_EXEC		(1 << 2)
#define PPM_PROT_SEM		(1 << 3)
#define PPM_PROT_GROWSDOWN	(1 << 4)
#define PPM_PROT_GROWSUP	(1 << 5)
#define PPM_PROT_SAO		(1 << 6)

 //mmap flags
#define PPM_MAP_SHARED		(1 << 0)
#define PPM_MAP_PRIVATE		(1 << 1)
#define PPM_MAP_FIXED		(1 << 2)
#define PPM_MAP_ANONYMOUS	(1 << 3)
#define PPM_MAP_32BIT		(1 << 4)
#define PPM_MAP_RENAME		(1 << 5)
#define PPM_MAP_NORESERVE	(1 << 6)
#define PPM_MAP_POPULATE	(1 << 7)
#define PPM_MAP_NONBLOCK	(1 << 8)
#define PPM_MAP_GROWSDOWN	(1 << 9)
#define PPM_MAP_DENYWRITE	(1 << 10)
#define PPM_MAP_EXECUTABLE	(1 << 11)
#define PPM_MAP_INHERIT		(1 << 12)
#define PPM_MAP_FILE		(1 << 13)
#define PPM_MAP_LOCKED		(1 << 14)

 //splice flags
#define PPM_SPLICE_F_MOVE		(1 << 0)
#define PPM_SPLICE_F_NONBLOCK	(1 << 1)
#define PPM_SPLICE_F_MORE		(1 << 2)
#define PPM_SPLICE_F_GIFT		(1 << 3)

 //quotactl cmds
#define PPM_Q_QUOTAON		(1 << 0)
#define PPM_Q_QUOTAOFF		(1 << 1)
#define PPM_Q_GETFMT		(1 << 2)
#define PPM_Q_GETINFO		(1 << 3)
#define PPM_Q_SETINFO		(1 << 4)
#define PPM_Q_GETQUOTA		(1 << 5)
#define PPM_Q_SETQUOTA		(1 << 6)
#define PPM_Q_SYNC			(1 << 7)
#define PPM_Q_XQUOTAON		(1 << 8)
#define PPM_Q_XQUOTAOFF		(1 << 9)
#define PPM_Q_XGETQUOTA		(1 << 10)
#define PPM_Q_XSETQLIM		(1 << 11)
#define PPM_Q_XGETQSTAT		(1 << 12)
#define PPM_Q_XQUOTARM		(1 << 13)
#define PPM_Q_XQUOTASYNC	(1 << 14)
#define PPM_Q_XGETQSTATV	(1 << 15)

 //quotactl types
#define PPM_USRQUOTA		(1 << 0)
#define PPM_GRPQUOTA		(1 << 1)

 //quotactl dqi_flags
#define PPM_DQF_NONE		(1 << 0)
#define PPM_V1_DQF_RSQUASH	(1 << 1)

 //quotactl quotafmts
#define PPM_QFMT_NOT_USED		(1 << 0)
#define PPM_QFMT_VFS_OLD	(1 << 1)
#define PPM_QFMT_VFS_V0		(1 << 2)
#define PPM_QFMT_VFS_V1		(1 << 3)

//Semop flags
#define PPM_IPC_NOWAIT		(1 << 0)
#define PPM_SEM_UNDO		(1 << 1)

 //Semget flags
#define PPM_IPC_CREAT  (1 << 13)
#define PPM_IPC_EXCL   (1 << 14)

#define PPM_IPC_STAT		(1 << 0)
#define PPM_IPC_SET		(1 << 1)
#define PPM_IPC_RMID		(1 << 2)
#define PPM_IPC_INFO		(1 << 3)
#define PPM_SEM_INFO		(1 << 4)
#define PPM_SEM_STAT		(1 << 5)
#define PPM_GETALL		(1 << 6)
#define PPM_GETNCNT		(1 << 7)
#define PPM_GETPID		(1 << 8)
#define PPM_GETVAL		(1 << 9)
#define PPM_GETZCNT		(1 << 10)
#define PPM_SETALL		(1 << 11)
#define PPM_SETVAL		(1 << 12)

 //Access flags
#define PPM_F_OK            (0)
#define PPM_X_OK            (1 << 0)
#define PPM_W_OK            (1 << 1)
#define PPM_R_OK            (1 << 2)

#define PPM_PF_PROTECTION_VIOLATION	(1 << 0)
#define PPM_PF_PAGE_NOT_PRESENT		(1 << 1)
#define PPM_PF_WRITE_ACCESS		(1 << 2)
#define PPM_PF_READ_ACCESS		(1 << 3)
#define PPM_PF_USER_FAULT		(1 << 4)
#define PPM_PF_SUPERVISOR_FAULT		(1 << 5)
#define PPM_PF_RESERVED_PAGE		(1 << 6)
#define PPM_PF_INSTRUCTION_FETCH	(1 << 7)

#ifndef RLIM_INFINITY
# define RLIM_INFINITY          (~0UL)
#endif

#ifndef _STK_LIM_MAX
# define _STK_LIM_MAX           RLIM_INFINITY
#endif

#define PPME_DIRECTION_FLAG 1
#define PPME_IS_ENTER(x) ((x & PPME_DIRECTION_FLAG) == 0)
#define PPME_IS_EXIT(x) (x & PPME_DIRECTION_FLAG)
#define PPME_MAKE_ENTER(x) (x & (~1))


const struct ppm_name_value socket_families[] = {
	{"AF_NFC", PPM_AF_NFC},
	{"AF_ALG", PPM_AF_ALG},
	{"AF_CAIF", PPM_AF_CAIF},
	{"AF_IEEE802154", PPM_AF_IEEE802154},
	{"AF_PHONET", PPM_AF_PHONET},
	{"AF_ISDN", PPM_AF_ISDN},
	{"AF_RXRPC", PPM_AF_RXRPC},
	{"AF_IUCV", PPM_AF_IUCV},
	{"AF_BLUETOOTH", PPM_AF_BLUETOOTH},
	{"AF_TIPC", PPM_AF_TIPC},
	{"AF_CAN", PPM_AF_CAN},
	{"AF_LLC", PPM_AF_LLC},
	{"AF_WANPIPE", PPM_AF_WANPIPE},
	{"AF_PPPOX", PPM_AF_PPPOX},
	{"AF_IRDA", PPM_AF_IRDA},
	{"AF_SNA", PPM_AF_SNA},
	{"AF_RDS", PPM_AF_RDS},
	{"AF_ATMSVC", PPM_AF_ATMSVC},
	{"AF_ECONET", PPM_AF_ECONET},
	{"AF_ASH", PPM_AF_ASH},
	{"AF_PACKET", PPM_AF_PACKET},
	{"AF_ROUTE", PPM_AF_ROUTE},
	{"AF_NETLINK", PPM_AF_NETLINK},
	{"AF_KEY", PPM_AF_KEY},
	{"AF_SECURITY", PPM_AF_SECURITY},
	{"AF_NETBEUI", PPM_AF_NETBEUI},
	{"AF_DECnet", PPM_AF_DECnet},
	{"AF_ROSE", PPM_AF_ROSE},
	{"AF_INET6", PPM_AF_INET6},
	{"AF_X25", PPM_AF_X25},
	{"AF_ATMPVC", PPM_AF_ATMPVC},
	{"AF_BRIDGE", PPM_AF_BRIDGE},
	{"AF_NETROM", PPM_AF_NETROM},
	{"AF_APPLETALK", PPM_AF_APPLETALK},
	{"AF_IPX", PPM_AF_IPX},
	{"AF_AX25", PPM_AF_AX25},
	{"AF_INET", PPM_AF_INET},
	{"AF_LOCAL", PPM_AF_LOCAL},
	{"AF_UNIX", PPM_AF_UNIX},
	{"AF_UNSPEC", PPM_AF_UNSPEC},
	{0, 0},
};

const struct ppm_name_value file_flags[] = {
	{"O_LARGEFILE", PPM_O_LARGEFILE},
	{"O_DIRECTORY", PPM_O_DIRECTORY},
	{"O_DIRECT", PPM_O_DIRECT},
	{"O_TRUNC", PPM_O_TRUNC},
	{"O_SYNC", PPM_O_SYNC},
	{"O_NONBLOCK", PPM_O_NONBLOCK},
	{"O_EXCL", PPM_O_EXCL},
	{"O_DSYNC", PPM_O_DSYNC},
	{"O_APPEND", PPM_O_APPEND},
	{"O_CREAT", PPM_O_CREAT},
	{"O_RDWR", PPM_O_RDWR},
	{"O_WRONLY", PPM_O_WRONLY},
	{"O_RDONLY", PPM_O_RDONLY},
	{"O_CLOEXEC", PPM_O_CLOEXEC},
	{"O_NONE", PPM_O_NONE},
	{0, 0},
};

const struct ppm_name_value flock_flags[] = {
	{"LOCK_SH", PPM_LOCK_SH},
	{"LOCK_EX", PPM_LOCK_EX},
	{"LOCK_NB", PPM_LOCK_NB},
	{"LOCK_UN", PPM_LOCK_UN},
	{"LOCK_NONE", PPM_LOCK_NONE},
	{0, 0},
};

const struct ppm_name_value clone_flags[] = {
	{"CLONE_FILES", PPM_CL_CLONE_FILES},
	{"CLONE_FS", PPM_CL_CLONE_FS},
	{"CLONE_IO", PPM_CL_CLONE_IO},
	{"CLONE_NEWIPC", PPM_CL_CLONE_NEWIPC},
	{"CLONE_NEWNET", PPM_CL_CLONE_NEWNET},
	{"CLONE_NEWNS", PPM_CL_CLONE_NEWNS},
	{"CLONE_NEWPID", PPM_CL_CLONE_NEWPID},
	{"CLONE_NEWUTS", PPM_CL_CLONE_NEWUTS},
	{"CLONE_PARENT", PPM_CL_CLONE_PARENT},
	{"CLONE_PARENT_SETTID", PPM_CL_CLONE_PARENT_SETTID},
	{"CLONE_PTRACE", PPM_CL_CLONE_PTRACE},
	{"CLONE_SIGHAND", PPM_CL_CLONE_SIGHAND},
	{"CLONE_SYSVSEM", PPM_CL_CLONE_SYSVSEM},
	{"CLONE_THREAD", PPM_CL_CLONE_THREAD},
	{"CLONE_UNTRACED", PPM_CL_CLONE_UNTRACED},
	{"CLONE_VM", PPM_CL_CLONE_VM},
	{"CLONE_INVERTED", PPM_CL_CLONE_INVERTED},
	{"NAME_CHANGED", PPM_CL_NAME_CHANGED},
	{"CLOSED", PPM_CL_CLOSED},
	{"CLONE_NEWUSER", PPM_CL_CLONE_NEWUSER},
	{"CLONE_CHILD_CLEARTID", PPM_CL_CLONE_CHILD_CLEARTID},
	{"CLONE_CHILD_SETTID", PPM_CL_CLONE_CHILD_SETTID},
	{"CLONE_SETTLS", PPM_CL_CLONE_SETTLS},
	{"CLONE_STOPPED", PPM_CL_CLONE_STOPPED},
	{"CLONE_VFORK", PPM_CL_CLONE_VFORK},
	{"CLONE_NEWCGROUP", PPM_CL_CLONE_NEWCGROUP},
	{0, 0},
};

const struct ppm_name_value futex_operations[] = {
	{"FUTEX_CLOCK_REALTIME", PPM_FU_FUTEX_CLOCK_REALTIME},
	{"FUTEX_PRIVATE_FLAG", PPM_FU_FUTEX_PRIVATE_FLAG},
	{"FUTEX_CMP_REQUEUE_PI", PPM_FU_FUTEX_CMP_REQUEUE_PI},
	{"FUTEX_WAIT_REQUEUE_PI", PPM_FU_FUTEX_WAIT_REQUEUE_PI},
	{"FUTEX_WAKE_BITSET", PPM_FU_FUTEX_WAKE_BITSET},
	{"FUTEX_WAIT_BITSET", PPM_FU_FUTEX_WAIT_BITSET},
	{"FUTEX_TRYLOCK_PI", PPM_FU_FUTEX_TRYLOCK_PI},
	{"FUTEX_UNLOCK_PI", PPM_FU_FUTEX_UNLOCK_PI},
	{"FUTEX_LOCK_PI", PPM_FU_FUTEX_LOCK_PI},
	{"FUTEX_WAKE_OP", PPM_FU_FUTEX_WAKE_OP},
	{"FUTEX_CMP_REQUEUE", PPM_FU_FUTEX_CMP_REQUEUE},
	{"FUTEX_REQUEUE", PPM_FU_FUTEX_REQUEUE},
	{"FUTEX_FD", PPM_FU_FUTEX_FD},
	{"FUTEX_WAKE", PPM_FU_FUTEX_WAKE},
	{"FUTEX_WAIT", PPM_FU_FUTEX_WAIT},
	{0, 0},
};

const struct ppm_name_value poll_flags[] = {
	{"POLLIN", PPM_POLLIN},
	{"POLLPRI", PPM_POLLPRI},
	{"POLLOUT", PPM_POLLOUT},
	{"POLLRDHUP", PPM_POLLRDHUP},
	{"POLLERR", PPM_POLLERR},
	{"POLLHUP", PPM_POLLHUP},
	{"POLLNVAL", PPM_POLLNVAL},
	{"POLLRDNORM", PPM_POLLRDNORM},
	{"POLLRDBAND", PPM_POLLRDBAND},
	{"POLLWRNORM", PPM_POLLWRNORM},
	{"POLLWRBAND", PPM_POLLWRBAND},
	{0, 0},
};

const struct ppm_name_value mount_flags[] = {
	{"RDONLY", PPM_MS_RDONLY},
	{"NOSUID", PPM_MS_NOSUID},
	{"NODEV", PPM_MS_NODEV},
	{"NOEXEC", PPM_MS_NOEXEC},
	{"SYNCHRONOUS", PPM_MS_SYNCHRONOUS},
	{"REMOUNT", PPM_MS_REMOUNT},
	{"MANDLOCK", PPM_MS_MANDLOCK},
	{"DIRSYNC", PPM_MS_DIRSYNC},
	{"NOATIME", PPM_MS_NOATIME},
	{"NODIRATIME", PPM_MS_NODIRATIME},
	{"BIND", PPM_MS_BIND},
	{"MOVE", PPM_MS_MOVE},
	{"REC", PPM_MS_REC},
	{"SILENT", PPM_MS_SILENT},
	{"POSIXACL", PPM_MS_POSIXACL},
	{"UNBINDABLE", PPM_MS_UNBINDABLE},
	{"PRIVATE", PPM_MS_PRIVATE},
	{"SLAVE", PPM_MS_SLAVE},
	{"SHARED", PPM_MS_SHARED},
	{"RELATIME", PPM_MS_RELATIME},
	{"KERNMOUNT", PPM_MS_KERNMOUNT},
	{"I_VERSION", PPM_MS_I_VERSION},
	{"STRICTATIME", PPM_MS_STRICTATIME},
	{"LAZYTIME", PPM_MS_LAZYTIME},
	{"NOSEC", PPM_MS_NOSEC},
	{"BORN", PPM_MS_BORN},
	{"ACTIVE", PPM_MS_ACTIVE},
	{"NOUSER", PPM_MS_NOUSER},
	{0, 0},
};

const struct ppm_name_value umount_flags[] = {
	{"FORCE", PPM_MNT_FORCE},
	{"DETACH", PPM_MNT_DETACH},
	{"EXPIRE", PPM_MNT_EXPIRE},
	{"NOFOLLOW", PPM_UMOUNT_NOFOLLOW},
	{0, 0},
};

const struct ppm_name_value lseek_whence[] = {
	{"SEEK_END", PPM_SEEK_END},
	{"SEEK_CUR", PPM_SEEK_CUR},
	{"SEEK_SET", PPM_SEEK_SET},
	{0, 0},
};

const struct ppm_name_value shutdown_how[] = {
	{"SHUT_RDWR", PPM_SHUT_RDWR},
	{"SHUT_WR", PPM_SHUT_WR},
	{"SHUT_RD", PPM_SHUT_RD},
	{0, 0},
};

const struct ppm_name_value rlimit_resources[] = {
	{"RLIMIT_UNKNOWN", PPM_RLIMIT_UNKNOWN},
	{"RLIMIT_RTTIME", PPM_RLIMIT_RTTIME},
	{"RLIMIT_RTPRIO", PPM_RLIMIT_RTPRIO},
	{"RLIMIT_NICE", PPM_RLIMIT_NICE},
	{"RLIMIT_MSGQUEUE", PPM_RLIMIT_MSGQUEUE},
	{"RLIMIT_SIGPENDING", PPM_RLIMIT_SIGPENDING},
	{"RLIMIT_LOCKS", PPM_RLIMIT_LOCKS},
	{"RLIMIT_AS", PPM_RLIMIT_AS},
	{"RLIMIT_MEMLOCK", PPM_RLIMIT_MEMLOCK},
	{"RLIMIT_NOFILE", PPM_RLIMIT_NOFILE},
	{"RLIMIT_NPROC", PPM_RLIMIT_NPROC},
	{"RLIMIT_RSS", PPM_RLIMIT_RSS},
	{"RLIMIT_CORE", PPM_RLIMIT_CORE},
	{"RLIMIT_STACK", PPM_RLIMIT_STACK},
	{"RLIMIT_DATA", PPM_RLIMIT_DATA},
	{"RLIMIT_FSIZE", PPM_RLIMIT_FSIZE},
	{"RLIMIT_CPU", PPM_RLIMIT_CPU},
	{0, 0},
};

const struct ppm_name_value fcntl_commands[] = {
	{"F_GETPIPE_SZ", PPM_FCNTL_F_GETPIPE_SZ},
	{"F_SETPIPE_SZ", PPM_FCNTL_F_SETPIPE_SZ},
	{"F_NOTIFY", PPM_FCNTL_F_NOTIFY},
	{"F_DUPFD_CLOEXEC", PPM_FCNTL_F_DUPFD_CLOEXEC},
	{"F_CANCELLK", PPM_FCNTL_F_CANCELLK},
	{"F_GETLEASE", PPM_FCNTL_F_GETLEASE},
	{"F_SETLEASE", PPM_FCNTL_F_SETLEASE},
	{"F_GETOWN_EX", PPM_FCNTL_F_GETOWN_EX},
	{"F_SETOWN_EX", PPM_FCNTL_F_SETOWN_EX},
	#ifndef CONFIG_64BIT
	{"F_SETLKW64", PPM_FCNTL_F_SETLKW64},
	{"F_SETLK64", PPM_FCNTL_F_SETLK64},
	{"F_GETLK64", PPM_FCNTL_F_GETLK64},
	#endif
	{"F_GETSIG", PPM_FCNTL_F_GETSIG},
	{"F_SETSIG", PPM_FCNTL_F_SETSIG},
	{"F_GETOWN", PPM_FCNTL_F_GETOWN},
	{"F_SETOWN", PPM_FCNTL_F_SETOWN},
	{"F_SETLKW", PPM_FCNTL_F_SETLKW},
	{"F_SETLK", PPM_FCNTL_F_SETLK},
	{"F_GETLK", PPM_FCNTL_F_GETLK},
	{"F_SETFL", PPM_FCNTL_F_SETFL},
	{"F_GETFL", PPM_FCNTL_F_GETFL},
	{"F_SETFD", PPM_FCNTL_F_SETFD},
	{"F_GETFD", PPM_FCNTL_F_GETFD},
	{"F_DUPFD", PPM_FCNTL_F_DUPFD},
	{"F_OFD_GETLK", PPM_FCNTL_F_OFD_GETLK},
	{"F_OFD_SETLK", PPM_FCNTL_F_OFD_SETLK},
	{"F_OFD_SETLKW", PPM_FCNTL_F_OFD_SETLKW},
	{"UNKNOWN", PPM_FCNTL_UNKNOWN},
	{0, 0},
};

const struct ppm_name_value sockopt_levels[] = {
	{"SOL_SOCKET", PPM_SOCKOPT_LEVEL_SOL_SOCKET},
	{"SOL_TCP", PPM_SOCKOPT_LEVEL_SOL_TCP},
	{"UNKNOWN", PPM_SOCKOPT_LEVEL_UNKNOWN},
	{0, 0},
};

const struct ppm_name_value sockopt_options[] = {
	{"SO_COOKIE", PPM_SOCKOPT_SO_COOKIE},
	{"SO_MEMINFO", PPM_SOCKOPT_SO_MEMINFO},
	{"SO_PEERGROUPS", PPM_SOCKOPT_SO_PEERGROUPS},
	{"SO_ATTACH_BPF", PPM_SOCKOPT_SO_ATTACH_BPF},
	{"SO_INCOMING_CPU", PPM_SOCKOPT_SO_INCOMING_CPU},
	{"SO_BPF_EXTENSIONS", PPM_SOCKOPT_SO_BPF_EXTENSIONS},
	{"SO_MAX_PACING_RATE", PPM_SOCKOPT_SO_MAX_PACING_RATE},
	{"SO_BUSY_POLL", PPM_SOCKOPT_SO_BUSY_POLL},
	{"SO_SELECT_ERR_QUEUE", PPM_SOCKOPT_SO_SELECT_ERR_QUEUE},
	{"SO_LOCK_FILTER", PPM_SOCKOPT_SO_LOCK_FILTER},
	{"SO_NOFCS", PPM_SOCKOPT_SO_NOFCS},
	{"SO_PEEK_OFF", PPM_SOCKOPT_SO_PEEK_OFF},
	{"SO_WIFI_STATUS", PPM_SOCKOPT_SO_WIFI_STATUS},
	{"SO_RXQ_OVFL", PPM_SOCKOPT_SO_RXQ_OVFL},
	{"SO_DOMAIN", PPM_SOCKOPT_SO_DOMAIN},
	{"SO_PROTOCOL", PPM_SOCKOPT_SO_PROTOCOL},
	{"SO_TIMESTAMPING", PPM_SOCKOPT_SO_TIMESTAMPING},
	{"SO_MARK", PPM_SOCKOPT_SO_MARK},
	{"SO_TIMESTAMPNS", PPM_SOCKOPT_SO_TIMESTAMPNS},
	{"SO_PASSSEC", PPM_SOCKOPT_SO_PASSSEC},
	{"SO_PEERSEC", PPM_SOCKOPT_SO_PEERSEC},
	{"SO_ACCEPTCONN", PPM_SOCKOPT_SO_ACCEPTCONN},
	{"SO_TIMESTAMP", PPM_SOCKOPT_SO_TIMESTAMP},
	{"SO_PEERNAME", PPM_SOCKOPT_SO_PEERNAME},
	{"SO_DETACH_FILTER", PPM_SOCKOPT_SO_DETACH_FILTER},
	{"SO_ATTACH_FILTER", PPM_SOCKOPT_SO_ATTACH_FILTER},
	{"SO_BINDTODEVICE", PPM_SOCKOPT_SO_BINDTODEVICE},
	{"SO_SECURITY_ENCRYPTION_NETWORK", PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK},
	{"SO_SECURITY_ENCRYPTION_TRANSPORT", PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT},
	{"SO_SECURITY_AUTHENTICATION", PPM_SOCKOPT_SO_SECURITY_AUTHENTICATION},
	{"SO_SNDTIMEO", PPM_SOCKOPT_SO_SNDTIMEO},
	{"SO_RCVTIMEO", PPM_SOCKOPT_SO_RCVTIMEO},
	{"SO_SNDLOWAT", PPM_SOCKOPT_SO_SNDLOWAT},
	{"SO_RCVLOWAT", PPM_SOCKOPT_SO_RCVLOWAT},
	{"SO_PEERCRED", PPM_SOCKOPT_SO_PEERCRED},
	{"SO_PASSCRED", PPM_SOCKOPT_SO_PASSCRED},
	{"SO_REUSEPORT", PPM_SOCKOPT_SO_REUSEPORT},
	{"SO_BSDCOMPAT", PPM_SOCKOPT_SO_BSDCOMPAT},
	{"SO_LINGER", PPM_SOCKOPT_SO_LINGER},
	{"SO_PRIORITY", PPM_SOCKOPT_SO_PRIORITY},
	{"SO_NO_CHECK", PPM_SOCKOPT_SO_NO_CHECK},
	{"SO_OOBINLINE", PPM_SOCKOPT_SO_OOBINLINE},
	{"SO_KEEPALIVE", PPM_SOCKOPT_SO_KEEPALIVE},
	{"SO_RCVBUFFORCE", PPM_SOCKOPT_SO_RCVBUFFORCE},
	{"SO_SNDBUFFORCE", PPM_SOCKOPT_SO_SNDBUFFORCE},
	{"SO_RCVBUF", PPM_SOCKOPT_SO_RCVBUF},
	{"SO_SNDBUF", PPM_SOCKOPT_SO_SNDBUF},
	{"SO_BROADCAST", PPM_SOCKOPT_SO_BROADCAST},
	{"SO_DONTROUTE", PPM_SOCKOPT_SO_DONTROUTE},
	{"SO_ERROR", PPM_SOCKOPT_SO_ERROR},
	{"SO_TYPE", PPM_SOCKOPT_SO_TYPE},
	{"SO_REUSEADDR", PPM_SOCKOPT_SO_REUSEADDR},
	{"SO_DEBUG", PPM_SOCKOPT_SO_DEBUG},
	{"UNKNOWN", PPM_SOCKOPT_UNKNOWN},
	{0, 0},
};

const struct ppm_name_value ptrace_requests[] = {
	{"PTRACE_SINGLEBLOCK", PPM_PTRACE_SINGLEBLOCK},
	{"PTRACE_SYSEMU_SINGLESTEP", PPM_PTRACE_SYSEMU_SINGLESTEP},
	{"PTRACE_SYSEMU", PPM_PTRACE_SYSEMU},
	{"PTRACE_ARCH_PRCTL", PPM_PTRACE_ARCH_PRCTL},
	{"PTRACE_SET_THREAD_AREA", PPM_PTRACE_SET_THREAD_AREA},
	{"PTRACE_GET_THREAD_AREA", PPM_PTRACE_GET_THREAD_AREA},
	{"PTRACE_OLDSETOPTIONS", PPM_PTRACE_OLDSETOPTIONS},
	{"PTRACE_SETFPXREGS", PPM_PTRACE_SETFPXREGS},
	{"PTRACE_GETFPXREGS", PPM_PTRACE_GETFPXREGS},
	{"PTRACE_SETFPREGS", PPM_PTRACE_SETFPREGS},
	{"PTRACE_GETFPREGS", PPM_PTRACE_GETFPREGS},
	{"PTRACE_SETREGS", PPM_PTRACE_SETREGS},
	{"PTRACE_GETREGS", PPM_PTRACE_GETREGS},
	{"PTRACE_SETSIGMASK", PPM_PTRACE_SETSIGMASK},
	{"PTRACE_GETSIGMASK", PPM_PTRACE_GETSIGMASK},
	{"PTRACE_PEEKSIGINFO", PPM_PTRACE_PEEKSIGINFO},
	{"PTRACE_LISTEN", PPM_PTRACE_LISTEN},
	{"PTRACE_INTERRUPT", PPM_PTRACE_INTERRUPT},
	{"PTRACE_SEIZE", PPM_PTRACE_SEIZE},
	{"PTRACE_SETREGSET", PPM_PTRACE_SETREGSET},
	{"PTRACE_GETREGSET", PPM_PTRACE_GETREGSET},
	{"PTRACE_SETSIGINFO", PPM_PTRACE_SETSIGINFO},
	{"PTRACE_GETSIGINFO", PPM_PTRACE_GETSIGINFO},
	{"PTRACE_GETEVENTMSG", PPM_PTRACE_GETEVENTMSG},
	{"PTRACE_SETOPTIONS", PPM_PTRACE_SETOPTIONS},
	{"PTRACE_SYSCALL", PPM_PTRACE_SYSCALL},
	{"PTRACE_DETACH", PPM_PTRACE_DETACH},
	{"PTRACE_ATTACH", PPM_PTRACE_ATTACH},
	{"PTRACE_SINGLESTEP", PPM_PTRACE_SINGLESTEP},
	{"PTRACE_KILL", PPM_PTRACE_KILL},
	{"PTRACE_CONT", PPM_PTRACE_CONT},
	{"PTRACE_POKEUSR", PPM_PTRACE_POKEUSR},
	{"PTRACE_POKEDATA", PPM_PTRACE_POKEDATA},
	{"PTRACE_POKETEXT", PPM_PTRACE_POKETEXT},
	{"PTRACE_PEEKUSR", PPM_PTRACE_PEEKUSR},
	{"PTRACE_PEEKDATA", PPM_PTRACE_PEEKDATA},
	{"PTRACE_PEEKTEXT", PPM_PTRACE_PEEKTEXT},
	{"PTRACE_TRACEME", PPM_PTRACE_TRACEME},
	{"PTRACE_UNKNOWN", PPM_PTRACE_UNKNOWN},
	{0, 0},
};

const struct ppm_name_value prot_flags[] = {
	{"PROT_READ", PPM_PROT_READ},
	{"PROT_WRITE", PPM_PROT_WRITE},
	{"PROT_EXEC", PPM_PROT_EXEC},
	{"PROT_SEM", PPM_PROT_SEM},
	{"PROT_GROWSDOWN", PPM_PROT_GROWSDOWN},
	{"PROT_GROWSUP", PPM_PROT_GROWSUP},
	{"PROT_SAO", PPM_PROT_SAO},
	{"PROT_NONE", PPM_PROT_NONE},
	{0, 0},
};

const struct ppm_name_value mmap_flags[] = {
	{"MAP_SHARED", PPM_MAP_SHARED},
	{"MAP_PRIVATE", PPM_MAP_PRIVATE},
	{"MAP_FIXED", PPM_MAP_FIXED},
	{"MAP_ANONYMOUS", PPM_MAP_ANONYMOUS},
	{"MAP_32BIT", PPM_MAP_32BIT},
	{"MAP_RENAME", PPM_MAP_RENAME},
	{"MAP_NORESERVE", PPM_MAP_NORESERVE},
	{"MAP_POPULATE", PPM_MAP_POPULATE},
	{"MAP_NONBLOCK", PPM_MAP_NONBLOCK},
	{"MAP_GROWSDOWN", PPM_MAP_GROWSDOWN},
	{"MAP_DENYWRITE", PPM_MAP_DENYWRITE},
	{"MAP_EXECUTABLE", PPM_MAP_EXECUTABLE},
	{"MAP_INHERIT", PPM_MAP_INHERIT},
	{"MAP_FILE", PPM_MAP_FILE},
	{"MAP_LOCKED", PPM_MAP_LOCKED},
	{0, 0},
};

const struct ppm_name_value splice_flags[] = {
	{"SPLICE_F_MOVE", PPM_SPLICE_F_MOVE},
	{"SPLICE_F_NONBLOCK", PPM_SPLICE_F_NONBLOCK},
	{"SPLICE_F_MORE", PPM_SPLICE_F_MORE},
	{"SPLICE_F_GIFT", PPM_SPLICE_F_GIFT},
	{0, 0},
};

const struct ppm_name_value quotactl_dqi_flags[] = {
	{"DQF_NONE", PPM_DQF_NONE},
	{"V1_DQF_RSQUASH", PPM_V1_DQF_RSQUASH},
	{0, 0},
};

const struct ppm_name_value quotactl_cmds[] = {
	{"Q_QUOTAON", PPM_Q_QUOTAON},
	{"Q_QUOTAOFF", PPM_Q_QUOTAOFF},
	{"Q_GETFMT", PPM_Q_GETFMT},
	{"Q_GETINFO", PPM_Q_GETINFO},
	{"Q_SETINFO", PPM_Q_SETINFO},
	{"Q_GETQUOTA", PPM_Q_GETQUOTA},
	{"Q_SETQUOTA", PPM_Q_SETQUOTA},
	{"Q_SYNC", PPM_Q_SYNC},
	{"Q_XQUOTAON", PPM_Q_XQUOTAON},
	{"Q_XQUOTAOFF", PPM_Q_XQUOTAOFF},
	{"Q_XGETQUOTA", PPM_Q_XGETQUOTA},
	{"Q_XSETQLIM", PPM_Q_XSETQLIM},
	{"Q_XGETQSTAT", PPM_Q_XGETQSTAT},
	{"Q_XQUOTARM", PPM_Q_XQUOTARM},
	{"Q_XQUOTASYNC", PPM_Q_XQUOTASYNC},
	{0, 0},
};

const struct ppm_name_value quotactl_types[] = {
	{"USRQUOTA", PPM_USRQUOTA},
	{"GRPQUOTA", PPM_GRPQUOTA},
	{0, 0},
};

const struct ppm_name_value quotactl_quota_fmts[] = {
	{"QFMT_NOT_USED", PPM_QFMT_NOT_USED},
	{"QFMT_VFS_OLD", PPM_QFMT_VFS_OLD},
	{"QFMT_VFS_V0", PPM_QFMT_VFS_V0},
	{"QFMT_VFS_V1", PPM_QFMT_VFS_V1},
	{0, 0},
};

const struct ppm_name_value semop_flags[] = {
	{"IPC_NOWAIT", PPM_IPC_NOWAIT},
	{"SEM_UNDO", PPM_SEM_UNDO},
	{0, 0},
};

const struct ppm_name_value semget_flags[] = {
	{"IPC_EXCL", PPM_IPC_EXCL},
	{"IPC_CREAT", PPM_IPC_CREAT},
	{0, 0},
};

const struct ppm_name_value semctl_commands[] = {
	{"IPC_STAT", PPM_IPC_STAT},
	{"IPC_SET", PPM_IPC_SET},
	{"IPC_RMID", PPM_IPC_RMID},
	{"IPC_INFO", PPM_IPC_INFO},
	{"SEM_INFO", PPM_SEM_INFO},
	{"SEM_STAT", PPM_SEM_STAT},
	{"GETALL", PPM_GETALL},
	{"GETNCNT", PPM_GETNCNT},
	{"GETPID", PPM_GETPID},
	{"GETVAL", PPM_GETVAL},
	{"GETZCNT", PPM_GETZCNT},
	{"SETALL", PPM_SETALL},
	{"SETVAL", PPM_SETVAL},
	{0, 0},
};

const struct ppm_name_value access_flags[] = {
	{"F_OK", PPM_F_OK},
	{"R_OK", PPM_R_OK},
	{"W_OK", PPM_W_OK},
	{"X_OK", PPM_X_OK},
	{0, 0},
};

const struct ppm_name_value pf_flags[] = {
	{"PROTECTION_VIOLATION", PPM_PF_PROTECTION_VIOLATION},
	{"PAGE_NOT_PRESENT", PPM_PF_PAGE_NOT_PRESENT},
	{"WRITE_ACCESS", PPM_PF_WRITE_ACCESS},
	{"READ_ACCESS", PPM_PF_READ_ACCESS},
	{"USER_FAULT", PPM_PF_USER_FAULT},
	{"SUPERVISOR_FAULT", PPM_PF_SUPERVISOR_FAULT},
	{"RESERVED_PAGE", PPM_PF_RESERVED_PAGE},
	{"INSTRUCTION_FETCH", PPM_PF_INSTRUCTION_FETCH},
	{0, 0},
};

const struct ppm_name_value unlinkat_flags[] = {
	{"AT_REMOVEDIR", PPM_AT_REMOVEDIR},
	{0, 0},
};

const struct ppm_name_value linkat_flags[] = {
	{"AT_SYMLINK_FOLLOW", PPM_AT_SYMLINK_FOLLOW},
	{"AT_EMPTY_PATH", PPM_AT_EMPTY_PATH},
	{0, 0},
};

const struct ppm_name_value chmod_mode[] = {
	{"S_IXOTH", PPM_S_IXOTH},
	{"S_IWOTH", PPM_S_IWOTH},
	{"S_IROTH", PPM_S_IROTH},
	{"S_IXGRP", PPM_S_IXGRP},
	{"S_IWGRP", PPM_S_IWGRP},
	{"S_IRGRP", PPM_S_IRGRP},
	{"S_IXUSR", PPM_S_IXUSR},
	{"S_IWUSR", PPM_S_IWUSR},
	{"S_IRUSR", PPM_S_IRUSR},
	{"S_ISVTX", PPM_S_ISVTX},
	{"S_ISGID", PPM_S_ISGID},
	{"S_ISUID", PPM_S_ISUID},
	{0, 0},
};

const struct ppm_param_info sockopt_dynamic_param[PPM_SOCKOPT_IDX_MAX] = {
	[PPM_SOCKOPT_IDX_UNKNOWN] = {{0}, PT_BYTEBUF, PF_HEX},
	[PPM_SOCKOPT_IDX_ERRNO] = {{0}, PT_ERRNO, PF_DEC},
	[PPM_SOCKOPT_IDX_UINT32] = {{0}, PT_UINT32, PF_DEC},
	[PPM_SOCKOPT_IDX_UINT64] = {{0}, PT_UINT64, PF_DEC},
	[PPM_SOCKOPT_IDX_TIMEVAL] = {{0}, PT_RELTIME, PF_DEC},
};

const struct ppm_param_info ptrace_dynamic_param[PPM_PTRACE_IDX_MAX] = {
	[PPM_PTRACE_IDX_UINT64] = {{0}, PT_UINT64, PF_HEX},
	[PPM_PTRACE_IDX_SIGTYPE] = {{0}, PT_SIGTYPE, PF_DEC},
};

const struct ppm_param_info bpf_dynamic_param[PPM_BPF_IDX_MAX] = {
	[PPM_BPF_IDX_FD] = {{0}, PT_FD, PF_DEC},
	[PPM_BPF_IDX_RES] = {{0}, PT_ERRNO, PF_DEC},
};


struct ppm_event_info {
	char name[PPM_MAX_NAME_LEN];
	enum ppm_event_category category;
	enum ppm_event_flags flags;
	uint32_t nparams;
	struct ppm_param_info params[PPM_MAX_EVENT_PARAMS];
} _packed;

const struct ppm_event_info g_event_info[PPM_EVENT_MAX] = {
	{"syscall", EC_OTHER, EF_NONE, 2, {{"ID", PT_SYSCALLID, PF_DEC}, {"nativeID", PT_UINT16, PF_DEC} } },
	{"syscall", EC_OTHER, EF_NONE, 1, {{"ID", PT_SYSCALLID, PF_DEC} } },
	{"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	{"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	{"close", EC_IO_OTHER, EF_DESTROYS_FD | EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_DEC} } },
	{"close", EC_IO_OTHER, EF_DESTROYS_FD | EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"read", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"read", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"write", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"write", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"brk", EC_MEMORY, EF_OLD_VERSION, 1, {{"size", PT_UINT32, PF_DEC} } },
	{"brk", EC_MEMORY, EF_OLD_VERSION, 1, {{"res", PT_UINT64, PF_HEX} } },
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 8, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC} } },
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 11, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"procexit", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"NA1", EC_PROCESS, EF_UNUSED, 0},
	{"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 3, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC} } },
	{"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"fd", PT_FD, PF_DEC}, {"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC} } },
	// {"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 2, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC} } },
	//{"socket", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	{"bind", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	{"bind", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"addr", PT_SOCKADDR, PF_NA} } },
	{"connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	{"connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	{"listen", EC_NET, EF_USES_FD, 2, {{"fd", PT_FD, PF_DEC}, {"backlog", PT_UINT32, PF_DEC} } },
	{"listen", EC_NET, EF_USES_FD, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 3, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC} } },
	{"send", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"send", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"sendto", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	{"sendto", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"recv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"recv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"recvfrom", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"recvfrom", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 3, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	{"shutdown", EC_NET, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"how", PT_FLAGS8, PF_HEX, shutdown_how} } },
	{"shutdown", EC_NET, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"getsockname", EC_NET, EF_DROP_FALCO, 0},
	{"getsockname", EC_NET, EF_DROP_FALCO, 0},
	{"getpeername", EC_NET, EF_DROP_FALCO, 0},
	{"getpeername", EC_NET, EF_DROP_FALCO, 0},
	{"socketpair", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 3, {{"domain", PT_FLAGS32, PF_DEC, socket_families}, {"type", PT_UINT32, PF_DEC}, {"proto", PT_UINT32, PF_DEC} } },
	{"socketpair", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"res", PT_ERRNO, PF_DEC}, {"fd1", PT_FD, PF_DEC}, {"fd2", PT_FD, PF_DEC}, {"source", PT_UINT64, PF_HEX}, {"peer", PT_UINT64, PF_HEX} } },
	{"setsockopt", EC_NET, EF_NONE, 0 },
	{"setsockopt", EC_NET, EF_USES_FD, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, PPM_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
	{"getsockopt", EC_NET, EF_MODIFIES_STATE | EF_DROP_FALCO, 0 },
	{"getsockopt", EC_NET, EF_USES_FD | EF_MODIFIES_STATE| EF_DROP_FALCO, 6, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"level", PT_FLAGS8, PF_DEC, sockopt_levels}, {"optname", PT_FLAGS8, PF_DEC, sockopt_options}, {"val", PT_DYN, PF_DEC, sockopt_dynamic_param, PPM_SOCKOPT_IDX_MAX}, {"optlen", PT_UINT32, PF_DEC}}},
	{"sendmsg", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	{"sendmsg", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"sendmmsg", EC_IO_WRITE, EF_DROP_FALCO, 0},
	{"sendmmsg", EC_IO_WRITE, EF_DROP_FALCO, 0},
	{"recvmsg", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	{"recvmsg", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_MODIFIES_STATE, 4, {{"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA}, {"tuple", PT_SOCKTUPLE, PF_NA} } },
	{"recvmmsg", EC_IO_READ, EF_DROP_FALCO, 0},
	{"recvmmsg", EC_IO_READ, EF_DROP_FALCO, 0},
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 1, {{"flags", PT_INT32, PF_HEX} } },
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 3, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC} } },
	{"creat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	{"creat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	{"pipe", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	{"pipe", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 4, {{"res", PT_ERRNO, PF_DEC}, {"fd1", PT_FD, PF_DEC}, {"fd2", PT_FD, PF_DEC}, {"ino", PT_UINT64, PF_DEC} } },
	{"eventfd", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 2, {{"initval", PT_UINT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX} } },
	{"eventfd", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"res", PT_FD, PF_DEC} } },
	{"futex", EC_IPC, EF_DROP_FALCO, 3, {{"addr", PT_UINT64, PF_HEX}, {"op", PT_FLAGS16, PF_HEX, futex_operations}, {"val", PT_UINT64, PF_DEC} } },
	{"futex", EC_IPC, EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"stat", EC_FILE, EF_DROP_FALCO, 0},
	{"stat", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"lstat", EC_FILE, EF_DROP_FALCO, 0},
	{"lstat", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"fstat", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_NA} } },
	{"fstat", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"stat64", EC_FILE, EF_DROP_FALCO, 0},
	{"stat64", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"lstat64", EC_FILE, EF_DROP_FALCO, 0},
	{"lstat64", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"fstat64", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_NA} } },
	{"fstat64", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"epoll_wait", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 1, {{"maxevents", PT_ERRNO, PF_DEC} } },
	{"epoll_wait", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"poll", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 2, {{"fds", PT_FDLIST, PF_DEC}, {"timeout", PT_INT64, PF_DEC} } },
	{"poll", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"fds", PT_FDLIST, PF_DEC} } },
	{"select", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 0},
	{"select", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"select", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 0},
	{"select", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"lseek", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 3, {{"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"whence", PT_FLAGS8, PF_DEC, lseek_whence} } },
	{"lseek", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"llseek", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 3, {{"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"whence", PT_FLAGS8, PF_DEC, lseek_whence} } },
	{"llseek", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"ioctl", EC_IO_OTHER, EF_USES_FD | EF_OLD_VERSION, 2, {{"fd", PT_FD, PF_DEC}, {"request", PT_UINT64, PF_HEX} } },
	{"ioctl", EC_IO_OTHER, EF_USES_FD | EF_OLD_VERSION, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"getcwd", EC_FILE, EF_DROP_FALCO, 0},
	{"getcwd", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_CHARBUF, PF_NA} } },
	{"chdir", EC_FILE, EF_MODIFIES_STATE, 0},
	{"chdir", EC_FILE, EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_CHARBUF, PF_NA} } },
	{"fchdir", EC_FILE, EF_USES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_NA} } },
	{"fchdir", EC_FILE, EF_USES_FD | EF_MODIFIES_STATE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"mkdir", EC_FILE, EF_NONE, 2, {{"path", PT_FSPATH, PF_NA}, {"mode", PT_UINT32, PF_HEX} } },
	{"mkdir", EC_FILE, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"rmdir", EC_FILE, EF_NONE, 1, {{"path", PT_FSPATH, PF_NA} } },
	{"rmdir", EC_FILE, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 4, {{"dirfd", PT_FD, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT} } },
	{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE | EF_OLD_VERSION, 1, {{"fd", PT_FD, PF_DEC} } },
	{"link", EC_FILE, EF_OLD_VERSION, 2, {{"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA} } },
	{"link", EC_FILE, EF_OLD_VERSION, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"linkat", EC_FILE, EF_OLD_VERSION, 4, {{"olddir", PT_FD, PF_DEC}, {"oldpath", PT_CHARBUF, PF_NA}, {"newdir", PT_FD, PF_DEC}, {"newpath", PT_CHARBUF, PF_NA} } },
	{"linkat", EC_FILE, EF_OLD_VERSION, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"unlink", EC_FILE, EF_OLD_VERSION, 1, {{"path", PT_FSPATH, PF_NA} } },
	{"unlink", EC_FILE, EF_OLD_VERSION, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"unlinkat", EC_FILE, EF_OLD_VERSION, 2, {{"dirfd", PT_FD, PF_DEC}, {"name", PT_CHARBUF, PF_NA} } },
	{"unlinkat", EC_FILE, EF_OLD_VERSION, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"pread", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 3, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC} } },
	{"pread", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"pwrite", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 3, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC} } },
	{"pwrite", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"readv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_DEC} } },
	{"readv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 3, {{"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"writev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	{"writev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"preadv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"pos", PT_UINT64, PF_DEC} } },
	{"preadv", EC_IO_READ, EF_USES_FD | EF_READS_FROM_FD | EF_DROP_FALCO, 3, {{"res", PT_ERRNO, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"pwritev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 3, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}, {"pos", PT_UINT64, PF_DEC} } },
	{"pwritev", EC_IO_WRITE, EF_USES_FD | EF_WRITES_TO_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"data", PT_BYTEBUF, PF_NA} } },
	{"dup", EC_IO_OTHER, EF_CREATES_FD | EF_USES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	{"dup", EC_IO_OTHER, EF_CREATES_FD | EF_USES_FD | EF_MODIFIES_STATE, 1, {{"res", PT_FD, PF_DEC} } },
	{"signalfd", EC_SIGNAL, EF_CREATES_FD | EF_MODIFIES_STATE, 3, {{"fd", PT_FD, PF_DEC}, {"mask", PT_UINT32, PF_HEX}, {"flags", PT_FLAGS8, PF_HEX} } },
	{"signalfd", EC_SIGNAL, EF_CREATES_FD | EF_MODIFIES_STATE, 1, {{"res", PT_FD, PF_DEC} } },
	{"kill", EC_SIGNAL, EF_NONE, 2, {{"pid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} } },
	{"kill", EC_SIGNAL, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"tkill", EC_SIGNAL, EF_NONE, 2, {{"tid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} } },
	{"tkill", EC_SIGNAL, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"tgkill", EC_SIGNAL, EF_NONE, 3, {{"pid", PT_PID, PF_DEC}, {"tid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} } },
	{"tgkill", EC_SIGNAL, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"nanosleep", EC_SLEEP, EF_WAITS | EF_DROP_FALCO, 1, {{"interval", PT_RELTIME, PF_DEC} } },
	{"nanosleep", EC_SLEEP, EF_WAITS | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"timerfd_create", EC_TIME, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 2, {{"clockid", PT_UINT8, PF_DEC}, {"flags", PT_FLAGS8, PF_HEX} } },
	{"timerfd_create", EC_TIME, EF_CREATES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"res", PT_FD, PF_DEC} } },
	{"inotify_init", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 1, {{"flags", PT_FLAGS8, PF_HEX} } },
	{"inotify_init", EC_IPC, EF_CREATES_FD | EF_MODIFIES_STATE, 1, {{"res", PT_FD, PF_DEC} } },
	{"getrlimit", EC_PROCESS, EF_DROP_FALCO, 1, {{"resource", PT_FLAGS8, PF_DEC, rlimit_resources} } },
	{"getrlimit", EC_PROCESS, EF_DROP_FALCO, 3, {{"res", PT_ERRNO, PF_DEC}, {"cur", PT_INT64, PF_DEC}, {"max", PT_INT64, PF_DEC} } },
	{"setrlimit", EC_PROCESS, EF_DROP_FALCO, 1, {{"resource", PT_FLAGS8, PF_DEC, rlimit_resources} } },
	{"setrlimit", EC_PROCESS, EF_DROP_FALCO, 3, {{"res", PT_ERRNO, PF_DEC}, {"cur", PT_INT64, PF_DEC}, {"max", PT_INT64, PF_DEC} } },
	{"prlimit", EC_PROCESS, EF_NONE, 2, {{"pid", PT_PID, PF_DEC}, {"resource", PT_FLAGS8, PF_DEC, rlimit_resources} } },
	{"prlimit", EC_PROCESS, EF_NONE, 5, {{"res", PT_ERRNO, PF_DEC}, {"newcur", PT_INT64, PF_DEC}, {"newmax", PT_INT64, PF_DEC}, {"oldcur", PT_INT64, PF_DEC}, {"oldmax", PT_INT64, PF_DEC} } },
	{"switch", EC_SCHEDULER, EF_SKIPPARSERESET | EF_OLD_VERSION | EF_DROP_FALCO, 1, {{"next", PT_PID, PF_DEC} } },
	{"NA2", EC_SCHEDULER, EF_SKIPPARSERESET | EF_UNUSED | EF_OLD_VERSION, 0},
	{"drop", EC_INTERNAL, EF_SKIPPARSERESET, 1, {{"ratio", PT_UINT32, PF_DEC} } },
	{"drop", EC_INTERNAL, EF_SKIPPARSERESET, 1, {{"ratio", PT_UINT32, PF_DEC} } },
	{"fcntl", EC_IO_OTHER, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 2, {{"fd", PT_FD, PF_DEC}, {"cmd", PT_FLAGS8, PF_DEC, fcntl_commands} } },
	{"fcntl", EC_IO_OTHER, EF_USES_FD | EF_MODIFIES_STATE | EF_DROP_FALCO, 1, {{"res", PT_FD, PF_DEC} } },
	{"switch", EC_SCHEDULER, EF_DROP_FALCO, 6, {{"next", PT_PID, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"NA2", EC_SCHEDULER, EF_UNUSED, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 13, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 16, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"brk", EC_MEMORY, EF_DROP_FALCO, 1, {{"addr", PT_UINT64, PF_HEX} } },
	{"brk", EC_MEMORY, EF_DROP_FALCO, 4, {{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"mmap", EC_MEMORY, EF_DROP_FALCO, 6, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC}, {"prot", PT_FLAGS32, PF_HEX, prot_flags}, {"flags", PT_FLAGS32, PF_HEX, mmap_flags}, {"fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC} } },
	{"mmap", EC_MEMORY, EF_DROP_FALCO, 4, {{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"mmap2", EC_MEMORY, EF_DROP_FALCO, 6, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC}, {"prot", PT_FLAGS32, PF_HEX, prot_flags}, {"flags", PT_FLAGS32, PF_HEX, mmap_flags}, {"fd", PT_FD, PF_DEC}, {"pgoffset", PT_UINT64, PF_DEC} } },
	{"mmap2", EC_MEMORY, EF_DROP_FALCO, 4, {{"res", PT_UINT64, PF_HEX}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"munmap", EC_MEMORY, EF_DROP_FALCO, 2, {{"addr", PT_UINT64, PF_HEX}, {"length", PT_UINT64, PF_DEC} } },
	{"munmap", EC_MEMORY, EF_DROP_FALCO, 4, {{"res", PT_ERRNO, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC} } },
	{"splice", EC_IO_OTHER, EF_USES_FD | EF_DROP_FALCO, 4, {{"fd_in", PT_FD, PF_DEC}, {"fd_out", PT_FD, PF_DEC}, {"size", PT_UINT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, splice_flags} } },
	{"splice", EC_IO_OTHER, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"ptrace", EC_PROCESS, EF_NONE, 2, {{"request", PT_FLAGS16, PF_DEC, ptrace_requests}, {"pid", PT_PID, PF_DEC} } },
	{"ptrace", EC_PROCESS, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"addr", PT_DYN, PF_HEX, ptrace_dynamic_param, PPM_PTRACE_IDX_MAX}, {"data", PT_DYN, PF_HEX, ptrace_dynamic_param, PPM_PTRACE_IDX_MAX} } },
	{"ioctl", EC_IO_OTHER, EF_USES_FD, 3, {{"fd", PT_FD, PF_DEC}, {"request", PT_UINT64, PF_HEX}, {"argument", PT_UINT64, PF_HEX} } },
	{"ioctl", EC_IO_OTHER, EF_USES_FD, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 14, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"env", PT_BYTEBUF, PF_NA} } },
	{"rename", EC_FILE, EF_NONE, 0 },
	{"rename", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA} } },
	{"renameat", EC_FILE, EF_NONE, 0 },
	{"renameat", EC_FILE, EF_NONE, 5, {{"res", PT_ERRNO, PF_DEC}, {"olddirfd", PT_FD, PF_DEC}, {"oldpath", PT_CHARBUF, PF_NA}, {"newdirfd", PT_FD, PF_DEC}, {"newpath", PT_CHARBUF, PF_NA} } },
	{"symlink", EC_FILE, EF_NONE, 0 },
	{"symlink", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"target", PT_CHARBUF, PF_NA}, {"linkpath", PT_FSPATH, PF_NA} } },
	{"symlinkat", EC_FILE, EF_NONE, 0 },
	{"symlinkat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"target", PT_CHARBUF, PF_NA}, {"linkdirfd", PT_FD, PF_DEC}, {"linkpath", PT_CHARBUF, PF_NA} } },
	{"fork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"fork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 16, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 16, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"procexit", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"status", PT_ERRNO, PF_DEC} } },
	{"NA1", EC_PROCESS, EF_UNUSED, 0},
	{"sendfile", EC_IO_WRITE, EF_USES_FD | EF_DROP_FALCO, 4, {{"out_fd", PT_FD, PF_DEC}, {"in_fd", PT_FD, PF_DEC}, {"offset", PT_UINT64, PF_DEC}, {"size", PT_UINT64, PF_DEC} } },
	{"sendfile", EC_IO_WRITE, EF_USES_FD | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"offset", PT_UINT64, PF_DEC} } },
	{"quotactl", EC_USER, EF_NONE, 4, {{"cmd", PT_FLAGS16, PF_DEC, quotactl_cmds }, {"type", PT_FLAGS8, PF_DEC, quotactl_types}, {"id", PT_UINT32, PF_DEC}, {"quota_fmt", PT_FLAGS8, PF_DEC, quotactl_quota_fmts } } },
	{"quotactl", EC_USER, EF_NONE, 14, {{"res", PT_ERRNO, PF_DEC}, {"special", PT_CHARBUF, PF_NA }, {"quotafilepath", PT_CHARBUF, PF_NA}, {"dqb_bhardlimit", PT_UINT64, PF_DEC }, {"dqb_bsoftlimit", PT_UINT64, PF_DEC }, {"dqb_curspace", PT_UINT64, PF_DEC }, {"dqb_ihardlimit", PT_UINT64, PF_DEC }, {"dqb_isoftlimit", PT_UINT64, PF_DEC }, {"dqb_btime", PT_RELTIME, PF_DEC }, {"dqb_itime", PT_RELTIME, PF_DEC }, {"dqi_bgrace", PT_RELTIME, PF_DEC }, {"dqi_igrace", PT_RELTIME, PF_DEC }, {"dqi_flags", PT_FLAGS8, PF_DEC, quotactl_dqi_flags }, {"quota_fmt_out", PT_FLAGS8, PF_DEC, quotactl_quota_fmts } } },
	{"setresuid", EC_USER, EF_MODIFIES_STATE, 3, {{"ruid", PT_UID, PF_DEC }, {"euid", PT_UID, PF_DEC }, {"suid", PT_UID, PF_DEC } } },
	{"setresuid", EC_USER, EF_MODIFIES_STATE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"setresgid", EC_USER, EF_MODIFIES_STATE, 3, {{"rgid", PT_GID, PF_DEC }, {"egid", PT_GID, PF_DEC }, {"sgid", PT_GID, PF_DEC } } },
	{"setresgid", EC_USER, EF_MODIFIES_STATE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"sysdigevent", EC_INTERNAL, EF_SKIPPARSERESET, 2, {{"event_type", PT_UINT32, PF_DEC}, {"event_data", PT_UINT64, PF_DEC} } },
	{"sysdigevent", EC_INTERNAL, EF_UNUSED, 0},
	{"setuid", EC_USER, EF_MODIFIES_STATE, 1, {{"uid", PT_UID, PF_DEC} } },
	{"setuid", EC_USER, EF_MODIFIES_STATE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"setgid", EC_USER, EF_MODIFIES_STATE, 1, {{"gid", PT_GID, PF_DEC} } },
	{"setgid", EC_USER, EF_MODIFIES_STATE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"getuid", EC_USER, EF_DROP_FALCO, 0},
	{"getuid", EC_USER, EF_DROP_FALCO, 1, {{"uid", PT_UID, PF_DEC} } },
	{"geteuid", EC_USER, EF_DROP_FALCO, 0 },
	{"geteuid", EC_USER, EF_DROP_FALCO, 1, {{"euid", PT_UID, PF_DEC} } },
	{"getgid", EC_USER, EF_DROP_FALCO, 0},
	{"getgid", EC_USER, EF_DROP_FALCO, 1, {{"gid", PT_GID, PF_DEC} } },
	{"getegid", EC_USER, EF_DROP_FALCO, 0 },
	{"getegid", EC_USER, EF_DROP_FALCO, 1, {{"egid", PT_GID, PF_DEC} } },
	{"getresuid", EC_USER, EF_DROP_FALCO, 0 },
	{"getresuid", EC_USER, EF_DROP_FALCO, 4, {{"res", PT_ERRNO, PF_DEC}, {"ruid", PT_UID, PF_DEC }, {"euid", PT_UID, PF_DEC }, {"suid", PT_UID, PF_DEC } } },
	{"getresgid", EC_USER, EF_DROP_FALCO, 0 },
	{"getresgid", EC_USER, EF_DROP_FALCO, 4, {{"res", PT_ERRNO, PF_DEC}, {"rgid", PT_GID, PF_DEC }, {"egid", PT_GID, PF_DEC }, {"sgid", PT_GID, PF_DEC } } },
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 15, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA} } },
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"clone", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"fork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"fork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC} } },
	{"clone", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"clone", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	{"fork", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"fork", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"vfork", EC_PROCESS, EF_MODIFIES_STATE, 20, {{"res", PT_PID, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_INT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, clone_flags}, {"uid", PT_UINT32, PF_DEC}, {"gid", PT_UINT32, PF_DEC}, {"vtid", PT_PID, PF_DEC}, {"vpid", PT_PID, PF_DEC} } },
	{"container", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 4, {{"id", PT_CHARBUF, PF_NA}, {"type", PT_UINT32, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"image", PT_CHARBUF, PF_NA} } },
	{"container", EC_INTERNAL, EF_UNUSED, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE, 16, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA} } },
	{"signaldeliver", EC_SIGNAL, EF_DROP_FALCO, 3, {{"spid", PT_PID, PF_DEC}, {"dpid", PT_PID, PF_DEC}, {"sig", PT_SIGTYPE, PF_DEC} } },
	{"signaldeliver", EC_SIGNAL, EF_UNUSED, 0 },
	{"procinfo", EC_INTERNAL, EF_SKIPPARSERESET | EF_DROP_FALCO, 2, {{"cpu_usr", PT_UINT64, PF_DEC}, {"cpu_sys", PT_UINT64, PF_DEC} } },
	{"NA2", EC_INTERNAL, EF_UNUSED, 0},
	{"getdents", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_NA} } },
	{"getdents", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"getdents64", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"fd", PT_FD, PF_NA} } },
	{"getdents64", EC_FILE, EF_USES_FD | EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"setns", EC_PROCESS, EF_USES_FD, 2, {{"fd", PT_FD, PF_NA}, {"nstype", PT_FLAGS32, PF_HEX, clone_flags} } },
	{"setns", EC_PROCESS, EF_USES_FD, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"flock", EC_FILE, EF_USES_FD, 2, {{"fd", PT_FD, PF_NA}, {"operation", PT_FLAGS32, PF_HEX, flock_flags} } },
	{"flock", EC_FILE, EF_USES_FD, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"cpu_hotplug", EC_SYSTEM, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 2, {{"cpu", PT_UINT32, PF_DEC}, {"action", PT_UINT32, PF_DEC} } },
	{"NA2", EC_SYSTEM, EF_UNUSED, 0},
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 1, {{"flags", PT_INT32, PF_HEX} } },
	{"accept", EC_NET, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA}, {"queuepct", PT_UINT8, PF_DEC}, {"queuelen", PT_UINT32, PF_DEC}, {"queuemax", PT_UINT32, PF_DEC} } },
	{"semop", EC_PROCESS, EF_DROP_FALCO, 1, {{"semid", PT_INT32, PF_DEC} } },
	{"semop", EC_PROCESS, EF_DROP_FALCO, 8, {{"res", PT_ERRNO, PF_DEC}, {"nsops", PT_UINT32, PF_DEC}, {"sem_num_0", PT_UINT16, PF_DEC}, {"sem_op_0", PT_INT16, PF_DEC}, {"sem_flg_0", PT_FLAGS16, PF_HEX, semop_flags}, {"sem_num_1", PT_UINT16, PF_DEC}, {"sem_op_1", PT_INT16, PF_DEC}, {"sem_flg_1", PT_FLAGS16, PF_HEX, semop_flags} } },
	{"semctl", EC_PROCESS, EF_DROP_FALCO, 4, {{"semid", PT_INT32, PF_DEC}, {"semnum", PT_INT32, PF_DEC}, {"cmd", PT_FLAGS16, PF_HEX, semctl_commands}, {"val", PT_INT32, PF_DEC} } },
	{"semctl", EC_PROCESS, EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"ppoll", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 3, {{"fds", PT_FDLIST, PF_DEC}, {"timeout", PT_RELTIME, PF_DEC}, {"sigmask", PT_SIGSET, PF_DEC} } },
	{"ppoll", EC_WAIT, EF_WAITS | EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"fds", PT_FDLIST, PF_DEC} } },
	{"mount", EC_FILE, EF_MODIFIES_STATE, 1, {{"flags", PT_FLAGS32, PF_HEX, mount_flags} } },
	{"mount", EC_FILE, EF_MODIFIES_STATE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dev", PT_CHARBUF, PF_NA}, {"dir", PT_FSPATH, PF_NA}, {"type", PT_CHARBUF, PF_NA} } },
	{"umount", EC_FILE, EF_MODIFIES_STATE, 1, {{"flags", PT_FLAGS32, PF_HEX, umount_flags} } },
	{"umount", EC_FILE, EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"name", PT_FSPATH, PF_NA} } },
	{"k8s", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },
	{"NA3", EC_SYSTEM, EF_UNUSED, 0},
	{"semget", EC_PROCESS, EF_DROP_FALCO, 3, {{"key", PT_INT32, PF_HEX}, {"nsems", PT_INT32, PF_DEC}, {"semflg", PT_FLAGS32, PF_HEX, semget_flags} } },
	{"semget", EC_PROCESS, EF_DROP_FALCO, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"access", EC_FILE, EF_DROP_FALCO, 1, {{"mode", PT_FLAGS32, PF_HEX, access_flags} } },
	{"access", EC_FILE, EF_DROP_FALCO, 2, {{"res", PT_ERRNO, PF_DEC}, {"name", PT_FSPATH, PF_NA} } },
	{"chroot", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"chroot", EC_PROCESS, EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"tracer", EC_OTHER, EF_NONE, 3, {{"id", PT_INT64, PF_DEC}, {"tags", PT_CHARBUFARRAY, PF_NA}, {"args", PT_CHARBUF_PAIR_ARRAY, PF_NA} } },
	{ "tracer", EC_OTHER, EF_NONE, 3, { { "id", PT_INT64, PF_DEC }, { "tags", PT_CHARBUFARRAY, PF_NA }, { "args", PT_CHARBUF_PAIR_ARRAY, PF_NA } } },
	{"mesos", EC_INTERNAL, EF_SKIPPARSERESET | EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },
	{"NA4", EC_SYSTEM, EF_UNUSED, 0},
	{"container", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"json", PT_CHARBUF, PF_NA} } },
	{"container", EC_PROCESS, EF_UNUSED, 0},
	{"setsid", EC_PROCESS, EF_MODIFIES_STATE, 0},
	{"setsid", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"res", PT_PID, PF_DEC} } },
	{"mkdir", EC_FILE, EF_NONE, 1, {{"mode", PT_UINT32, PF_HEX} } },
	{"mkdir", EC_FILE, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"rmdir", EC_FILE, EF_NONE, 0},
	{"rmdir", EC_FILE, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"notification", EC_OTHER, EF_SKIPPARSERESET, 2, {{"id", PT_CHARBUF, PF_DEC}, {"desc", PT_CHARBUF, PF_NA}, } },
	{"NA4", EC_SYSTEM, EF_UNUSED, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC} } },
	{"unshare", EC_PROCESS, EF_NONE, 1, {{"flags", PT_FLAGS32, PF_HEX, clone_flags} } },
	{"unshare", EC_PROCESS, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"infra", EC_INTERNAL, EF_SKIPPARSERESET, 4, {{"source", PT_CHARBUF, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"description", PT_CHARBUF, PF_NA}, {"scope", PT_CHARBUF, PF_NA} } },
	{"NA4", EC_SYSTEM, EF_UNUSED, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 1, {{"filename", PT_FSPATH, PF_NA} } },
	{"execve", EC_PROCESS, EF_MODIFIES_STATE | EF_OLD_VERSION, 17, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC} } },
	{"page_fault", EC_OTHER, EF_SKIPPARSERESET | EF_DROP_FALCO, 3, {{"addr", PT_UINT64, PF_HEX}, {"ip", PT_UINT64, PF_HEX}, {"error", PT_FLAGS32, PF_HEX, pf_flags} } },
	{"NA5", EC_OTHER, EF_UNUSED, 0},
	{"execve", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"filename", PT_FSPATH, PF_NA} } },
	{"execve", EC_PROCESS, EF_MODIFIES_STATE, 19, {{"res", PT_ERRNO, PF_DEC}, {"exe", PT_CHARBUF, PF_NA}, {"args", PT_BYTEBUF, PF_NA}, {"tid", PT_PID, PF_DEC}, {"pid", PT_PID, PF_DEC}, {"ptid", PT_PID, PF_DEC}, {"cwd", PT_CHARBUF, PF_NA}, {"fdlimit", PT_UINT64, PF_DEC}, {"pgft_maj", PT_UINT64, PF_DEC}, {"pgft_min", PT_UINT64, PF_DEC}, {"vm_size", PT_UINT32, PF_DEC}, {"vm_rss", PT_UINT32, PF_DEC}, {"vm_swap", PT_UINT32, PF_DEC}, {"comm", PT_CHARBUF, PF_NA}, {"cgroups", PT_BYTEBUF, PF_NA}, {"env", PT_BYTEBUF, PF_NA}, {"tty", PT_INT32, PF_DEC}, {"pgid", PT_PID, PF_DEC}, {"loginuid", PT_INT32, PF_DEC} } },
	{"setpgid", EC_PROCESS, EF_MODIFIES_STATE, 2, {{"pid", PT_PID, PF_DEC}, {"pgid", PT_PID, PF_DEC} } },
	{"setpgid", EC_PROCESS, EF_MODIFIES_STATE, 1, {{"res", PT_PID, PF_DEC} } },
	{"bpf", EC_OTHER, EF_CREATES_FD, 1, {{"cmd", PT_INT64, PF_DEC} } },
	{"bpf", EC_OTHER, EF_CREATES_FD, 1, {{"res_or_fd", PT_DYN, PF_DEC, bpf_dynamic_param, PPM_BPF_IDX_MAX} } },
	{"seccomp", EC_OTHER, EF_NONE, 1, {{"op", PT_UINT64, PF_DEC}, {"flags", PT_UINT64, PF_HEX} } },
	{"seccomp", EC_OTHER, EF_NONE, 1, {{"res", PT_ERRNO, PF_DEC} } },
	{"unlink", EC_FILE, EF_NONE, 0},
	{"unlink", EC_FILE, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"path", PT_FSPATH, PF_NA} } },
	{"unlinkat", EC_FILE, EF_NONE, 0},
	{"unlinkat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, unlinkat_flags} } },
	{"mkdirat", EC_FILE, EF_NONE, 0},
	{"mkdirat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"path", PT_FSPATH, PF_NA}, {"mode", PT_UINT32, PF_HEX} } },
	{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"fd", PT_FD, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },
	{"link", EC_FILE, EF_NONE, 0},
	{"link", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"oldpath", PT_FSPATH, PF_NA}, {"newpath", PT_FSPATH, PF_NA} } },
	{"linkat", EC_FILE, EF_NONE, 0},
	{"linkat", EC_FILE, EF_NONE, 6, {{"res", PT_ERRNO, PF_DEC}, {"olddir", PT_FD, PF_DEC}, {"oldpath", PT_CHARBUF, PF_NA}, {"newdir", PT_FD, PF_DEC}, {"newpath", PT_CHARBUF, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, linkat_flags} } },
	{"fchmodat", EC_FILE, EF_NONE, 0},
	{"fchmodat", EC_FILE, EF_NONE, 4, {{"res", PT_ERRNO, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"filename", PT_FSPATH, PF_NA}, {"mode", PT_MODE, PF_OCT, chmod_mode} } },
	{"chmod", EC_FILE, EF_NONE, 0},
	{"chmod", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"filename", PT_FSPATH, PF_NA}, {"mode", PT_MODE, PF_OCT, chmod_mode} } },
	{"fchmod", EC_FILE, EF_NONE, 0},
	{"fchmod", EC_FILE, EF_NONE, 3, {{"res", PT_ERRNO, PF_DEC}, {"fd", PT_FD, PF_DEC}, {"mode", PT_MODE, PF_OCT, chmod_mode} } }
};
*/
import "C"

func populateSyscallTableMap(module *elf.Module) error {
	log := logger.WithName("[popultae-syscall-table-map]")

	syscallTableMap := module.Map("syscall_table")

	for index, syscallEvent := range C.g_syscall_table {
		key := unsafe.Pointer(&index)
		value := unsafe.Pointer(&syscallEvent)

		err := module.UpdateElement(syscallTableMap, key, value, 0)
		if err != nil {
			log.Error(err, "failed to update syscall table map", "syscall-id", index)
			return err
		}
	}
	return nil
}

func populateFillerTableMap(module *elf.Module) error {
	log := logger.WithName("[populate-fillers-table-map]")

	fillersMap := module.Map("fillers_table")
	for index, ppmEvents := range C.g_ppm_events {
		//if ppmEvents.filler_id == 0 {
		//	continue
		//}
		//log.V(10).Info("update filler table", "key", index, "ppm eventes", ppmEvents)
		//spew.Dump(index, ppmEvents.filler_id)

		key := unsafe.Pointer(&index)
		value := unsafe.Pointer(&ppmEvents)

		err := module.UpdateElement(fillersMap, key, value, 0)
		if err != nil {
			log.Error(err, "error updating filler table map", "PPME_EVENT_ID", index)
			return err
		}
	}
	return nil
}

func populateEventTableMap(module *elf.Module) error {
	log := logger.WithName("[populate-event-table-map]")

	fillersMap := module.Map("event_info_table")
	for index, ppmEvents := range C.g_event_info {
		key := unsafe.Pointer(&index)
		value := unsafe.Pointer(&ppmEvents)

		err := module.UpdateElement(fillersMap, key, value, 0)
		if err != nil {
			log.Error(err, "error updating filler table map", "PPME_EVENT_ID", index)
			return err
		}
	}
	return nil
}

func getSyscallName(id int) string {
	return C.GoString(&C.g_event_info[id].name[0])
}
