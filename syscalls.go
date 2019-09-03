package main

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

/*

#include <linux/unistd.h>

#define SYSCALL_TABLE_ID0 0
#define SYSCALL_TABLE_SIZE 512

#define _packed __attribute__((packed))

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
