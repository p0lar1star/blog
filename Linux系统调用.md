# Linux系统调用表

记录下来，免得到处找

## 32位 int 0x80

| %eax | Name                       | Source                      | %ebx                     | %ecx                         | %edx                    | %esx            | %edi             |
| ---- | -------------------------- | --------------------------- | ------------------------ | ---------------------------- | ----------------------- | --------------- | ---------------- |
| 1    | sys_exit                   | kernel/exit.c               | int                      | -                            | -                       | -               | -                |
| 2    | sys_fork                   | arch/i386/kernel/process.c  | struct pt_regs           | -                            | -                       | -               | -                |
| 3    | sys_read                   | fs/read_write.c             | unsigned int             | char *                       | size_t                  | -               | -                |
| 4    | sys_write                  | fs/read_write.c             | unsigned int             | const char *                 | size_t                  | -               | -                |
| 5    | sys_open                   | fs/open.c                   | const char *             | int                          | int                     | -               | -                |
| 6    | sys_close                  | fs/open.c                   | unsigned int             | -                            | -                       | -               | -                |
| 7    | sys_waitpid                | kernel/exit.c               | pid_t                    | unsigned int *               | int                     | -               | -                |
| 8    | sys_creat                  | fs/open.c                   | const char *             | int                          | -                       | -               | -                |
| 9    | sys_link                   | fs/namei.c                  | const char *             | const char *                 | -                       | -               | -                |
| 10   | sys_unlink                 | fs/namei.c                  | const char *             | -                            | -                       | -               | -                |
| 11   | sys_execve                 | arch/i386/kernel/process.c  | struct pt_regs           | -                            | -                       | -               | -                |
| 12   | sys_chdir                  | fs/open.c                   | const char *             | -                            | -                       | -               | -                |
| 13   | sys_time                   | kernel/time.c               | int *                    | -                            | -                       | -               | -                |
| 14   | sys_mknod                  | fs/namei.c                  | const char *             | int                          | dev_t                   | -               | -                |
| 15   | sys_chmod                  | fs/open.c                   | const char *             | mode_t                       | -                       | -               | -                |
| 16   | sys_lchown                 | fs/open.c                   | const char *             | uid_t                        | gid_t                   | -               | -                |
| 18   | sys_stat                   | fs/stat.c                   | char *                   | struct __old_kernel_stat *   | -                       | -               | -                |
| 19   | sys_lseek                  | fs/read_write.c             | unsigned int             | off_t                        | unsigned int            | -               | -                |
| 20   | sys_getpid                 | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 21   | sys_mount                  | fs/super.c                  | char *                   | char *                       | char *                  | -               | -                |
| 22   | sys_oldumount              | fs/super.c                  | char *                   | -                            | -                       | -               | -                |
| 23   | sys_setuid                 | kernel/sys.c                | uid_t                    | -                            | -                       | -               | -                |
| 24   | sys_getuid                 | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 25   | sys_stime                  | kernel/time.c               | int *                    | -                            | -                       | -               | -                |
| 26   | sys_ptrace                 | arch/i386/kernel/ptrace.c   | long                     | long                         | long                    | long            | -                |
| 27   | sys_alarm                  | kernel/sched.c              | unsigned int             | -                            | -                       | -               | -                |
| 28   | sys_fstat                  | fs/stat.c                   | unsigned int             | struct __old_kernel_stat *   | -                       | -               | -                |
| 29   | sys_pause                  | arch/i386/kernel/sys_i386.c | -                        | -                            | -                       | -               | -                |
| 30   | sys_utime                  | fs/open.c                   | char *                   | struct utimbuf *             | -                       | -               | -                |
| 33   | sys_access                 | fs/open.c                   | const char *             | int                          | -                       | -               | -                |
| 34   | sys_nice                   | kernel/sched.c              | int                      | -                            | -                       | -               | -                |
| 36   | sys_sync                   | fs/buffer.c                 | -                        | -                            | -                       | -               | -                |
| 37   | sys_kill                   | kernel/signal.c             | int                      | int                          | -                       | -               | -                |
| 38   | sys_rename                 | fs/namei.c                  | const char *             | const char *                 | -                       | -               | -                |
| 39   | sys_mkdir                  | fs/namei.c                  | const char *             | int                          | -                       | -               | -                |
| 40   | sys_rmdir                  | fs/namei.c                  | const char *             | -                            | -                       | -               | -                |
| 41   | sys_dup                    | fs/fcntl.c                  | unsigned int             | -                            | -                       | -               | -                |
| 42   | sys_pipe                   | arch/i386/kernel/sys_i386.c | unsigned long *          | -                            | -                       | -               | -                |
| 43   | sys_times                  | kernel/sys.c                | struct tms *             | -                            | -                       | -               | -                |
| 45   | sys_brk                    | mm/mmap.c                   | unsigned long            | -                            | -                       | -               | -                |
| 46   | sys_setgid                 | kernel/sys.c                | gid_t                    | -                            | -                       | -               | -                |
| 47   | sys_getgid                 | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 48   | sys_signal                 | kernel/signal.c             | int                      | __sighandler_t               | -                       | -               | -                |
| 49   | sys_geteuid                | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 50   | sys_getegid                | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 51   | sys_acct                   | kernel/acct.c               | const char *             | -                            | -                       | -               | -                |
| 52   | sys_umount                 | fs/super.c                  | char *                   | int                          | -                       | -               | -                |
| 54   | sys_ioctl                  | fs/ioctl.c                  | unsigned int             | unsigned int                 | unsigned long           | -               | -                |
| 55   | sys_fcntl                  | fs/fcntl.c                  | unsigned int             | unsigned int                 | unsigned long           | -               | -                |
| 57   | sys_setpgid                | kernel/sys.c                | pid_t                    | pid_t                        | -                       | -               | -                |
| 59   | sys_olduname               | arch/i386/kernel/sys_i386.c | struct oldold_utsname *  | -                            | -                       | -               | -                |
| 60   | sys_umask                  | kernel/sys.c                | int                      | -                            | -                       | -               | -                |
| 61   | sys_chroot                 | fs/open.c                   | const char *             | -                            | -                       | -               | -                |
| 62   | sys_ustat                  | fs/super.c                  | dev_t                    | struct ustat *               | -                       | -               | -                |
| 63   | sys_dup2                   | fs/fcntl.c                  | unsigned int             | unsigned int                 | -                       | -               | -                |
| 64   | sys_getppid                | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 65   | sys_getpgrp                | kernel/sys.c                | -                        | -                            | -                       | -               | -                |
| 66   | sys_setsid                 | kernel/sys.c                | -                        | -                            | -                       | -               | -                |
| 67   | sys_sigaction              | arch/i386/kernel/signal.c   | int                      | const struct old_sigaction * | struct old_sigaction *  | -               | -                |
| 68   | sys_sgetmask               | kernel/signal.c             | -                        | -                            | -                       | -               | -                |
| 69   | sys_ssetmask               | kernel/signal.c             | int                      | -                            | -                       | -               | -                |
| 70   | sys_setreuid               | kernel/sys.c                | uid_t                    | uid_t                        | -                       | -               | -                |
| 71   | sys_setregid               | kernel/sys.c                | gid_t                    | gid_t                        | -                       | -               | -                |
| 72   | sys_sigsuspend             | arch/i386/kernel/signal.c   | int                      | int                          | old_sigset_t            | -               | -                |
| 73   | sys_sigpending             | kernel/signal.c             | old_sigset_t *           | -                            | -                       | -               | -                |
| 74   | sys_sethostname            | kernel/sys.c                | char *                   | int                          | -                       | -               | -                |
| 75   | sys_setrlimit              | kernel/sys.c                | unsigned int             | struct rlimit *              | -                       | -               | -                |
| 76   | sys_getrlimit              | kernel/sys.c                | unsigned int             | struct rlimit *              | -                       | -               | -                |
| 77   | sys_getrusage              | kernel/sys.c                | int                      | struct rusage *              | -                       | -               | -                |
| 78   | sys_gettimeofday           | kernel/time.c               | struct timeval *         | struct timezone *            | -                       | -               | -                |
| 79   | sys_settimeofday           | kernel/time.c               | struct timeval *         | struct timezone *            | -                       | -               | -                |
| 80   | sys_getgroups              | kernel/sys.c                | int                      | gid_t *                      | -                       | -               | -                |
| 81   | sys_setgroups              | kernel/sys.c                | int                      | gid_t *                      | -                       | -               | -                |
| 82   | old_select                 | arch/i386/kernel/sys_i386.c | struct sel_arg_struct *  | -                            | -                       | -               | -                |
| 83   | sys_symlink                | fs/namei.c                  | const char *             | const char *                 | -                       | -               | -                |
| 84   | sys_lstat                  | fs/stat.c                   | char *                   | struct __old_kernel_stat *   | -                       | -               | -                |
| 85   | sys_readlink               | fs/stat.c                   | const char *             | char *                       | int                     | -               | -                |
| 86   | sys_uselib                 | fs/exec.c                   | const char *             | -                            | -                       | -               | -                |
| 87   | sys_swapon                 | mm/swapfile.c               | const char *             | int                          | -                       | -               | -                |
| 88   | sys_reboot                 | kernel/sys.c                | int                      | int                          | int                     | void *          | -                |
| 89   | old_readdir                | fs/readdir.c                | unsigned int             | void *                       | unsigned int            | -               | -                |
| 90   | old_mmap                   | arch/i386/kernel/sys_i386.c | struct mmap_arg_struct * | -                            | -                       | -               | -                |
| 91   | sys_munmap                 | mm/mmap.c                   | unsigned long            | size_t                       | -                       | -               | -                |
| 92   | sys_truncate               | fs/open.c                   | const char *             | unsigned long                | -                       | -               | -                |
| 93   | sys_ftruncate              | fs/open.c                   | unsigned int             | unsigned long                | -                       | -               | -                |
| 94   | sys_fchmod                 | fs/open.c                   | unsigned int             | mode_t                       | -                       | -               | -                |
| 95   | sys_fchown                 | fs/open.c                   | unsigned int             | uid_t                        | gid_t                   | -               | -                |
| 96   | sys_getpriority            | kernel/sys.c                | int                      | int                          | -                       | -               | -                |
| 97   | sys_setpriority            | kernel/sys.c                | int                      | int                          | int                     | -               | -                |
| 99   | sys_statfs                 | fs/open.c                   | const char *             | struct statfs *              | -                       | -               | -                |
| 100  | sys_fstatfs                | fs/open.c                   | unsigned int             | struct statfs *              | -                       | -               | -                |
| 101  | sys_ioperm                 | arch/i386/kernel/ioport.c   | unsigned long            | unsigned long                | int                     | -               | -                |
| 102  | sys_socketcall             | net/socket.c                | int                      | unsigned long *              | -                       | -               | -                |
| 103  | sys_syslog                 | kernel/printk.c             | int                      | char *                       | int                     | -               | -                |
| 104  | sys_setitimer              | kernel/itimer.c             | int                      | struct itimerval *           | struct itimerval *      | -               | -                |
| 105  | sys_getitimer              | kernel/itimer.c             | int                      | struct itimerval *           | -                       | -               | -                |
| 106  | sys_newstat                | fs/stat.c                   | char *                   | struct stat *                | -                       | -               | -                |
| 107  | sys_newlstat               | fs/stat.c                   | char *                   | struct stat *                | -                       | -               | -                |
| 108  | sys_newfstat               | fs/stat.c                   | unsigned int             | struct stat *                | -                       | -               | -                |
| 109  | sys_uname                  | arch/i386/kernel/sys_i386.c | struct old_utsname *     | -                            | -                       | -               | -                |
| 110  | sys_iopl                   | arch/i386/kernel/ioport.c   | unsigned long            | -                            | -                       | -               | -                |
| 111  | sys_vhangup                | fs/open.c                   | -                        | -                            | -                       | -               | -                |
| 112  | sys_idle                   | arch/i386/kernel/process.c  | -                        | -                            | -                       | -               | -                |
| 113  | sys_vm86old                | arch/i386/kernel/vm86.c     | unsigned long            | struct vm86plus_struct *     | -                       | -               | -                |
| 114  | sys_wait4                  | kernel/exit.c               | pid_t                    | unsigned long *              | int options             | struct rusage * | -                |
| 115  | sys_swapoff                | mm/swapfile.c               | const char *             | -                            | -                       | -               | -                |
| 116  | sys_sysinfo                | kernel/info.c               | struct sysinfo *         | -                            | -                       | -               | -                |
| 117  | sys_ipc (*Note)            | arch/i386/kernel/sys_i386.c | uint                     | int                          | int                     | int             | void *           |
| 118  | sys_fsync                  | fs/buffer.c                 | unsigned int             | -                            | -                       | -               | -                |
| 119  | sys_sigreturn              | arch/i386/kernel/signal.c   | unsigned long            | -                            | -                       | -               | -                |
| 120  | sys_clone                  | arch/i386/kernel/process.c  | struct pt_regs           | -                            | -                       | -               | -                |
| 121  | sys_setdomainname          | kernel/sys.c                | char *                   | int                          | -                       | -               | -                |
| 122  | sys_newuname               | kernel/sys.c                | struct new_utsname *     | -                            | -                       | -               | -                |
| 123  | sys_modify_ldt             | arch/i386/kernel/ldt.c      | int                      | void *                       | unsigned long           | -               | -                |
| 124  | sys_adjtimex               | kernel/time.c               | struct timex *           | -                            | -                       | -               | -                |
| 125  | sys_mprotect               | mm/mprotect.c               | unsigned long            | size_t                       | unsigned long           | -               | -                |
| 126  | sys_sigprocmask            | kernel/signal.c             | int                      | old_sigset_t *               | old_sigset_t *          | -               | -                |
| 127  | sys_create_module          | kernel/module.c             | const char *             | size_t                       | -                       | -               | -                |
| 128  | sys_init_module            | kernel/module.c             | const char *             | struct module *              | -                       | -               | -                |
| 129  | sys_delete_module          | kernel/module.c             | const char *             | -                            | -                       | -               | -                |
| 130  | sys_get_kernel_syms        | kernel/module.c             | struct kernel_sym *      | -                            | -                       | -               | -                |
| 131  | sys_quotactl               | fs/dquot.c                  | int                      | const char *                 | int                     | caddr_t         | -                |
| 132  | sys_getpgid                | kernel/sys.c                | pid_t                    | -                            | -                       | -               | -                |
| 133  | sys_fchdir                 | fs/open.c                   | unsigned int             | -                            | -                       | -               | -                |
| 134  | sys_bdflush                | fs/buffer.c                 | int                      | long                         | -                       | -               | -                |
| 135  | sys_sysfs                  | fs/super.c                  | int                      | unsigned long                | unsigned long           | -               | -                |
| 136  | sys_personality            | kernel/exec_domain.c        | unsigned long            | -                            | -                       | -               | -                |
| 138  | sys_setfsuid               | kernel/sys.c                | uid_t                    | -                            | -                       | -               | -                |
| 139  | sys_setfsgid               | kernel/sys.c                | gid_t                    | -                            | -                       | -               | -                |
| 140  | sys_llseek                 | fs/read_write.c             | unsigned int             | unsigned long                | unsigned long           | loff_t *        | unsigned int     |
| 141  | sys_getdents               | fs/readdir.c                | unsigned int             | void *                       | unsigned int            | -               | -                |
| 142  | sys_select                 | fs/select.c                 | int                      | fd_set *                     | fd_set *                | fd_set *        | struct timeval * |
| 143  | sys_flock                  | fs/locks.c                  | unsigned int             | unsigned int                 | -                       | -               | -                |
| 144  | sys_msync                  | mm/filemap.c                | unsigned long            | size_t                       | int                     | -               | -                |
| 145  | sys_readv                  | fs/read_write.c             | unsigned long            | const struct iovec *         | unsigned long           | -               | -                |
| 146  | sys_writev                 | fs/read_write.c             | unsigned long            | const struct iovec *         | unsigned long           | -               | -                |
| 147  | sys_getsid                 | kernel/sys.c                | pid_t                    | -                            | -                       | -               | -                |
| 148  | sys_fdatasync              | fs/buffer.c                 | unsigned int             | -                            | -                       | -               | -                |
| 149  | sys_sysctl                 | kernel/sysctl.c             | struct __sysctl_args *   | -                            | -                       | -               | -                |
| 150  | sys_mlock                  | mm/mlock.c                  | unsigned long            | size_t                       | -                       | -               | -                |
| 151  | sys_munlock                | mm/mlock.c                  | unsigned long            | size_t                       | -                       | -               | -                |
| 152  | sys_mlockall               | mm/mlock.c                  | int                      | -                            | -                       | -               | -                |
| 153  | sys_munlockall             | mm/mlock.c                  | -                        | -                            | -                       | -               | -                |
| 154  | sys_sched_setparam         | kernel/sched.c              | pid_t                    | struct sched_param *         | -                       | -               | -                |
| 155  | sys_sched_getparam         | kernel/sched.c              | pid_t                    | struct sched_param *         | -                       | -               | -                |
| 156  | sys_sched_setscheduler     | kernel/sched.c              | pid_t                    | int                          | struct sched_param *    | -               | -                |
| 157  | sys_sched_getscheduler     | kernel/sched.c              | pid_t                    | -                            | -                       | -               | -                |
| 158  | sys_sched_yield            | kernel/sched.c              | -                        | -                            | -                       | -               | -                |
| 159  | sys_sched_get_priority_max | kernel/sched.c              | int                      | -                            | -                       | -               | -                |
| 160  | sys_sched_get_priority_min | kernel/sched.c              | int                      | -                            | -                       | -               | -                |
| 161  | sys_sched_rr_get_interval  | kernel/sched.c              | pid_t                    | struct timespec *            | -                       | -               | -                |
| 162  | sys_nanosleep              | kernel/sched.c              | struct timespec *        | struct timespec *            | -                       | -               | -                |
| 163  | sys_mremap                 | mm/mremap.c                 | unsigned long            | unsigned long                | unsigned long           | unsigned long   | -                |
| 164  | sys_setresuid              | kernel/sys.c                | uid_t                    | uid_t                        | uid_t                   | -               | -                |
| 165  | sys_getresuid              | kernel/sys.c                | uid_t *                  | uid_t *                      | uid_t *                 | -               | -                |
| 166  | sys_vm86                   | arch/i386/kernel/vm86.c     | struct vm86_struct *     | -                            | -                       | -               | -                |
| 167  | sys_query_module           | kernel/module.c             | const char *             | int                          | char *                  | size_t          | size_t *         |
| 168  | sys_poll                   | fs/select.c                 | struct pollfd *          | unsigned int                 | long                    | -               | -                |
| 169  | sys_nfsservctl             | fs/filesystems.c            | int                      | void *                       | void *                  | -               | -                |
| 170  | sys_setresgid              | kernel/sys.c                | gid_t                    | gid_t                        | gid_t                   | -               | -                |
| 171  | sys_getresgid              | kernel/sys.c                | gid_t *                  | gid_t *                      | gid_t *                 | -               | -                |
| 172  | sys_prctl                  | kernel/sys.c                | int                      | unsigned long                | unsigned long           | unsigned long   | unsigned long    |
| 173  | sys_rt_sigreturn           | arch/i386/kernel/signal.c   | unsigned long            | -                            | -                       | -               | -                |
| 174  | sys_rt_sigaction           | kernel/signal.c             | int                      | const struct sigaction *     | struct sigaction *      | size_t          | -                |
| 175  | sys_rt_sigprocmask         | kernel/signal.c             | int                      | sigset_t *                   | sigset_t *              | size_t          | -                |
| 176  | sys_rt_sigpending          | kernel/signal.c             | sigset_t *               | size_t                       | -                       | -               | -                |
| 177  | sys_rt_sigtimedwait        | kernel/signal.c             | const sigset_t *         | siginfo_t *                  | const struct timespec * | size_t          | -                |
| 178  | sys_rt_sigqueueinfo        | kernel/signal.c             | int                      | int                          | siginfo_t *             | -               | -                |
| 179  | sys_rt_sigsuspend          | arch/i386/kernel/signal.c   | sigset_t *               | size_t                       | -                       | -               | -                |
| 180  | sys_pread                  | fs/read_write.c             | unsigned int             | char *                       | size_t                  | loff_t          | -                |
| 181  | sys_pwrite                 | fs/read_write.c             | unsigned int             | const char *                 | size_t                  | loff_t          | -                |
| 182  | sys_chown                  | fs/open.c                   | const char *             | uid_t                        | gid_t                   | -               | -                |
| 183  | sys_getcwd                 | fs/dcache.c                 | char *                   | unsigned long                | -                       | -               | -                |
| 184  | sys_capget                 | kernel/capability.c         | cap_user_header_t        | cap_user_data_t              | -                       | -               | -                |
| 185  | sys_capset                 | kernel/capability.c         | cap_user_header_t        | const cap_user_data_t        | -                       | -               | -                |
| 186  | sys_sigaltstack            | arch/i386/kernel/signal.c   | const stack_t *          | stack_t *                    | -                       | -               | -                |
| 187  | sys_sendfile               | mm/filemap.c                | int                      | int                          | off_t *                 | size_t          | -                |
| 190  | sys_vfork                  | arch/i386/kernel/process.c  | struct pt_regs           | -                            | -                       |                 |                  |

## 64位 syscall

```
#ifndef _ASM_X86_UNISTD_64_H
#define _ASM_X86_UNISTD_64_H 1
 
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_stat 4
#define __NR_fstat 5
#define __NR_lstat 6
#define __NR_poll 7
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_munmap 11
#define __NR_brk 12
#define __NR_rt_sigaction 13
#define __NR_rt_sigprocmask 14
#define __NR_rt_sigreturn 15
#define __NR_ioctl 16
#define __NR_pread64 17
#define __NR_pwrite64 18
#define __NR_readv 19
#define __NR_writev 20
#define __NR_access 21
#define __NR_pipe 22
#define __NR_select 23
#define __NR_sched_yield 24
#define __NR_mremap 25
#define __NR_msync 26
#define __NR_mincore 27
#define __NR_madvise 28
#define __NR_shmget 29
#define __NR_shmat 30
#define __NR_shmctl 31
#define __NR_dup 32
#define __NR_dup2 33
#define __NR_pause 34
#define __NR_nanosleep 35
#define __NR_getitimer 36
#define __NR_alarm 37
#define __NR_setitimer 38
#define __NR_getpid 39
#define __NR_sendfile 40
#define __NR_socket 41
#define __NR_connect 42
#define __NR_accept 43
#define __NR_sendto 44
#define __NR_recvfrom 45
#define __NR_sendmsg 46
#define __NR_recvmsg 47
#define __NR_shutdown 48
#define __NR_bind 49
#define __NR_listen 50
#define __NR_getsockname 51
#define __NR_getpeername 52
#define __NR_socketpair 53
#define __NR_setsockopt 54
#define __NR_getsockopt 55
#define __NR_clone 56
#define __NR_fork 57
#define __NR_vfork 58
#define __NR_execve 59
#define __NR_exit 60
#define __NR_wait4 61
#define __NR_kill 62
#define __NR_uname 63
#define __NR_semget 64
#define __NR_semop 65
#define __NR_semctl 66
#define __NR_shmdt 67
#define __NR_msgget 68
#define __NR_msgsnd 69
#define __NR_msgrcv 70
#define __NR_msgctl 71
#define __NR_fcntl 72
#define __NR_flock 73
#define __NR_fsync 74
#define __NR_fdatasync 75
#define __NR_truncate 76
#define __NR_ftruncate 77
#define __NR_getdents 78
#define __NR_getcwd 79
#define __NR_chdir 80
#define __NR_fchdir 81
#define __NR_rename 82
#define __NR_mkdir 83
#define __NR_rmdir 84
#define __NR_creat 85
#define __NR_link 86
#define __NR_unlink 87
#define __NR_symlink 88
#define __NR_readlink 89
#define __NR_chmod 90
#define __NR_fchmod 91
#define __NR_chown 92
#define __NR_fchown 93
#define __NR_lchown 94
#define __NR_umask 95
#define __NR_gettimeofday 96
#define __NR_getrlimit 97
#define __NR_getrusage 98
#define __NR_sysinfo 99
#define __NR_times 100
#define __NR_ptrace 101
#define __NR_getuid 102
#define __NR_syslog 103
#define __NR_getgid 104
#define __NR_setuid 105
#define __NR_setgid 106
#define __NR_geteuid 107
#define __NR_getegid 108
#define __NR_setpgid 109
#define __NR_getppid 110
#define __NR_getpgrp 111
#define __NR_setsid 112
#define __NR_setreuid 113
#define __NR_setregid 114
#define __NR_getgroups 115
#define __NR_setgroups 116
#define __NR_setresuid 117
#define __NR_getresuid 118
#define __NR_setresgid 119
#define __NR_getresgid 120
#define __NR_getpgid 121
#define __NR_setfsuid 122
#define __NR_setfsgid 123
#define __NR_getsid 124
#define __NR_capget 125
#define __NR_capset 126
#define __NR_rt_sigpending 127
#define __NR_rt_sigtimedwait 128
#define __NR_rt_sigqueueinfo 129
#define __NR_rt_sigsuspend 130
#define __NR_sigaltstack 131
#define __NR_utime 132
#define __NR_mknod 133
#define __NR_uselib 134
#define __NR_personality 135
#define __NR_ustat 136
#define __NR_statfs 137
#define __NR_fstatfs 138
#define __NR_sysfs 139
#define __NR_getpriority 140
#define __NR_setpriority 141
#define __NR_sched_setparam 142
#define __NR_sched_getparam 143
#define __NR_sched_setscheduler 144
#define __NR_sched_getscheduler 145
#define __NR_sched_get_priority_max 146
#define __NR_sched_get_priority_min 147
#define __NR_sched_rr_get_interval 148
#define __NR_mlock 149
#define __NR_munlock 150
#define __NR_mlockall 151
#define __NR_munlockall 152
#define __NR_vhangup 153
#define __NR_modify_ldt 154
#define __NR_pivot_root 155
#define __NR__sysctl 156
#define __NR_prctl 157
#define __NR_arch_prctl 158
#define __NR_adjtimex 159
#define __NR_setrlimit 160
#define __NR_chroot 161
#define __NR_sync 162
#define __NR_acct 163
#define __NR_settimeofday 164
#define __NR_mount 165
#define __NR_umount2 166
#define __NR_swapon 167
#define __NR_swapoff 168
#define __NR_reboot 169
#define __NR_sethostname 170
#define __NR_setdomainname 171
#define __NR_iopl 172
#define __NR_ioperm 173
#define __NR_create_module 174
#define __NR_init_module 175
#define __NR_delete_module 176
#define __NR_get_kernel_syms 177
#define __NR_query_module 178
#define __NR_quotactl 179
#define __NR_nfsservctl 180
#define __NR_getpmsg 181
#define __NR_putpmsg 182
#define __NR_afs_syscall 183
#define __NR_tuxcall 184
#define __NR_security 185
#define __NR_gettid 186
#define __NR_readahead 187
#define __NR_setxattr 188
#define __NR_lsetxattr 189
#define __NR_fsetxattr 190
#define __NR_getxattr 191
#define __NR_lgetxattr 192
#define __NR_fgetxattr 193
#define __NR_listxattr 194
#define __NR_llistxattr 195
#define __NR_flistxattr 196
#define __NR_removexattr 197
#define __NR_lremovexattr 198
#define __NR_fremovexattr 199
#define __NR_tkill 200
#define __NR_time 201
#define __NR_futex 202
#define __NR_sched_setaffinity 203
#define __NR_sched_getaffinity 204
#define __NR_set_thread_area 205
#define __NR_io_setup 206
#define __NR_io_destroy 207
#define __NR_io_getevents 208
#define __NR_io_submit 209
#define __NR_io_cancel 210
#define __NR_get_thread_area 211
#define __NR_lookup_dcookie 212
#define __NR_epoll_create 213
#define __NR_epoll_ctl_old 214
#define __NR_epoll_wait_old 215
#define __NR_remap_file_pages 216
#define __NR_getdents64 217
#define __NR_set_tid_address 218
#define __NR_restart_syscall 219
#define __NR_semtimedop 220
#define __NR_fadvise64 221
#define __NR_timer_create 222
#define __NR_timer_settime 223
#define __NR_timer_gettime 224
#define __NR_timer_getoverrun 225
#define __NR_timer_delete 226
#define __NR_clock_settime 227
#define __NR_clock_gettime 228
#define __NR_clock_getres 229
#define __NR_clock_nanosleep 230
#define __NR_exit_group 231
#define __NR_epoll_wait 232
#define __NR_epoll_ctl 233
#define __NR_tgkill 234
#define __NR_utimes 235
#define __NR_vserver 236
#define __NR_mbind 237
#define __NR_set_mempolicy 238
#define __NR_get_mempolicy 239
#define __NR_mq_open 240
#define __NR_mq_unlink 241
#define __NR_mq_timedsend 242
#define __NR_mq_timedreceive 243
#define __NR_mq_notify 244
#define __NR_mq_getsetattr 245
#define __NR_kexec_load 246
#define __NR_waitid 247
#define __NR_add_key 248
#define __NR_request_key 249
#define __NR_keyctl 250
#define __NR_ioprio_set 251
#define __NR_ioprio_get 252
#define __NR_inotify_init 253
#define __NR_inotify_add_watch 254
#define __NR_inotify_rm_watch 255
#define __NR_migrate_pages 256
#define __NR_openat 257
#define __NR_mkdirat 258
#define __NR_mknodat 259
#define __NR_fchownat 260
#define __NR_futimesat 261
#define __NR_newfstatat 262
#define __NR_unlinkat 263
#define __NR_renameat 264
#define __NR_linkat 265
#define __NR_symlinkat 266
#define __NR_readlinkat 267
#define __NR_fchmodat 268
#define __NR_faccessat 269
#define __NR_pselect6 270
#define __NR_ppoll 271
#define __NR_unshare 272
#define __NR_set_robust_list 273
#define __NR_get_robust_list 274
#define __NR_splice 275
#define __NR_tee 276
#define __NR_sync_file_range 277
#define __NR_vmsplice 278
#define __NR_move_pages 279
#define __NR_utimensat 280
#define __NR_epoll_pwait 281
#define __NR_signalfd 282
#define __NR_timerfd_create 283
#define __NR_eventfd 284
#define __NR_fallocate 285
#define __NR_timerfd_settime 286
#define __NR_timerfd_gettime 287
#define __NR_accept4 288
#define __NR_signalfd4 289
#define __NR_eventfd2 290
#define __NR_epoll_create1 291
#define __NR_dup3 292
#define __NR_pipe2 293
#define __NR_inotify_init1 294
#define __NR_preadv 295
#define __NR_pwritev 296
#define __NR_rt_tgsigqueueinfo 297
#define __NR_perf_event_open 298
#define __NR_recvmmsg 299
#define __NR_fanotify_init 300
#define __NR_fanotify_mark 301
#define __NR_prlimit64 302
#define __NR_name_to_handle_at 303
#define __NR_open_by_handle_at 304
#define __NR_clock_adjtime 305
#define __NR_syncfs 306
#define __NR_sendmmsg 307
#define __NR_setns 308
#define __NR_getcpu 309
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311
#define __NR_kcmp 312
#define __NR_finit_module 313
#define __NR_sched_setattr 314
#define __NR_sched_getattr 315
#define __NR_renameat2 316
#define __NR_memfd_create 319
#define __NR_kexec_file_load 320
#define __NR_userfaultfd 323
 
#endif /* _ASM_X86_UNISTD_64_H */
```