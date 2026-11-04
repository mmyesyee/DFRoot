// Symbolic constants for Linux/ARM (EABI), Thumb-2 shellcode.
// NOTE: 32-bit ARM uses the *legacy* syscall table — none of the numbers
//       match AArch64 (getuid is 199 here, not 174).

    .equ SIGCHLD,              17

    // sched.h
    .equ CSIGNAL,              0x000000FF
    .equ CLONE_VM,             0x00000100
    .equ CLONE_FS,             0x00000200
    .equ CLONE_FILES,          0x00000400
    .equ CLONE_SIGHAND,        0x00000800
    .equ CLONE_VFORK,          0x00004000
    .equ CLONE_PARENT,         0x00008000
    .equ CLONE_THREAD,         0x00010000
    .equ CLONE_SETTLS,         0x00080000
    .equ CLONE_PARENT_SETTID,  0x00100000
    .equ CLONE_CHILD_CLEARTID, 0x00200000
    .equ CLONE_DETACHED,       0x00400000
    .equ CLONE_UNTRACED,       0x00800000
    .equ CLONE_CHILD_SETTID,   0x01000000
    .equ CLONE_NEWCGROUP,      0x02000000

    // fcntl.h
    .equ O_RDONLY,             0
    .equ O_WRONLY,             1
    .equ O_RDWR,               2
    .equ O_CREAT,           0x40        // 00000100
    .equ O_EXCL,            0x80        // 00000200
    .equ O_TRUNC,          0x200        // 00001000
    .equ O_APPEND,         0x400        // 00002000
    .equ O_CLOEXEC,      0x80000        // 02000000

    .equ AT_FDCWD,            -100

    // ARM EABI (o32) syscall numbers
    .equ SYS_fork,              2
    .equ SYS_read,              3
    .equ SYS_write,             4
    .equ SYS_open,              5
    .equ SYS_close,             6
    .equ SYS_execve,           11
    .equ SYS_dup2,             63
    .equ SYS_lseek,            19
    .equ SYS_getpid,           20
    .equ SYS_clone,           120
    .equ SYS_getuid,          199
    .equ SYS_getgid,          200
    .equ SYS_gettid,          224
    .equ SYS_exit_group,      248
    .equ SYS_openat,          322
    .equ SYS_splice,          340
    .equ SYS_finit_module,    379
