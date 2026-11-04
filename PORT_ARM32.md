# DFRoot on arm32 userspace (arm64 kernel)

Scenario B: kernel is AArch64, userspace is 32-bit only (Android Go / 32-bit
userland builds). `uname -m` may report `aarch64`/`armv8l`; `/system/lib64` is
absent, `zygote` is 32-bit, every patched file lives under `/system/lib`.

## Design rule

| piece | arch | why |
|---|---|---|
| `dfroot.ko` | **arm64** | loaded by the kernel; DDK builds stay untouched |
| `splicehelper` | **arm32** | replaces the page cache of `crash_dump32`, which the kernel execs as ELF32 |
| `libcxx` payload | **arm32** | hooked function lives in the 32-bit `libc++.so` |
| trampoline branch | **Thumb-2 `B.W`** | Android arm32 libs are Thumb-2 |
| `libdfroot.so`, `bootstrap` | arm32 | app ABI = userspace ABI |

`kCrashDump` follow the *target* bitness, not the app's: it must be
`crash_dump32` because that is the binary we splice the helper into.

## Changes

### `libcxx32.S` (new) + `include32.inc` (new)

Thumb-2 rewrite of `libcxx.S`. Same payload logic, different ISA:

- ARM EABI calling for `svc`: syscall number in `r7`, args `r0..r5`, `svc #0`.
- **Legacy syscall numbers** — `getuid=199`, `gettid=224`, `clone=120`,
  `execve=11`, `write=4`, `openat=322`, `exit_group=248`. None of them match
  AArch64 (174/178/220/221/64/56/93/76).
- `clone` on ARM is `clone(flags, stack, ptid, tls, ctid)` in `r0..r4`;
  `stack = 0` gives fork semantics, same trick as the A64 version.
- Immediate materialisation uses `movw`/`movt` instead of `movz`/`movk`;
  `AT_FDCWD` is built with `mvn r0, #~AT_FDCWD` (no 16-bit `mov` of `-100`).
- Registers are preserved with `push {r0-r7, lr}` / `pop {r0-r7, lr}` and the
  entry falls through into the patched "stolen instruction" slot, exactly like
  the A64 blob, so the hooked function keeps running after the payload.
- Added `/system/bin/insmod` as a fallback after `/vendor/bin/insmod`:
  32-bit builds often only ship toybox `insmod`.

Current size: **350 bytes** (blob layout: data @ +0x00, code @ +0xa0,
stolen-instruction slot @ +0x156, patched jump-back @ +0x15a).

### `elf_parser.c`

- `EI_CLASS` dispatch: `Elf32_*` / `Elf64_*` paths share one flow.
- 32-bit thumb functions carry `st_value & 1`; it is stripped for the offset
  computation and returned via a new `thumb` out-parameter.
- Cave placement is rounded up to 16 bytes, because the page-cache primitive
  patches whole 16-byte CBC blocks (`shell_off` is used as the block base).
  Also refuses slots that would cross a page boundary or run past EOF.
- Thumb hops reject a 16-bit prologue: the trampoline is a 4-byte `B.W`, so the
  stolen instruction must be 4 bytes. (`push.w {r4-r11,lr}` is, in practice.)

### `exp.c`

- `DF_TARGET32` selects `crash_dump32` + `/system/lib/libc++.so`, and the
  `/vendor/lib/...` KO staging candidates.
- Branch encoding is now arch-aware:
  - A64 → `B imm26` (unchanged semantics),
  - Thumb-2 → `B.W T4` with `S/I1/I2/imm10/imm11` and PC = insn + 4,
  - ARM → `B imm24` with PC = insn + 8.
- `jmpback` returns to `hook_off + insn_len` instead of hardcoded `+4`.
- The trampoline patch now handles block straddling: if `hook_off & 15 > 12`
  the aligned 32-byte pair is patched and saved in `PatchRestore` (
  `tramp_orig[32]`, `tramp_len`), so restore is symmetric.

### `splicehelper.c`

`__arm__` path uses register-constrained inline asm (`r0..r5`, `r7`) instead of
the A64 naked functions; `off_arg_t` degrades to a 32-bit offset (all patched
files are well under 2 GB).

### `CMakeLists.txt`

- `SHELLCODE_ASM` is picked by `ANDROID_ABI` (`libcxx32.S` for `armeabi-v7a`),
  and `max-page-size` becomes 4096 there.
- `splicehelper` is compiled with `-O2 -fomit-frame-pointer` — required on
  arm32 because `r7` is the syscall register and must not be the frame pointer.

## Verified in this sandbox

| check | result |
|---|---|
| `libcxx32.S` assembles (clang IAS + GNU as, armv7-a/thumb) | ok, 350 B |
| blob layout / `libcxx_len` / `libcxx_first_inst_copy` offsets | data 0x00, code 0xa0, slot 0x156, branch 0x15a, len 0x15e |
| `B.W` encoder vs `arm-linux-gnueabi-objdump` (8 cases incl. ±16 MB edges) | all targets exact |
| ELF32 parser on a synthetic thumb .so | `hook=0x1080 payload=0x1200 insn=0x4ff0e92d thumb=1` |
| full arm32 link of `libdfroot.so` (`exp.c`+`libcxx32.S`+`elf_parser.c`) | ok, `Machine: ARM`, `ELF32` |
| aarch64 objects still compile | ok (unchanged behaviour) |

## Verified on hardware

Xiaomi Watch 2 Pro, Wear OS / Android 14, kernel `5.15.167-android14-11-maybe-dirty`,
`uname -m` = `armv8l`, `abilist` = `armeabi-v7a,armeabi` (aarch64 kernel, pure
32-bit userspace). Full chain:

```
patch: /apex/.../crash_dump32 <- splicehelper (1312)  verify OK
patch: /vendor/lib/libbinderdebug.so <- dfroot.ko (13392)  verify OK
advanced 12 bytes to the first 32-bit Thumb insn at 0x46542
Found: hook=0x46542 shellcode=0x66b90 len=608 (thumb)
patch: /system/lib/libc++.so <- shellcode (608) + trampoline (16)  verify OK
=== init ===
shellcode: worker child spawned / grandchild forked / exec'ing insmod
kernel module: launching bootstrap
bootstrap: starting SU daemon
ksud start: SUCCESS
```

Cleanup restored both patches, and every 16-byte write was verified by reading
the content back.

### The four bugs that only show up on 32-bit

1. **`off_t` is 4 bytes, `loff_t*` is 8.** `splice(fd, &off, ...)` made the
   kernel read stack garbage as the high half of the file offset → `EINVAL` at
   block 0. Fixed with `off64_t` everywhere and `off_arg_t` = 8 bytes in the
   bridge. (arm64 never noticed: `off_t` is already 64-bit there.)
2. **`clone(CLONE_VFORK|CLONE_VM)` shares the parent's stack.** On arm32 the
   bridge child trampled the caller's frame and the offset handed to the next
   call came back as `0x102c2a6a`. Replaced with `fork()`.
3. **The patched page cache is not dirty.** The ESP decrypt writes through
   kmap, so nobody marks the page; the kernel reclaimed it after ~74 blocks and
   re-read the stock `crash_dump32` from disk (`e_type=3`). Fixed by holding a
   read-only mapping of the page and by checking + re-patching if it reverts.
   Note: pinning through a *pipe* (splice 1 byte) makes the page a spliceable
   pipe page, and the primitive then writes into it - that SEGV'd the bridge.
4. **16-bit Thumb hook sites.** `sentry::sentry()` starts with
   `push {r4, lr}` (0xb510); a 4-byte `B.W` cannot steal a 2-byte instruction.
   The parser walks forward to the first 32-bit Thumb-2 instruction instead, and
   the payload saves/restores APSR because a mid-function hook site may depend
   on flags set earlier.

## Still needs the device

1. `B.W` range: ±16 MB from the hook site to the shellcode slot. The tail-page
   slack path is ~4 KB away, so it is fine; the code-cave fallback can exceed
   the range and will now fail loudly instead of corrupting the file.
2. Confirm the hook site is Thumb-2:
   `readelf -s /system/lib/libc++.so | grep sentry` → the value should have
   bit0 set, and the first 4 bytes at that offset should be `2d e9 ...`
   (`push.w`). If the lib is ARM mode, the ARM `B` path is used instead.
3. `/apex/com.android.runtime/bin/crash_dump32` must exist and be openable from
   `untrusted_app` (that is what the `crash_dump` bridge does).
4. The arm64 KO must match the device KMI. Go devices are frequently *non*-GKI
   (4.19/5.4 vendor kernels) and are not covered by the DDK matrix — that, not
   the userspace port, is the remaining hard blocker.
5. The SU manager must ship an armeabi-v7a `ksud` (KernelSU does; check your
   fork's release matrix), otherwise `bootstrap` stages nothing to run.
