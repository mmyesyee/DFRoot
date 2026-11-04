#!/usr/bin/env python3
"""Rewrite a kernel module's vermagic so it matches the target kernel.

Why this works: `.modinfo` is never laid out into the module's memory image.
The loader only reads it out of the file image, through the section header's
sh_offset/sh_size (find_sec(".modinfo") + get_modinfo()). So the section can be
moved to the end of the file and enlarged for free - no offsets shift, nothing
else in the ELF has to be touched.

    # take the exact string from a module that already loads on the device:
    #   strings -a dfroot.ko | grep '^vermagic='
    ./patch_vermagic.py --strip-versions kernelsu.ko \
        "5.15.167-android14-11-maybe-dirty SMP preempt mod_unload modversions aarch64"

Only the release/vermagic string is replaced; the code and symbol versions are
untouched, so if the module was built against a different source tree the
kernel may still reject it later with "disagrees about version of symbol ...".
"""
import struct
import sys


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def strip_versions(data, read_sh, e_shnum):
    """Blank the __versions section.

    With CONFIG_MODVERSIONS the kernel cross-checks every symbol CRC against
    its own; a module built on another tree then fails with 'disagrees about
    version of symbol ...'. Dropping the section downgrades that to the
    'no symbol version for ...' warnings that an unsigned GKI module gets --
    which this kernel accepts (dfroot.ko loads exactly that way).
    """
    for i in range(e_shnum):
        d = read_sh(i)
        p = d["shstr"]
        end = data.index(b"\x00", p)
        if data[p:end] in (b"__versions", b".gnu.linkonce.this_module_versions"):
            struct.pack_into("<Q", data, d["off"] + 32, 0)   # sh_size = 0
            return True
    return False


def main():
    args = [a for a in sys.argv[1:]]
    if len(args) < 2:
        die("usage: patch_vermagic.py [--strip-versions] <module.ko> <new vermagic>\n"
            "       get the exact string with: strings -a <a module that loads> "
            "| grep '^vermagic='")

    strip = False
    if args and args[0] == "--strip-versions":
        strip = True
        args = args[1:]

    path, new_vm = args[0], args[1]

    data = bytearray(open(path, "rb").read())
    if data[:4] != b"\x7fELF":
        die("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        die("only little-endian ELF64 is supported")
    e_type = struct.unpack_from("<H", data, 0x10)[0]

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        die("no section headers")

    SH = struct.Struct("<IIQQQQIIQQ")

    def read_sh(i):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size,
         link, info, align, entsize) = SH.unpack_from(data, off)
        return dict(off=off, name=name, typ=typ, flags=flags, addr=addr,
                    offset=offset, size=size, link=link, info=info,
                    align=align, entsize=entsize, shstr=0)

    shstr = read_sh(e_shstrndx)
    shstr_off = shstr["offset"]

    def sec_name(d):
        p = shstr_off + d["name"]
        end = data.index(b"\x00", p)
        return data[p:end].decode("latin-1")

    def read_sh2(i):
        d = read_sh(i)
        d["shstr"] = shstr_off + d["name"]
        return d

    modinfo = None
    for i in range(e_shnum):
        d = read_sh2(i)
        if sec_name(d) == ".modinfo":
            modinfo = d
            break
    if modinfo is None:
        die("no .modinfo section - this is not a kernel module")
    if modinfo["flags"] & 0x2:          # SHF_ALLOC
        die(".modinfo is SHF_ALLOC here; refusing to move it")

    old = bytes(data[modinfo["offset"]:modinfo["offset"] + modinfo["size"]])
    entries = [e for e in old.split(b"\x00") if e]
    tags = {}
    for e in entries:
        k, _, v = e.partition(b"=")
        tags[k.decode("latin-1")] = v.decode("latin-1")

    name = tags.get("name")
    if not name:
        die("no name= entry in .modinfo")

    print("module   : %s" % name)
    print("old vermagic: %s" % tags.get("vermagic", "<none>"))
    print("new vermagic: %s" % new_vm)

    blob = bytearray()
    blob += ("name=%s\0" % name).encode()
    blob += ("vermagic=%s\0" % new_vm).encode()
    blob += b"depends=\0"
    if tags.get("retpoline"):
        blob += ("retpoline=%s\0" % tags["retpoline"]).encode()

    while len(data) % 8:
        data += b"\x00"
    new_off = len(data)
    data += blob
    while len(data) % 8:
        data += b"\x00"

    # point the section header at the appended blob
    SH.pack_into(data, modinfo["off"],
                 modinfo["name"], modinfo["typ"], modinfo["flags"],
                 modinfo["addr"], new_off, len(blob),
                 modinfo["link"], modinfo["info"], 1, modinfo["entsize"])

    if strip:
        if strip_versions(data, read_sh2, e_shnum):
            print("stripped : __versions (symbol CRC checks become warnings)")
        else:
            print("note     : no __versions section, nothing to strip")

    open(path, "wb").write(data)
    print("patched  : %s (wrote %d bytes)" % (path, len(data)))
    print()
    print("verify with: strings -a %s | grep -E 'vermagic=|^name='" % path)


if __name__ == "__main__":
    main()
