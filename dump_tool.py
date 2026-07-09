#!/d/python/python
# -*- coding: utf-8 -*-

import sys
import struct

def find_pattern(data, pattern, start=0):
    for i in range(start, len(data) - len(pattern)):
        if data[i:i+len(pattern)] == pattern:
            return i
    return -1

def hexdump(data, offset=0, length=400):
    for i in range(0, min(length, len(data) - offset), 16):
        addr = offset + i
        chunk = data[offset+i:offset+i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {addr:08x}: {hex_str:<48s}  {ascii_str}')

def find_function_offset(data, func_name):
    # 简单搜索：在 .strtab 中找函数名，然后在 .symtab 中找对应符号
    idx = data.find(func_name.encode() + b'\x00')
    if idx < 0:
        return None

    # 尝试在 ELF 中查找符号表
    # ELF 头: 0x7f 'E' 'L' 'F'
    if data[:4] != b'\x7fELF':
        print("警告: 不是标准 ELF 文件")
        return None

    # 64-bit ELF header
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]  # section header offset
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]  # section header entry size
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]  # section header count
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]  # section name string table index

    # 读取 section name 字符串表
    shstrtab_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

    # 搜索 .symtab section
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from('<I', data, sh_off)[0]
        sh_type = struct.unpack_from('<I', data, sh_off + 4)[0]

        name = data[shstrtab_off + sh_name:].split(b'\x00')[0]

        if name == b'.symtab' and sh_type == 2:  # SHT_SYMTAB
            sh_offset = struct.unpack_from('<Q', data, sh_off + 0x18)[0]
            sh_size = struct.unpack_from('<Q', data, sh_off + 0x20)[0]
            sh_entsize = struct.unpack_from('<Q', data, sh_off + 0x38)[0]

            # 找 .strtab
            strtab_off = None
            for j in range(e_shnum):
                s_off = e_shoff + j * e_shentsize
                s_name = struct.unpack_from('<I', data, s_off)[0]
                s_name_str = data[shstrtab_off + s_name:].split(b'\x00')[0]
                if s_name_str == b'.strtab':
                    strtab_off = struct.unpack_from('<Q', data, s_off + 0x18)[0]
                    break

            if strtab_off is None:
                continue

            # 遍历符号表
            for k in range(0, sh_size, sh_entsize):
                st_name = struct.unpack_from('<I', data, sh_offset + k)[0]
                st_value = struct.unpack_from('<Q', data, sh_offset + k + 8)[0]
                st_size = struct.unpack_from('<Q', data, sh_offset + k + 16)[0]

                sym_name = data[strtab_off + st_name:].split(b'\x00')[0]

                if sym_name == func_name.encode():
                    return st_value

            return None

    return None

def analyze_kvm(data, func_name="kvm_mmu_get_page"):
    print("=" * 60)
    print(f"   KVM Januscape 漏洞偏移分析工具")
    print(f"   目标函数: {func_name}")
    print("=" * 60)
    print()

    # 搜索函数名
    func_offset = find_function_offset(data, func_name)
    if func_offset is None:
        print(f"错误: 未找到 {func_name} 函数")
        print("请确认 kvm.ko 文件包含该函数（可能需要先解压 .ko.xz）")
        return

    print(f"函数 {func_name} 偏移: 0x{func_offset:x}")
    print()

    # 显示函数开头 400 字节
    print(f"--- {func_name} 前 400 字节 ---")
    hexdump(data, func_offset, 400)
    print()

    # 搜索关键模式
    # 模式1: cmp %rax, 0x28(%r15) = 49 39 47 28
    # 模式2: cmp %r10, 0x28(%r15) = 4d 39 57 28
    # 模式3: cmp %rax, 0x28(%rbx) = 48 39 43 28
    patterns = [
        (b'\x49\x39\x47\x28', "cmp %rax, 0x28(%r15)"),
        (b'\x4d\x39\x57\x28', "cmp %r10, 0x28(%r15)"),
        (b'\x4c\x39\x47\x28', "cmp %r8, 0x28(%r15)"),
        (b'\x48\x39\x43\x28', "cmp %rax, 0x28(%rbx)"),
    ]

    print("--- 搜索 gfn 比较指令 ---")
    for pat, desc in patterns:
        pos = find_pattern(data, pat, func_offset)
        if pos >= 0 and pos < func_offset + 400:
            # 读取后续 6 字节（je 指令）
            je_bytes = data[pos+4:pos+10]
            je_hex = ' '.join(f'{b:02x}' for b in je_bytes)

            print(f"  偏移 0x{pos - func_offset:x}: {desc}")
            print(f"  后续指令: {je_hex}")

            if je_bytes[0] == 0x0f and je_bytes[1] == 0x84:
                # je rel32
                rel = struct.unpack_from('<i', je_bytes, 2)[0]
                target = pos + 6 + rel
                print(f"  -> je 指令，跳转到偏移 0x{target - func_offset:x}")
                print(f"  *** 这是需要 patch 的漏洞指令！patch 偏移 = 0x{pos - func_offset + 4:x} ***")
            elif je_bytes[0] == 0x0f and je_bytes[1] == 0x85:
                # jne rel32
                rel = struct.unpack_from('<i', je_bytes, 2)[0]
                target = pos + 6 + rel
                print(f"  -> jne 指令，跳转到偏移 0x{target - func_offset:x}")
            print()

def main():
    if len(sys.argv) < 2:
        print("用法: python dump_tool.py <kvm.ko文件路径>")
        print()
        print("获取 kvm.ko 的方法:")
        print("  1. 在母鸡上: modinfo -F filename kvm")
        print("  2. 复制到本地: xz -d kvm.ko.xz")
        print("  3. 运行: python dump_tool.py kvm.ko")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"错误: 文件不存在 {filepath}")
        sys.exit(1)

    print(f"文件: {filepath}")
    print(f"大小: {len(data)} 字节 ({len(data)/1024:.1f} KB)")
    print()

    analyze_kvm(data)

if __name__ == '__main__':
    main()