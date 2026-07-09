# KVM-XJ 热补丁

## 概述

CVE-2026-53359（Januscape）KVM 虚拟机逃逸漏洞的零停机热补丁。

- 无需重启母鸡
- 无需重启或迁移 VM
- 保留嵌套虚拟化功能
- 适用于 CentOS Stream 8 / RHEL 8 系列内核

## 漏洞原理

Linux 内核 KVM 模块的影子 MMU 中存在释放后使用（Use-After-Free）漏洞。

`kvm_mmu_get_page()` 函数在遍历哈希表查找可复用的影子页表时，仅比较了 gfn（客户机物理页框号），没有比较 role（页表角色），导致角色不匹配的页表被错误复用，最终引发 UAF。

```
修复前（有漏洞）：
┌──────────────────────────────────────┐
│ kvm_mmu_get_page()                   │
│   遍历哈希表                          │
│   if (child->gfn == gfn)  ← 只比较gfn │
│       return child  ← 错误复用！UAF！  │
│   分配新页（安全）                     │
└──────────────────────────────────────┘

修复后（本补丁）：
┌──────────────────────────────────────┐
│ kvm_mmu_get_page()                   │
│   遍历哈希表                          │
│   if (child->gfn == gfn)  ← 跳转被NOP│
│      （永远不执行）                    │
│   分配新页（强制安全路径）              │
└──────────────────────────────────────┘
```

## 修复原理

在 `kvm_mmu_get_page()` 函数中，找到 gfn 比较后的条件跳转指令（`je`），使用 `text_poke` 将其替换为 NOP（空操作），使 CPU 跳过复用逻辑，强制分配新页。

```
二进制层面：
偏移 0x104: 49 39 47 28          cmp %rax, 0x28(%r15)  ← 比较 gfn
偏移 0x108: 0f 84 9f 01 00 00    je   +0x19f           ← 匹配就跳转复用

打补丁后：
偏移 0x108: 66 0f 1f 44 00 00    NOP × 6              ← 什么也不做
```

## 影响范围

| 项目 | 影响 |
|------|------|
| 母鸡重启 | 不需要 |
| VM 重启 | 不需要 |
| 嵌套虚拟化 | 保留，正常使用 |
| 影子页表复用 | 被禁用，每次分配新页 |
| 性能 | 轻微下降（多分配几次页表），可接受 |

## 支持的内核

| 内核版本 | je 偏移 | 状态 |
|---------|---------|------|
| 4.18.0-496.el8.x86_64 | 0x108 | 已测试 |
| 4.18.0-358.el8.x86_64 | 0xe8 | 已测试 |
| 其他内核 | 需要先 dump 确认 | 待验证 |

## 编译

```bash
# 安装编译依赖
yum install -y kernel-devel gcc make elfutils-libelf-devel

# 如果 kernel-devel 版本不匹配，创建软链接
ln -sf /usr/src/kernels/$(ls /usr/src/kernels | head -1) /lib/modules/$(uname -r)/build

# 编译
make
```

## 加载

```bash
# 加载热补丁
insmod KVM-XJ.ko

# 查看状态
dmesg | grep KVM-XJ
cat /sys/module/kvm_intel/parameters/nested   # 应该还是 1
lsmod | grep KVM_XJ
```

## 卸载

```bash
# 卸载热补丁（恢复原始代码）
rmmod KVM_XJ
```

## 适配其他内核

1. 在目标母鸡上 dump `kvm_mmu_get_page` 的代码字节
2. 搜索 `49 39 47 28`（cmp %rax, 0x28(%r15)）或 `4d 39 57 28`（cmp %r10, 0x28(%r15)）
3. 紧跟其后的 `0f 84 xx xx xx xx` 就是需要 patch 的 `je` 指令
4. 修改源码中 `0x108` 为实际偏移

## 注意事项

1. **生产环境操作前请先在测试机验证**，确认偏移正确
2. `text_poke` 调用 `stop_machine`，会短暂暂停所有 CPU，VM 可能有毫秒级暂停
3. 补丁卸载后原始代码立即恢复，如需回滚直接 `rmmod`
4. 此补丁为临时方案，建议后续升级内核到包含官方修复的版本
5. 不同内核版本的偏移不同，务必确认后再加载

## 文件说明

| 文件 | 说明 |
|------|------|
| KVM-XJ.c | 热补丁源码 |
| Makefile | 编译脚本 |

## 许可证

GPL v2