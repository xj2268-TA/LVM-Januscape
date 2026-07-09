# KVM-XJ 热补丁

dump_tool.py 是自动寻找偏移，怎么用就自己看代码

## 漏洞概述

CVE-2026-53359（Januscape）是 Linux 内核 KVM 影子 MMU 中的释放后使用（UAF）漏洞。

- 潜伏时间：16 年（2010年8月至2026年7月）
- 影响范围：所有启用嵌套虚拟化的 Intel/AMD x86 系统
- 危害等级：高危，VM 内 root 用户可逃逸到母鸡，获取母鸡 root 权限
- 利用方式：母鸡内核 panic（DoS）或完整虚拟机逃逸（无公开POC）

## 漏洞原理

`kvm_mmu_get_page()` 函数在哈希表中查找可复用的影子页表时，仅比较了 gfn（客户机物理页框号），没有比较 role（页表角色/MMU 角色），导致角色不匹配的页表被错误复用，引发 UAF。

```
修复前（有漏洞）：
┌──────────────────────────────────────┐
│ kvm_mmu_get_page()                   │
│   遍历哈希表                          │
│   if (child->gfn == gfn)             │
│       return child  ← 只比较gfn！     │
│       角色不匹配也复用 → UAF！         │
│   分配新页（安全）                     │
└──────────────────────────────────────┘
```

在上游内核 commit `81ccda30b4e8` 中加了一行 role 比较：
```c
// 修复前
if (... && spte_to_child_sp(*sptep)->gfn == gfn)

// 修复后
if (... && spte_to_child_sp(*sptep)->gfn == gfn
       && spte_to_child_sp(*sptep)->role.word == role.word)
```

## 我的修复方法

### 方法：text_poke 二进制热补丁（NOP Patch）

不修改内核源码，不替换函数，而是直接在运行中的内核内存里修改漏洞指令。

### 原理

```
二进制层面：
偏移 0x104: 49 39 47 28          cmp %rax, 0x28(%r15)   ← 比较 gfn
偏移 0x108: 0f 84 9f 01 00 00    je   +0x19f            ← 匹配就跳转复用

打补丁后：
偏移 0x108: 66 0f 1f 44 00 00    NOP × 6               ← 什么也不做
```

```
修复后：
┌──────────────────────────────────────┐
│ kvm_mmu_get_page()                   │
│   遍历哈希表                          │
│   if (child->gfn == gfn)             │
│       NOP（跳转被抹掉，滑过去）        │
│   分配新页（强制走安全路径）            │
│   → 不复用 = 不触发 UAF = 漏洞修复     │
└──────────────────────────────────────┘
```

### 技术实现

1. 通过 `kallsyms_lookup_name` 找到 `kvm_mmu_get_page` 函数地址
2. 通过 `kallsyms_lookup_name` 找到 `text_poke` 函数（内核代码热修改 API）
3. 使用 `stop_machine` 暂停所有 CPU，确保修改安全
4. 用 `text_poke` 将 6 字节的 `je` 指令替换为 6 字节的 `NOP`
5. 卸载时用 `text_poke` 恢复原始指令

## 为什么不使用其他方案

| 方案 | 问题 |
|------|------|
| 升级内核重启 | 需要重启母鸡，所有 VM 停机 |
| nested=0（关闭嵌套虚拟化） | 嵌套虚拟化功能丧失，无法在 VM 中运行 VM |
| kpatch 方式 | 需要 kernel-debuginfo，编译耗时 10-20 分钟，依赖复杂 |
| ftrace 函数替换 | `kvm_mmu_get_child_sp` 被 GCC 内联，无独立函数入口 |
| 我的 text_poke 方案 | 编译 10 秒，一个 .c 文件，直接修改漏洞指令 |

## 影响评估

| 功能 | 影响 |
|------|------|
| 母鸡重启 | 不需要 |
| VM 重启/迁移 | 不需要 |
| 嵌套虚拟化（VM 里跑 VM） | 保留，正常使用 |
| 创建/启动虚拟机 | 正常 |
| KSM 内存合并 | 不影响，独立功能 |
| CPU 性能 | 几乎无影响（NOP 不消耗 CPU） |
| 内存 | 影子页表不再复用，每次分配新页，多占少量内存 |
| KVM 模块卸载 | 正常（rmmod 自动恢复原始代码） |

## 部署要求

| 条件 | 说明 |
|------|------|
| 内核版本 | Linux 4.18+（CentOS 8 / RHEL 8 / Rocky 8 等） |
| 编译环境 | kernel-devel + gcc + make |
| 母鸡重启 | 不需要 |
| VM 停机 | 不需要 |
| 嵌套虚拟化 | 保留 |

## 编译和加载

```bash
# 编译
make

# 加载热补丁
insmod KVM-XJ.ko

# 查看状态
dmesg | grep KVM-XJ
cat /sys/module/kvm_intel/parameters/nested   # 应该还是 1
lsmod | grep KVM_XJ

# 卸载（恢复原始代码）
rmmod KVM_XJ
```

## 适配其他内核

不同内核版本编译优化不同，`je` 指令偏移也不同。使用 `dump_tool.py` 自动分析：

```bash
# 1. 从母鸡下载 kvm.ko
scp root@母鸡:/lib/modules/.../kvm.ko.xz .
xz -d kvm.ko.xz

# 2. 运行分析工具
python dump_tool.py kvm.ko

# 3. 工具会输出 patch 偏移，修改 KVM-XJ.c 中的 0x108
```

## 已验证的内核

| 内核版本 | je 偏移 | 状态 |
|---------|---------|------|
| 4.18.0-496.el8.x86_64 | 0x108 | 已测试 |
| 4.18.0-358.el8.x86_64 | 0xe8 | 已测试 |

## 注意事项

1. 不会用，不会看代码的建议不要使用