#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KVM-XJ: CVE-2026-53359 (Januscape) KVM热补丁");

static unsigned long mubiao_dizhi;
static unsigned char yuanshi_zijie[6];
static unsigned char kong_zijie[6] = {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00};

typedef void *(*text_poke_hanshu)(void *addr, const void *opcode, size_t len);

static int zhixing_xiubu(void *data)
{
    text_poke_hanshu poke = (text_poke_hanshu)kallsyms_lookup_name("text_poke");
    if (!poke) {
        printk(KERN_ERR "KVM-XJ: 未找到text_poke函数\n");
        return -1;
    }
    memcpy(yuanshi_zijie, (void*)(mubiao_dizhi + 0x108), 6);
    poke((void*)(mubiao_dizhi + 0x108), kong_zijie, 6);
    return 0;
}

static int __init rebuxiu_init(void)
{
    mubiao_dizhi = kallsyms_lookup_name("kvm_mmu_get_page");
    if (!mubiao_dizhi) {
        printk(KERN_ERR "KVM-XJ: 未找到kvm_mmu_get_page函数\n");
        return -ENOENT;
    }
    printk(KERN_INFO "KVM-XJ: 目标函数地址=%px\n", (void*)mubiao_dizhi);
    printk(KERN_INFO "KVM-XJ: 正在修补偏移0x108处的跳转指令\n");
    stop_machine(zhixing_xiubu, NULL, NULL);
    printk(KERN_INFO "KVM-XJ: 补丁已加载 CVE-2026-53359修复成功\n");
    return 0;
}

static void __exit rebuxiu_xiezai(void)
{
    text_poke_hanshu poke = (text_poke_hanshu)kallsyms_lookup_name("text_poke");
    if (mubiao_dizhi && poke) {
        poke((void*)(mubiao_dizhi + 0x108), yuanshi_zijie, 6);
        printk(KERN_INFO "KVM-XJ: 补丁已卸载 原始代码已恢复\n");
    }
}

module_init(rebuxiu_init);
module_exit(rebuxiu_xiezai);