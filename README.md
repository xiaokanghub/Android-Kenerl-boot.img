# Android-Kenerl-boot.img
提取ARM64 内核文件 zImage 并用IDA anti ptrace<br>
小米8 ARM64 <br>
boot >> /dev/block/platform/soc/1d84000.ufshc/by-name<br>
lrwxrwxrwx 1 root root 16 1970-06-02 00:55 boot -> /dev/block/sde45<br>
使用命令:dd if=/dev/block/sde45 of=/data/local/boot.img 转储 随后使用adb pull 将boot.img提取出来<br>
然后使用abootimg -x boot.img 解析 拿到zImage<br>
直接用IDA打开该内核文件 设置处理器类型为ARM Little-endian  随后进入手机shell 输入命令:<br>
echo 0 > /proc/sys/kernel/kptr_restrict (关闭内核符号屏蔽)<br>
cat /proc/kallsyms (查看内核符号信息)<br>
```
ffffff8f40e80000 t _head
ffffff8f40e80000 T _text
ffffff8f40e80800 T do_undefinstr
ffffff8f40e80800 T _stext
ffffff8f40e80800 T __exception_text_start
ffffff8f40e80a70 T do_sysinstr
ffffff8f40e80af0 T do_cp15_32_instr_compat
ffffff8f40e80b70 T do_cp15_64_instr_compat
ffffff8f40e80bf0 T do_mem_abort
ffffff8f40e80cb8 T do_el0_ia_bp_hardening
ffffff8f40e80cd8 T do_sp_pc_abort
ffffff8f40e80dd4 T do_debug_exception
ffffff8f40e80ea4 t gic_handle_irq
ffffff8f40e80f58 t gic_handle_irq
ffffff8f40e810fc T __exception_text_end
ffffff8f40e81100 T __entry_text_start
ffffff8f40e81800 T vectors
ffffff8f40e81f8c t el0_sync_invalid
ffffff8f40e82024 t el0_irq_invalid
ffffff8f40e820bc t el0_fiq_invalid
ffffff8f40e82154 t el0_error_invalid
ffffff8f40e821ec t el0_fiq_invalid_compat
ffffff8f40e82288 t el0_error_invalid_compat
ffffff8f40e82324 t el1_sync_invalid
ffffff8f40e82398 t el1_irq_invalid
ffffff8f40e8240c t el1_fiq_invalid
ffffff8f40e82480 t el1_error_invalid
ffffff8f40e82500 t el1_sync
ffffff8f40e825a8 t el1_da
```
设置ROM start address和Loading address为0xffffff8f40e80000 有的是0xffffffc000080000<br>
存储符号表:cat /proc/kallsyms > /sdcard/syms.txt <br>
此时IDA进去后是无法分析出函数的  与网上的不同  这里只有DCB数据 这时候需要手动创建函数  使用IDAPython 脚本<br>
```
#! python
def main():
    start = AskAddr(MinEA(), "欲转为Code的起始地址：")
    end = AskAddr(MinEA(), "欲转为Code的结束地址：")
    if start >= end:
        print('输入的区间不正确～')
        return

    for cur_addr in range(start, end, 4):
        flags = GetFlags(cur_addr)
        print("[MSG] 0x%X 's flags: %x" % (cur_addr, flags))
        if Byte(cur_addr) and not (isCode(flags) and isTail(flags) and isUnknown(flags) and isHead(flags)):
            print('[MSG] 0x%X is Data, Make to code.' % cur_addr)
            MakeCode(cur_addr)
main()
```
处理完成后才可以再function name 区域看到sub_XXX  但是这个还是没有函数名 需要进一步处理  IDAPython脚本处理<br>
```
// 使用一下IDA脚本(python)，将函数/符号名设到对应的sub_xxx上
ksyms = open("syms.txt") 
i = 0 
for line in ksyms: 
    i += 1 
    addr = int(line[0:8],16)  
    name = line[11:-1]  
    idaapi.set_debug_name(addr,name)  
    MakeNameEx(addr,name,SN_NOWARN)
    add_func(addr)
    if i % 100 == 0:
        Message("cur: %d\n" % i)
```


