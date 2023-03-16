/** hellowworld.bpf.c
 *  source code of the BPF prorgam
 *  complie with`clang-target=bpf`
*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* 在系统调用execve的埋点处(通过SEC宏设置)注入bpf_prog 
   这样每次系统调用execve执行时，都会回调bpf_prog */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(void *ctx) {
    bpf_printk("Hello world!\n");
    return 0;
}

 char LICENSE[] SEC("license") = "GPL";
