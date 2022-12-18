#include "common.h"
#include "httpCapture.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tracepoint/syscalls/sys_enter_accept4")
int syscall_enter_accept4(struct sys_enter_accept4_ctx *ctx) {
    bpf_printk("enter sys_enter_accept4 !!!\n");

    u64 initVal = 0, *valp;
    u32 index = 0;  //数组类型MAP,需要使用下标
    valp = bpf_map_lookup_elem(&accept_count_array,&index);
    if(!valp){
        bpf_map_update_elem(&accept_count_array,&index,&initVal,BPF_ANY);
        return 0;
    }
    
    __sync_fetch_and_add(valp,100);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int syscall_exit_accept4(struct sys_exit_accept4_ctx *ctx) {
    bpf_printk("enter sys_exit_accept4 !!!\n");

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    u64 initVal = 0, *valp;
    //hash类型MAP, 直接使用pid当做key
    valp = bpf_map_lookup_elem(&accept_count_hash,&pid);
    if(!valp){
        bpf_map_update_elem(&accept_count_hash,&pid,&initVal,BPF_ANY);
        bpf_printk("===>  pid=%d, count=%d\n", pid, *valp);
        return 0;
    }
    bpf_printk("===>  pid=%d, count=%d\n", pid, *valp);
    __sync_fetch_and_add(valp,1);
 
    bpf_printk("exit sys_exit_accept4 !!!\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int syscall_enter_read(struct sys_enter_read_ctx *ctx) {
    struct eventx event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid  = pid_tgid >> 32;
    u64 ret = bpf_probe_read(&event.buf,sizeof(event.buf),ctx->buf);
    if(ret != 0){
        bpf_printk("syscall_enter_read load buf failed !!!\n");
        return 0;
    }
    bpf_perf_event_output(ctx,&read_events,BPF_F_CURRENT_CPU,&event,sizeof(event));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int syscall_exit_read(struct sys_exit_read_ctx *ctx) {
    bpf_printk("退出read函数\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall_enter_write(struct pt_regs *ctx) {
    bpf_printk("进入write函数\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int syscall_exit_write(struct pt_regs *ctx) {
    bpf_printk("退出write函数\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int syscall_enter_close(struct pt_regs *ctx) {
    bpf_printk("进入close函数\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int syscall_exit_close(struct pt_regs *ctx) {
    bpf_printk("退出close函数\n");
    return 0;
}
// clang -target bpf -Wall -O2 -o http.o -c http.c -I./include
// go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -target bpf hello.c -- -I./include


SEC("kprobe/sys_execve")
int kprobe_execve() {
	bpf_printk("hello world!!!\n");
	return 0;
}