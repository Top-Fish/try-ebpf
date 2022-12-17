#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
};

// bpf_printk 会将内容输出到/sys/kernel/debug/tracing/trace_pipe

struct sys_enter_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64 fd;
	__u64* sockaddr;
	__u64* addrlen;
    __u64  flags;
};
struct sys_exit_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64 ret;
};
///sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format 
SEC("tracepoint/syscalls/sys_enter_accept4")
int syscall_enter_accept4(struct sys_enter_accept4_ctx *ctx) {
    bpf_printk("enter sys_enter_accept4 !!!\n");
    bpf_printk("您好,全世界 !!!\n"); // 不能输出中文
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int syscall_exit_accept4(struct sys_exit_accept4_ctx *ctx) {
    bpf_printk("exit sys_enter_accept4 !!!\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int syscall_enter_read(struct pt_regs *ctx) {
    bpf_printk("进入read函数\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int syscall_exit_read(struct pt_regs *ctx) {
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