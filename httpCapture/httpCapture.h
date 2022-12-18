#ifndef __HTTPCAPTURE__
#define __HTTPCAPTURE__
#include "common.h"
struct key {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
};
// 数组类型MAP
struct bpf_map_def SEC("maps") accept_count_array = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,                //数组大小为1
};

// HASH类型MAP
struct bpf_map_def SEC("maps") accept_count_hash = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 100,                //hash map大小为100
};


/**************************************************************************************
 * 结构原型: /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format 
 * 使用对象: tracepoint/syscalls/sys_enter_accept4
 * 注意事项:
 * ************************************************************************************/
struct sys_enter_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64 fd;
	__u64* sockaddr;
	__u64* addrlen;
    __u64  flags;
};

/**************************************************************************************
 * 结构原型: /sys/kernel/debug/tracing/events/syscalls/sys_exit_accept4/format 
 * 使用对象: tracepoint/syscalls/sys_enter_accept4
 * 注意事项:
 * ************************************************************************************/
struct sys_exit_accept4_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64 ret;
};

/**************************************************************************************
 * 结构原型: /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format 
 * 使用对象: tracepoint/syscalls/sys_enter_read
 * 注意事项:
 * ************************************************************************************/
struct sys_enter_read_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64  fd;
	__u64* buf;
	__u64* buflen;
};

/**************************************************************************************
 * 结构原型: /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format 
 * 使用对象: tracepoint/syscalls/sys_exit_read
 * 注意事项:
 * ************************************************************************************/
struct sys_exit_read_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64  ret;
};

#endif