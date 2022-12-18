#ifndef __HTTPCAPTURE__
#define __HTTPCAPTURE__
#include "common.h"

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

// perf event类型MAP
#define MAX_ENTRIES_PERF_OUTPUT (1 << 12) // 4096
#define MAXBUFSIZE (1<<8) //bpf默认栈大小不能超过512,否则会提示错误

struct bpf_map_def SEC("maps")  read_events = {
	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(u32),
	.max_entries = MAX_ENTRIES_PERF_OUTPUT, 
};
struct eventx{
	u32 pid;
	u8  buf[MAXBUFSIZE]; 
};
// Force emitting struct event into the ELF.
const struct eventx *unused __attribute__((unused)); //不添加的话不会生成对应的go结构

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
	__u64  buflen;
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