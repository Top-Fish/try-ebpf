#ifndef __HTTPCAPTURE__
#define __HTTPCAPTURE__
#include "common.h"
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define OWNER "httpCapture"
/**********************************************************
 * 				 		数组类型MAP					
 * ********************************************************/
struct bpf_map_def SEC("maps") accept_count_array = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,                //数组大小为1
};

/**********************************************************
 * 				 		HASH类型MAP			        
 * ********************************************************/
struct bpf_map_def SEC("maps") accept_count_hash = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 100,                //hash map大小为100
};


/**********************************************************
 * 				 		perf event类型MAP			        
 * ********************************************************/
#define MAX_ENTRIES_PERF_OUTPUT (1 << 11) // 4096
#define MAXBUFSIZE (1<<8) //bpf默认栈大小不能超过512,否则会提示错误

struct bpf_map_def SEC("maps")  perf_events = {
	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
};
struct eventx{
	u32 pid;
	u8  buf[MAXBUFSIZE]; 
};
// Force emitting struct event into the ELF.
const struct eventx *unused __attribute__((unused)); //不添加的话不会生成对应的go结构


/**********************************************************
 * 				 超过512字节的结构,使用map进行存储			        
 * ********************************************************/
struct eventx_plus{
	u32 pid;
	u32 option; //0:请求, 1:响应
	u8  cmd[32];
	u8  buf[MAXBUFSIZE<<4]; //2^12=4096
};
struct bpf_map_def SEC("maps")  bpf_stack_ext = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(struct eventx_plus),
	.max_entries = 1, 
};
// Force emitting struct event into the ELF.
const struct eventx_plus *unused2 __attribute__((unused)); //不添加的话不会生成对应的go结构














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


/**************************************************************************************
 * 结构原型: /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
 * 使用对象: tracepoint/syscalls/sys_enter_write
 * 注意事项:
 * ************************************************************************************/
struct sys_enter_write_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;
	
	__u64  fd;
	__u64* buf;
	__u64  buflen;
};
#endif