#include "common.h"
#include "httpCapture.h"

int isHttp(u8 *buf, u64 buflen);
int _strcmp(u8 *dst, u8 *src, u32 len);
int isMySelf(u8 *cmd);

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
    __u64 pid = pid_tgid >>32;

    u64 initVal = 0, *valp;
    //hash类型MAP, 直接使用pid当做key
    valp = bpf_map_lookup_elem(&accept_count_hash,&pid);
    if(!valp){
        bpf_map_update_elem(&accept_count_hash,&pid,&initVal,BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp,1);
 
    bpf_printk("exit sys_exit_accept4 !!!\n");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int syscall_enter_read(struct sys_enter_read_ctx *ctx) {
    u8 cmd[32]={0};
    bpf_get_current_comm(cmd,sizeof(cmd));
    if(isMySelf(cmd)==1){
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >>32;

    int index = 0;
    struct eventx_plus *event;
    event = bpf_map_lookup_elem(&bpf_stack_ext,&index);
    if(!event){
        bpf_printk("syscall_enter_read get bpfstackext failed !!!\n");
        return 0;
    }
    event->pid = pid;
    event->option = 0;
    bpf_probe_read(&(event->cmd),sizeof(event->cmd),cmd);

    u64 ret = bpf_probe_read(&(event->buf),4096,ctx->buf);
    if(ret != 0){
        bpf_printk("syscall_enter_read load buf failed !!!\n");
        return 0;
    }
    u64 len = 0;
    bpf_probe_read(&len,sizeof(len),&ctx->buflen);
    if (isHttp(event->buf,len)==0){
        return 0;
    }
    bpf_perf_event_output(ctx,&perf_events,BPF_F_CURRENT_CPU,event,sizeof(*event));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int syscall_exit_read(struct sys_exit_read_ctx *ctx) {
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall_enter_write(struct sys_enter_write_ctx *ctx) {
    u8 cmd[32]={0};
    bpf_get_current_comm(cmd,sizeof(cmd));
    if(isMySelf(cmd)==1){
        return 0;
    }
    int index = 0;
    struct eventx_plus *event;
    event = bpf_map_lookup_elem(&bpf_stack_ext,&index);
    if(!event){
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >>32;
    event->pid  = pid;
    event->option = 1;
    bpf_probe_read(&(event->cmd),sizeof(event->cmd),cmd);

    u64 ret = bpf_probe_read(&(event->buf),4096,ctx->buf);
    if(ret != 0){
        bpf_printk("syscall_enter_write load buf failed !!!\n");
        return 0;
    }
    u64 len = 0;
    bpf_probe_read(&len,sizeof(len),&ctx->buflen);
    if (isHttp(event->buf,len)==0){
        return 0;
    } 
    ret = bpf_perf_event_output(ctx,&perf_events,BPF_F_CURRENT_CPU,event,sizeof(*event));
    if(ret != 0){
        bpf_printk("bpf_perf_event_output failed !!!\n");
        return 0;
    }
    // struct eventx event;
    // u8 cmd[64] = {0};
    // __u64 pid_tgid = bpf_get_current_pid_tgid();
    // bpf_get_current_comm(cmd,64);
    // event.pid  = pid_tgid >> 32;
    // if (event.pid != 21695 && event.pid != 21698){
    //     return 0;
    // }
    // bpf_printk("=========================pid=%d, cmd=%s===========================\n",event.pid, cmd);
    // u64 ret = bpf_probe_read(&event.buf,sizeof(event.buf),ctx->buf);
    // if(ret != 0){
    //     bpf_printk("syscall_enter_read load buf failed !!!\n");
    //     return 0;
    // }
    // bpf_perf_event_output(ctx,&perf_events,BPF_F_CURRENT_CPU,&event,sizeof(event));
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


////////////////////////////////////////////////////
int isHttp(u8 *buf, u64 buflen){
    if(buflen < 20){// HTTP头部应该有个最小长度限制
        return 0;
    }else if(buf[0]=='P' && buf[1]=='O' && buf[2]== 'S' && buf[3]=='T'){
        return 1;
    }else if(buf[0]=='G' && buf[1]=='E' && buf[2]== 'T'){
        return 1;
    }else if(buf[0]=='P' && buf[1]=='U' && buf[2]== 'T'){
        return 1;
    }else if(buf[0]=='H' && buf[1]=='T' && buf[2]== 'T'&& buf[3]== 'P'){
        return 1;
    }else if(buf[0]=='H' && buf[1]=='E' && buf[2]== 'A'&& buf[3]== 'D'){
        return 1;
    }
    return 0;
}
int isMySelf(u8 *cmd){
    if (_strcmp(cmd,(u8 *)OWNER,12)==0){
        return 1;
    }
    return 0;
}
int _strcmp(u8 *dst, u8 *src, u32 len){
    len = MIN(len,16);
    
    for(;len>0 && *dst == *src;len--,dst++,src++);

    if(len==0){
        return 0;
    }
    return -1;
}