# hello world go-ebpf


# 流程

## 1. 编写go http server 程序
- 参见gin/main.go


## 2. 查看调用栈信息
- 追踪调用栈信息：`strace -f -o syscall.txt go run main.go`
```go
... ...
143384 futex(0xc00003f148, FUTEX_WAKE_PRIVATE, 1) = 1
143384 accept4(3, 0xc00029fa58, [112], SOCK_CLOEXEC|SOCK_NONBLOCK) = -1 EAGAIN (Resource temporarily unavailable)
143384 read(7, "GET /ebpf/ HTTP/1.1\r\nHost: 192.1"..., 4096) = 404
143389 <... futex resumed>)             = 0
143385 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
... ...
143384 write(1, "[GIN] 2022/12/17 - 12:54:29 |\33[9"..., 113) = 113
143385 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
143384 write(7, "HTTP/1.1 200 OK\r\nContent-Type: t"..., 141) = 141
143384 read(7, 0xc0003c6000, 4096)      = -1 EAGAIN (Resource temporarily unavailable)
143384 epoll_pwait(4,  <unfinished ...>
... ...
143607 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
143606 <... unlinkat resumed>)          = 0
143606 close(7 <unfinished ...>
143607 <... nanosleep resumed>NULL)     = 0
143607 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
143606 <... close resumed>)             = 0
```
这里主要关注四个函数：accept4,read,write,close。他们分别对应：
-[x] accept4: TCP的三次握手
使用五元组区分不用连接--> hash
-[x] read,write: 通讯内容的读写
需要向用户空间发送数据--> perf event hash
-[x] close: TCP的四次挥手
使用五元组区分不用连接--> hash

数据结构涉及到共计2种：一个hash数组, 一个perf event; 如果需要区分读写，那么是2个perf event


## 2. 查看系统调用对应的hook位置
使用诸如: 
- bpftrace -l '*accept*' 
```shell
    # bpftrace -l *accept4*
    kprobe:__ia32_sys_accept4
    kprobe:__sys_accept4
    kprobe:__sys_accept4_file
    kprobe:__x64_sys_accept4
    tracepoint:syscalls:sys_enter_accept4
    tracepoint:syscalls:sys_exit_accept4
```
- bpftrace -l '*read*'
```shell
tracepoint:syscalls:sys_enter_pread64
tracepoint:syscalls:sys_enter_preadv
tracepoint:syscalls:sys_enter_preadv2
tracepoint:syscalls:sys_enter_process_vm_readv
tracepoint:syscalls:sys_enter_read
tracepoint:syscalls:sys_enter_readahead
tracepoint:syscalls:sys_enter_readlink
tracepoint:syscalls:sys_enter_readlinkat
tracepoint:syscalls:sys_enter_readv
tracepoint:syscalls:sys_exit_pread64
tracepoint:syscalls:sys_exit_preadv
tracepoint:syscalls:sys_exit_preadv2
tracepoint:syscalls:sys_exit_process_vm_readv
tracepoint:syscalls:sys_exit_read
tracepoint:syscalls:sys_exit_readahead
tracepoint:syscalls:sys_exit_readlink
tracepoint:syscalls:sys_exit_readlinkat
tracepoint:syscalls:sys_exit_readv
tracepoint:xdp:xdp_cpumap_kthread
```
- bpftrace -l '*write*'
```shell
tracepoint:syscalls:sys_enter_process_vm_writev
tracepoint:syscalls:sys_enter_pwrite64
tracepoint:syscalls:sys_enter_pwritev
tracepoint:syscalls:sys_enter_pwritev2
tracepoint:syscalls:sys_enter_write
tracepoint:syscalls:sys_enter_writev
tracepoint:syscalls:sys_exit_process_vm_writev
tracepoint:syscalls:sys_exit_pwrite64
tracepoint:syscalls:sys_exit_pwritev
tracepoint:syscalls:sys_exit_pwritev2
tracepoint:syscalls:sys_exit_write
tracepoint:syscalls:sys_exit_writev
```
- bpftrace -l '*close*'
```shell
tracepoint:syscalls:sys_enter_close
tracepoint:syscalls:sys_enter_close_range
tracepoint:syscalls:sys_exit_close
tracepoint:syscalls:sys_exit_close_range
```
? 如何确认函数原型呢？ 以及对应的参数？？

## 3. 编写内核态程序

> bpf_printk 会将内容输出到/sys/kernel/debug/tracing/trace_pipe
> bpf_printk不能输出中文!!!!!!!!!!!!
> 需要到以下目录获取每个函数的ctx信息：sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
> 每一个函数下都有一个对应的format文件，里面记录了这个hook的参数信息
> 每个函数下还有个enable的开关文件,这个只是内核里的调试信息，不影响我们编写的log信息

### sys_enter_read：
> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format 
```
#cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format 
name: sys_enter_read
ID: 691
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:char * buf;       offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;
```

## 4. 编译.c文件
`//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf http.c -- -I../include`

使用makefile编译，方便传递各种参数