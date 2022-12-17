package main

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// 不知道为啥，--必须的添加上，否则编译不过去
// export BPF_CLANG=clang-14
// export BPF_CFLAGS="-Wall -O2 -g -Werror"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf http.c -- -I../include

type syscallHooks struct {
	sysEnterAccept4 link.Link
	sysExitAccept4  link.Link
	sysEnterRead    link.Link
	sysExitRead     link.Link
	sysEnterWrite   link.Link
	sysExitWrite    link.Link
	sysEnterClose   link.Link
	sysExitClose    link.Link
	helloWorld      link.Link
}

var sysCallDbg bool = false

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("%s\n", err.Error())
		return
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Printf("loading objects error: %s\n", err.Error())
		return
	}
	defer objs.Close()

	sysHook := syscallHooks{}
	sysHook.installHooks(&objs)
	defer sysHook.Close()
	for {
		fmt.Printf("----------------------\n")
		time.Sleep(10 * time.Second)
	}
}
func (s *syscallHooks) installHooks(objs *bpfObjects) (err error) {
	if sysCallDbg {
		s.helloWorld, err = link.Kprobe("sys_execve", objs.KprobeExecve, nil)
		if err != nil {
			fmt.Printf("tracepoint sys_enter_accept4: %s\n", err.Error())
			return err
		}

	}

	s.sysEnterAccept4, err = link.Tracepoint("syscalls", "sys_enter_accept4", objs.SyscallEnterAccept4, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_enter_accept4: %s\n", err.Error())
		return err
	}
	s.sysExitAccept4, err = link.Tracepoint("syscalls", "sys_exit_accept4", objs.SyscallExitAccept4, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_accept4: %s\n", err.Error())
		return err
	}
	s.sysEnterRead, err = link.Tracepoint("syscalls", "sys_enter_read", objs.SyscallEnterRead, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_enter_read: %s\n", err.Error())
		return err
	}
	s.sysExitRead, err = link.Tracepoint("syscalls", "sys_exit_read", objs.SyscallExitRead, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_read: %s\n", err.Error())
		return err
	}
	s.sysEnterWrite, err = link.Tracepoint("syscalls", "sys_enter_write", objs.SyscallEnterWrite, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_enter_read: %s\n", err.Error())
		return err
	}
	s.sysExitWrite, err = link.Tracepoint("syscalls", "sys_exit_write", objs.SyscallExitWrite, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_read: %s\n", err.Error())
		return err
	}
	s.sysEnterClose, err = link.Tracepoint("syscalls", "sys_enter_close", objs.SyscallEnterClose, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_enter_read: %s\n", err.Error())
		return err
	}
	s.sysExitClose, err = link.Tracepoint("syscalls", "sys_exit_close", objs.SyscallExitClose, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_read: %s\n", err.Error())
		return err
	}
	return nil
}

func (s *syscallHooks) Close() error {
	if sysCallDbg {
		s.helloWorld.Close()
	}
	s.sysEnterRead.Close()
	s.sysEnterWrite.Close()
	s.sysEnterAccept4.Close()
	s.sysEnterClose.Close()
	s.sysExitRead.Close()
	s.sysExitWrite.Close()
	s.sysExitAccept4.Close()
	s.sysExitClose.Close()
	return nil
}
