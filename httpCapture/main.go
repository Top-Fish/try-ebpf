package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// 不知道为啥，--必须的添加上，否则编译不过去
// export BPF_CLANG=clang-14
// export BPF_CFLAGS="-Wall -O2 -g -Werror"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type eventx -type eventx_plus bpf httpCapture.c -- -I../include

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

	perfEvent(&objs)
	// basicHash(&objs)
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
		fmt.Printf("tracepoint sys_enter_write: %s\n", err.Error())
		return err
	}
	s.sysExitWrite, err = link.Tracepoint("syscalls", "sys_exit_write", objs.SyscallExitWrite, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_write: %s\n", err.Error())
		return err
	}
	s.sysEnterClose, err = link.Tracepoint("syscalls", "sys_enter_close", objs.SyscallEnterClose, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_enter_close: %s\n", err.Error())
		return err
	}
	s.sysExitClose, err = link.Tracepoint("syscalls", "sys_exit_close", objs.SyscallExitClose, nil)
	if err != nil {
		fmt.Printf("tracepoint sys_exit_close: %s\n", err.Error())
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

func perfEvent(objs *bpfObjects) {
	perfEventFd, err := perf.NewReader(objs.PerfEvents, 10*os.Getpagesize()) //设置太小了无法读取数据!!!!!!!!
	if err != nil {
		fmt.Printf("perfEvent()/perf.NewReader : %s\n", err.Error())
		return
	}
	defer perfEventFd.Close()

	// var event bpfEventx
	var event bpfEventxPlus
	var alreadyRead bool
	for {
		record, err := perfEventFd.Read()
		if err != nil {
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			// fmt.Printf("perfEvent()/binary.Read : %s\n", err.Error())
			continue
		}
		if alreadyRead && event.Option == 0 {
			alreadyRead = false //不知道为何read系统调用总是执行两次,这里只是为了去除第二次read系统调用获取的消息
			continue
		} else if event.Option == 0 {
			fmt.Printf("========================HTTP请求============================\n")
		} else if event.Option == 1 {
			fmt.Printf("========================HTTP响应============================\n")
			alreadyRead = true
		} else {
			continue
		}

		fmt.Printf("程序名称:%s\n进程PID:%d\n", event.Cmd, event.Pid)
		fmt.Printf("消息内容:\n%s\n", event.Buf)
		fmt.Printf("============================================================\n\n\n")

	}

}

func basicHash(objs *bpfObjects) {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			{ // 数组类型MAP
				var value uint64
				mapKey := uint32(0)
				if err := objs.AcceptCountArray.Lookup(mapKey, &value); err != nil {
					fmt.Printf("objs.AcceptCountMap.Lookup :[%s]\n", err.Error())
					continue
				}
				fmt.Printf("当前的引用次数为：%d\n", value)
			}
			{ // hash类型MAP
				if false { //获取指定key的value
					var key uint32 = 11381 //运行的http服务进程是11381
					var value uint64
					if err := objs.AcceptCountHash.Lookup(key, &value); err != nil {
						fmt.Printf("objs.AcceptCountMap.Lookup :[%s]\n", err.Error())
						continue
					}
					fmt.Printf("当前进程调用次数为：%d\n", value)
				}
				if true { //批量获取, 可用在未知key的情况下获取整个hash MAP
					var (
						nextkey      uint32
						lookupKeys   = make([]uint32, 100)
						lookupValues = make([]uint64, 100)
					)
					count, err := objs.AcceptCountHash.BatchLookup(nil, &nextkey, lookupKeys, lookupValues, nil)
					if err != nil && count == 0 {
						fmt.Printf("objs.AcceptCountHash.BatchLookup :[%s]\n", err.Error())
						continue
					}
					fmt.Printf("当前的hash表的大小为：%d\n", count)
					for i := 0; i < count; i++ {
						fmt.Printf("HASH-MAP内容:  hash[%d]=%d\n", lookupKeys[i], lookupValues[i])
					}
				}
			}

		}
	}
}
