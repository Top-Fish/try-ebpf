// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEventx struct {
	Pid uint32
	Buf [256]uint8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeExecve        *ebpf.ProgramSpec `ebpf:"kprobe_execve"`
	SyscallEnterAccept4 *ebpf.ProgramSpec `ebpf:"syscall_enter_accept4"`
	SyscallEnterClose   *ebpf.ProgramSpec `ebpf:"syscall_enter_close"`
	SyscallEnterRead    *ebpf.ProgramSpec `ebpf:"syscall_enter_read"`
	SyscallEnterWrite   *ebpf.ProgramSpec `ebpf:"syscall_enter_write"`
	SyscallExitAccept4  *ebpf.ProgramSpec `ebpf:"syscall_exit_accept4"`
	SyscallExitClose    *ebpf.ProgramSpec `ebpf:"syscall_exit_close"`
	SyscallExitRead     *ebpf.ProgramSpec `ebpf:"syscall_exit_read"`
	SyscallExitWrite    *ebpf.ProgramSpec `ebpf:"syscall_exit_write"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	AcceptCountArray *ebpf.MapSpec `ebpf:"accept_count_array"`
	AcceptCountHash  *ebpf.MapSpec `ebpf:"accept_count_hash"`
	ReadEvents       *ebpf.MapSpec `ebpf:"read_events"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	AcceptCountArray *ebpf.Map `ebpf:"accept_count_array"`
	AcceptCountHash  *ebpf.Map `ebpf:"accept_count_hash"`
	ReadEvents       *ebpf.Map `ebpf:"read_events"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.AcceptCountArray,
		m.AcceptCountHash,
		m.ReadEvents,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeExecve        *ebpf.Program `ebpf:"kprobe_execve"`
	SyscallEnterAccept4 *ebpf.Program `ebpf:"syscall_enter_accept4"`
	SyscallEnterClose   *ebpf.Program `ebpf:"syscall_enter_close"`
	SyscallEnterRead    *ebpf.Program `ebpf:"syscall_enter_read"`
	SyscallEnterWrite   *ebpf.Program `ebpf:"syscall_enter_write"`
	SyscallExitAccept4  *ebpf.Program `ebpf:"syscall_exit_accept4"`
	SyscallExitClose    *ebpf.Program `ebpf:"syscall_exit_close"`
	SyscallExitRead     *ebpf.Program `ebpf:"syscall_exit_read"`
	SyscallExitWrite    *ebpf.Program `ebpf:"syscall_exit_write"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeExecve,
		p.SyscallEnterAccept4,
		p.SyscallEnterClose,
		p.SyscallEnterRead,
		p.SyscallEnterWrite,
		p.SyscallExitAccept4,
		p.SyscallExitClose,
		p.SyscallExitRead,
		p.SyscallExitWrite,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
