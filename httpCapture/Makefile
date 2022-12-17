CLANG ?= clang-14
CFLAGS ?= -O2 -Wall -g -Werror

.PHONY: all clean generate

all:clean generate

clean:
	rm bpf_bpfeb.* -rf
	rm bpf_bpfel.* -rf

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate .



