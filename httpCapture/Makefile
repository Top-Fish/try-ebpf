CLANG ?= clang-14
CFLAGS ?= -O2 -Wall -g -Werror
TARGET ?= httpCapture
.PHONY: all clean generate

all:clean generate build

clean:
	rm bpf_bpfeb.* -rf
	rm bpf_bpfel.* -rf
	rm ${TARGET} -rf

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate .

build:
	go build -o ${TARGET} main.go bpf_bpfel.go



