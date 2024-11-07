.PHONE: build init

init:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/vmlinux.h

build:
	clang -O2 -g -target bpf -c ./ebpf/radar.c -o ./ebpf/radar.o