APP=helloworld

# this is for using distribution provided bpftool
BPFTOOL=bpftool


.PHONY: $(APP)
$(APP): skel
	clang -DHAVE_ATTR_TEST=0 \
	-I../../usr/include -I. \
	helloworld.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 \
	-I../../usr/include -I. \
	-c helloworld.bpf.c -o helloworld.bpf.o

.PHONY: skel
skel: bpf
	$(BPFTOOL) gen skeleton helloworld.bpf.o name helloworld > helloworld.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)

.PHONY: gdb
gdb: bpf
	sudo gdb --args $(BPFTOOL) gen skeleton helloworld.bpf.o name helloworld