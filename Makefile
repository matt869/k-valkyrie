# K-Valkyrie eBPF Probes & Daemon Makefile
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

PROBES_DIR := ebpf_probes
HEADERS_DIR := $(PROBES_DIR)/headers
BUILD_DIR := build

BPF_CFLAGS := -g -O2 -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I$(HEADERS_DIR) \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include

PROBE_SOURCES := $(wildcard $(PROBES_DIR)/*.bpf.c)
PROBE_OBJECTS := $(patsubst $(PROBES_DIR)/%.bpf.c, $(BUILD_DIR)/%.bpf.o, $(PROBE_SOURCES))
PROBE_SKELS   := $(patsubst $(PROBES_DIR)/%.bpf.c, $(BUILD_DIR)/%.skel.h, $(PROBE_SOURCES))

all: dirs vmlinux bpf_probes

dirs:
	mkdir -p $(BUILD_DIR)

# Dump CO-RE kernel definitions from active Linux kernel if not present
vmlinux:
	@if [ ! -f $(HEADERS_DIR)/vmlinux.h ]; then \
		echo "[*] Generating $(HEADERS_DIR)/vmlinux.h via bpftool..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS_DIR)/vmlinux.h 2>/dev/null || true; \
	else \
		echo "[+] $(HEADERS_DIR)/vmlinux.h already exists."; \
	fi

# Compile each eBPF C program to BPF object & generate libbpf skeleton
$(BUILD_DIR)/%.bpf.o: $(PROBES_DIR)/%.bpf.c dirs
	@echo "[*] Compiling $< -> $@..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "[*] Generating skeleton for $< -> $@..."
	$(BPFTOOL) gen skeleton $< > $@ 2>/dev/null || true

bpf_probes: $(PROBE_OBJECTS) $(PROBE_SKELS)
	@echo "[+] All eBPF probes compiled successfully to $(BUILD_DIR)/"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all dirs vmlinux bpf_probes clean
