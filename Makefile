obj-m += kernel/av_main.o
kernel/av_main-objs := kernel/av_kprobe.o kernel/av_netlink.o

PWD := $(CURDIR) 
KVERSION = $(shell uname -r)
DEBUG_CFLAGS += -g -DDEBUG

all: 
	make -C kernel
debug:
	make -C kernel debug
clean: 
	make -C kernel clean
