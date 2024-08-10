obj-m   += av.o
av-objs := av_common.o \
           av_netlink.o \
           av_kprobe.o \
		   av_firewall.o \
		   av_main.o \
		   av_char_dev.o

PWD := $(CURDIR) 
KVERSION = $(shell uname -r)
DEBUG_CFLAGS += -g -DDEBUG

# Use AV_CHAR_DEV or AV_NETLINK (or both)
ccflags-y := -DAV_CHAR_DEV -DAV_NETLINK

all: 
	make -C ../linux/ M=$(PWD) modules

debug:
	make -C ../linux/ M=$(PWD) modules EXTRA_CFLAGS="$(DEBUG_CFLAGS)"

clean: 
	make -C ../linux/ M=$(PWD) clean
