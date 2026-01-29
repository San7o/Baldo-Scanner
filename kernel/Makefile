obj-m   += baldo.o
baldo-objs := common.o \
							netlink.o \
							kprobe.o \
							firewall.o \
							main.o \
							char_dev.o

PWD := $(CURDIR) 
KVERSION = $(shell uname -r)
DEBUG_CFLAGS += -g -DDEBUG

# Use BALDO_CHAR_DEV or BALDO_NETLINK (or both)
ccflags-y := -DBALDO_CHAR_DEV -DBALDO_NETLINK

all: 
	make -C ../linux-src/ M=$(PWD) modules

debug:
	make -C .av.mod.cmd./linux-src/ M=$(PWD) modules EXTRA_CFLAGS="$(DEBUG_CFLAGS)"

clean: 
	make -C ../linux-src/ M=$(PWD) clean
