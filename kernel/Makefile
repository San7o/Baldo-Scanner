obj-m   += av_main.o
av_main-objs := av_netlink.o av_kprobe.o

PWD := $(CURDIR) 
KVERSION = $(shell uname -r)
DEBUG_CFLAGS += -g -DDEBUG

all: 
	make -C ../linux/ M=$(PWD) modules

debug:
	make -C ../linux/ M=$(PWD) modules EXTRA_CFLAGS="$(DEBUG_CFLAGS)"

clean: 
	make -C ../linux/ M=$(PWD) clean
