#obj-m += kernel/hello.o 
obj-m += kernel/av_kprobe.o
#obj-m += kernel/av_systable.o
PWD := $(CURDIR) 
KVERSION = $(shell uname -r)
DEBUG_CFLAGS += -g -DDEBUG

all: 
	make -C linux/ M=$(PWD) modules 

debug:
	make -C linux/ M=$(PWD) modules EXTRA_CFLAGS="$(DEBUG_CFLAGS)"

clean: 
	make -C linux/ M=$(PWD) clean
