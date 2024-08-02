obj-m +=kernel/hello.o 
PWD := $(CURDIR) 
KVERSION = $(shell uname -r)

all: 
	make -C linux/ M=$(PWD) modules 

clean: 
	make -C linux/ M=$(PWD) clean
