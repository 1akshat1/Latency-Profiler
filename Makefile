obj-m := latency_profiler.o
CONFIG_MODULE_SIG=n

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all: latency_profiler.c 
	make -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean
run: 
	sudo dmesg --clear && sudo insmod latency_profiler.ko 
remove:
	sudo rmmod latency_profiler