obj-m += buse.o
buse-objs := main.o buse-blkdev.o buse-chrdev.o buse-wqueue.o buse-rqueue.o buse-configfs.o

MODULEDIR := /lib/modules/$(shell uname -r)
KERNELDIR := $(MODULEDIR)/build

#CC += -DDEBUG

build: buse.ko

buse.ko:
	make -C $(KERNELDIR) M=$(shell pwd) modules

install: buse.ko
	install -D -m 644 $(shell pwd)/$< $(MODULEDIR)/extra/$<
	strip --strip-debug $(MODULEDIR)/extra/$<
	depmod

clean:
	make -C $(KERNELDIR) M=$(shell pwd) clean
