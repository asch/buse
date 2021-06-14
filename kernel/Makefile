obj-m += buse.o
buse-objs := main.o buse-blkdev.o buse-chrdev.o buse-wqueue.o buse-rqueue.o buse-configfs.o

MODULEDIR := /lib/modules/$(shell uname -r)
KERNELDIR := $(MODULEDIR)/build

#CC += -DDEBUG

install: buse.ko
	sudo cp $(PWD)/$< $(MODULEDIR)/extra/
	sudo strip --strip-debug $(MODULEDIR)/extra/$<
	sudo depmod

buse.ko:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
