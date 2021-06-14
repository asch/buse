obj-m += buse.o
buse-objs := main.o buse-blkdev.o buse-chrdev.o buse-wqueue.o buse-rqueue.o buse-configfs.o

KERNELDIR := /lib/modules/$(shell uname -r)/build

CC += -DDEBUG

install: buse.ko
	sudo cp $(PWD)/buse.ko /lib/modules/$(shell uname -r)/kernel/drivers/block/
	sudo depmod

buse.ko:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
