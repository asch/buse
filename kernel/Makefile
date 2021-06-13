obj-m += buse.o
buse-objs := main.o buse-blkdev.o buse-chrdev.o buse-wqueue.o buse-rqueue.o buse-configfs.o

KERNELDIR := /lib/modules/$(shell uname -r)/build

CC += -DDEBUG

all:
	make -C $(KERNELDIR) M=$(PWD) modules

install:
	sudo cp $(PWD)/buse.ko /lib/modules/$(shell uname -r)/kernel/drivers/block/
	sudo depmod

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
