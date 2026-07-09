obj-m += KVM-XJ.o
CFLAGS_KVM-XJ.o := -mindirect-branch=keep -mfunction-return=keep

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean