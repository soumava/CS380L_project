obj-m	:= lkm.o

KDIR=/lib/modules/3.11.1/build

EXTRA_CFLAGS += -g

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
