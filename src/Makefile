ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  
#.PHONY: build clean sneaky_process build
all: sneaky_process build

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c 
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o  

endif
