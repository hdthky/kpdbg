TARGET_MODULE := kpdbg
DEV_PATH := /dev/kpdbg
MAJOR_NUM := 237

obj-m := $(TARGET_MODULE).o

# If we are running without kernel build system
ifeq ($(KERNELRELEASE),)
	BUILDSYSTEM_DIR:=/lib/modules/$(shell uname -r)/build
	# BUILDSYSTEM_DIR:=$(HOME)/kdbg/linux-repro
	PWD:=$(shell pwd)


.PHONY: all clean load unload test clean_test

all:
# run kernel build system to make module
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean: clean_test
# run kernel build system to cleanup in current directory
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean

load:
	insmod $(TARGET_MODULE).ko
	if [ ! -c $(DEV_PATH) ];\
	then mknod $(DEV_PATH) c $(MAJOR_NUM) 0; chmod 666 $(DEV_PATH);\
	else rm $(DEV_PATH); mknod $(DEV_PATH) c $(MAJOR_NUM) 0; chmod 666 $(DEV_PATH); fi

unload:
	if [ -c $(DEV_PATH) ]; then rm $(DEV_PATH); fi
	rmmod $(TARGET_MODULE)

test:
	gcc -g -O0 -DKPDBG_DEV_PATH=\"$(DEV_PATH)\" -o test test.c

clean_test:
	rm -f test

endif