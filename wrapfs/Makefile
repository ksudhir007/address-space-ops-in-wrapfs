WRAPFS_VERSION="0.2"

EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\" $(CRYPTO)

obj-$(CONFIG_WRAP_FS) += wrapfs.o

wrapfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Werror wrapfs_setkey.c -o wrapfs_setkey.o
	gcc test/read_demo.c -o test/read_demo.o
	gcc test/write_demo.c -o test/write_demo.o
default:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Werror wrapfs_setkey.c -o wrapfs_setkey.o
	gcc test/read_demo.c -o test/read_demo.o
	gcc test/write_demo.c -o test/write_demo.o
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
