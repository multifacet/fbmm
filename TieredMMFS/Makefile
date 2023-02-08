obj-m += tieredmmfs.o
tieredmmfs-y += fs.o tieredmmfs_rb.o

all:
	make -C ../kbuild M=$(PWD) modules

clean:
	make -C ../kbuild M=$(PWD) clean
