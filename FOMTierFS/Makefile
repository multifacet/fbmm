obj-m += fomtierfs.o
fomtierfs-y += fs.o fomtierfs_rb.o

all:
	make -C ../kbuild M=$(PWD) modules

clean:
	make -C ../kbuild M=$(PWD) clean
