obj-m += basicmmfs.o
basicmmfs-y += basic.o basic_sysfs.o

all:
	make -C ../kbuild M=$(PWD) modules

clean:
	make -C ../kbuild M=$(PWD) clean
