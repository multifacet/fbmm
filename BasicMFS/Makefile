obj-m += basicmfs.o
basicmfs-y += basic.o

all:
	make -C ../kbuild M=$(PWD) modules

clean:
	make -C ../kbuild M=$(PWD) clean
