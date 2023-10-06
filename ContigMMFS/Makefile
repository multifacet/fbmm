obj-m += contigmmfs.o
contigmmfs-y += contig.o

all:
	make -C ../kbuild M=$(PWD) modules

clean:
	make -C ../kbuild M=$(PWD) clean
