obj-m := ebt_macencap.o ebt_macdecap.o

fakeall :
	sh make.sh

link :
	sh make.sh link

.PHONY : clean
clean :
	-rm -fr .tmp*
	-rm -f *.o *.ko* *.mod.* .* modules.order Module.symvers
	-make -C ebtables/ clean