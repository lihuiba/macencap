#obj-m := ebt_macencap.o ebt_macdecap.o ebt_msroute.o ebt_dumpskb.o
obj-m := macache.o

fakeall :
	sh make.sh

link :
	sh make.sh link

.PHONY : clean
clean :
	-rm -fr .tmp*
	-rm -f *.o *.ko* *.mod.* .* modules.order Module.symvers
	-make -C ebtables/ clean
