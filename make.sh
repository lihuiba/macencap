#!/bin/sh

kernel=/usr/src/kernels/`uname -r`
include=$kernel/include/linux/netfilter_bridge
echo "using kernel from '$kernel'"

if [ $1 == "link" ]; then
	for file in ebt_macencap.h ebt_macdecap.h ebt_msroute.h; do
		target="$include/$file"
		if [ ! -e $target ]; then
			ln -v `pwd`/$file $target -s
		else
			echo "target exists: $target"
		fi
	done
	exit
fi

make -C $kernel modules M=$PWD
#make -C ebtables/
