#!/bin/bash

SNEIK=`pwd`
WORKD=`mktemp -d`
echo "Work directory =" $WORKD
AEADMAIN=$SNEIK/common/nist/genkat_aead.c
HASHMAIN=$SNEIK/common/nist/genkat_hash.c
CC=gcc
CFLAGS="-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2"
TARGETS="ref opt"

#These work if you have the right crosss-compiler and QEMU binfmt support
#CC=arm-linux-gnueabihf-gcc
#CFLAGS="-std=c99 -Wall -static -O2 -march=armv7"
#TARGETS="ref opt armv7"

#CC=riscv64-unknown-linux-gnu-gcc
#CFLAGS="-std=c99 -Wall -static -O2 -march=rv32g -mabi=ilp32"
#TARGETS="ref opt rv32i"

echo "Compiler = " $CC $CFLAGS

for algpath in $SNEIK/crypto_aead/*
do
	echo
	algname=`basename $algpath`
	cd $algpath
	KAT=`echo *.txt`
	echo -en $algname "\t kat\t"
	sha256sum $KAT

	for targ in $TARGETS
	do
		cd $algpath/$targ
		sources=`ls *.* | grep -v '\.h'`
		$CC $CFLAGS -I. -o $WORKD/$targ.$algname $sources $AEADMAIN
		cd $WORKD
		./$targ.$algname
		echo -en $algname "\t" $targ "\t"
		sha256sum *.txt
		rm -f *
	done
done

for algpath in $SNEIK/crypto_hash/*
do
	echo
	algname=`basename $algpath`
	cd $algpath
	KAT=`echo *.txt`
	echo -en $algname "\t kat\t"
	sha256sum $KAT

	for targ in $TARGETS
	do
		cd $algpath/$targ
		sources=`ls *.* | grep -v '\.h'`
		$CC $CFLAGS -I. -o $WORKD/$targ.$algname $sources $HASHMAIN
		cd $WORKD
		./$targ.$algname
		echo -en $algname "\t" $targ "\t"
		sha256sum *.txt
		rm -f *
	done
done

