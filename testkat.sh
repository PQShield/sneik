#!/bin/bash

SNEIK=`pwd`
WORKD=`mktemp -d`
echo "Work directory =" $WORKD
AEADMAIN=$SNEIK/common/nist/genkat_aead.c
HASHMAIN=$SNEIK/common/nist/genkat_hash.c
CFLAGS="-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2"

for x in $SNEIK/crypto_aead/*
do
	echo
	y=`basename $x`
	cd $x
	KAT=`echo *.txt`
	echo -n $y "KAT "
	sha256sum $KAT
	cd $x/ref
	gcc $CFLAGS -I. -o $WORKD/ref.$y *.* $AEADMAIN
	cd $x/opt
	gcc $CFLAGS -I. -o $WORKD/opt.$y *.* $AEADMAIN
	cd $WORKD
	rm -f *.txt
	./ref.$y
	echo -n $y "REF "
	sha256sum *.txt
	rm -f *.txt
	./opt.$y
	echo -n $y "OPT "
	sha256sum *.txt

	rm -f *
done

for x in $SNEIK/crypto_hash/*
do
	echo
	y=`basename $x`
	cd $x
	KAT=`echo *.txt`
	echo -n $y "KAT "
	sha256sum $KAT
	cd $x/ref
	gcc $CFLAGS -I. -o $WORKD/ref.$y *.* $HASHMAIN
	cd $x/opt
	gcc $CFLAGS -I. -o $WORKD/opt.$y *.* $HASHMAIN
	cd $WORKD
	rm -f *.txt
	./ref.$y
	echo -n $y "REF "
	sha256sum *.txt
	rm -f *.txt
	./opt.$y
	echo -n $y "OPT "
	sha256sum *.txt

	rm -f *
done

