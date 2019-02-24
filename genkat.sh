#!/bin/bash

SNEIK=`pwd`
WORKD=`mktemp -d`
echo "Work directory =" $WORKD
AEADMAIN=$SNEIK/common/nist/genkat_aead.c
HASHMAIN=$SNEIK/common/nist/genkat_hash.c
CFLAGS="-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2"

for x in $SNEIK/crypto_aead/*
do
	y=`basename $x`
	cd $x/ref
	gcc $CFLAGS -I. -o $WORKD/test.$y *.* $AEADMAIN
	cd $WORKD
	./test.$y
	echo -n $y ": "
	sha256sum *.txt
	cp *.txt $x
	rm -f *
done

for x in $SNEIK/crypto_hash/*
do
	y=`basename $x`
	cd $x/ref
	gcc $CFLAGS -I. -o $WORKD/test.$y *.* $HASHMAIN
	cd $WORKD
	./test.$y
	echo -n $y ": "
	sha256sum *.txt
	cp *.txt $x
	rm -f *
done

rm -rf $WORKD

