#!/bin/bash

. ./_defines.sh

[ -d $OISOD ] || mkdir $OISOD
[ -d $EISOD ] && {
  rmdir $EISOD || errexit "Remove '$EISOD' first please"
}

OISO=$1
[ -z "$OISO" ] && errexit "Usage: $0 <iso_to_extract>"

mount -o loop,ro $OISO $OISOD || errexit "Can't mount iso '$OISO'"
cp -rf $OISOD $EISOD
umount $OISO || errexit "Can't umount iso from '$OISOD'"
rmdir $OISOD

cd $EISOD 
mkdir $EINITRD
cd $EINITRD
gzip -dc ../${FINITRD} | cpio -i || errexit "Can't read initrd.img"

cd ../
mkdir $EINSTALL
cd $EINSTALL
gzip -dc ../${FINSTALL} | cpio -i || errexit "Can't read install.img"

cd ../
mkdir $ERAMDISK
cd $ERAMDISK
gzip -dc ../${FRAMDISK} | cpio -i || errexit "Can't read ramdisk.img"

cd ../
mkdir -p temporary/$ESYSTEM
mount -o loop,ro ${FSYSSFS} temporary/$ESYSTEM || errexit "Can't mount 'system.sfs' to 'temporary/$ESYSTEM'"
mkdir temporary/${ESYSTEMIMG}
mount -o loop,ro temporary/$ESYSTEM/${FSYSIMG} temporary/${ESYSTEMIMG}
cp -arf temporary/${ESYSTEMIMG} . || errexit "Can't copy files from 'temporary/$ESYSTEM'"
umount temporary/$ESYSTEM/${FSYSIMG} || errexit "Can't umount 'temporary/${ESYSTEMIMG}"
umount ${FSYSSFS} || errexit "Can't umount 'temporary/$ESYSTEM"
rmdir temporary/$ESYSTEM
rmdir temporary/${ESYSTEMIMG}
rmdir temporary

cd $FROM

echo "Extraction seems to went fine, press ENTER"
read foo

