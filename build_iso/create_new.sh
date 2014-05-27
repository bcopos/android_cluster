#!/bin/bash

. _defines.sh

NISO=$1
[ -z "$NISO" ] && errexit "Usage: $0 <name>"

[ -d $EISOD ] || errexit "'$EISOD' does not exist"
[ -d $NISOD ] && {
  rm -rf $NISOD || errexit "Can not remove $NISOD"
}
mkdir $NISOD

ESYSTEMIMG=${FROM}/${EISOD}/${ESYSTEMIMG}
SSIZE=$( du -cm ${ESYSTEMIMG} | tail -n1 | awk '{print $1}' )
SSIZE=$(( $SSIZE + ($SSIZE / 10) ))
ESYSTEM=${FROM}/${NISOD}/${ESYSTEM}
FSYSSFS=${FROM}/${NISOD}/${FSYSSFS}
mkdir ${ESYSTEM}
FSYSIMG=${ESYSTEM}/${FSYSIMG}
dd if=/dev/zero of=${FSYSIMG} bs=1M count=0 seek=${SSIZE} || errexit "Can't create '${FSYSIMG}' size of ${SSIZE}"
LOOP=$( loopit ${FSYSIMG} )
[ -z "$LOOP" ] && errexit "Can't loop '${FSYSIMG}'"
mkfs.ext4 $LOOP || errexit "Error while formatting $LOOP"
mkdir temp
mount $LOOP temp || errexit "Error mounting $LOOP to temp"
cp -arf ${ESYSTEMIMG}/* temp || errexit "Error copying ${ESYSTEMIMG} on $LOOP"
umount $LOOP || errexit "Can't umount $LOOP from temp"
rmdir temp
losetup -d $LOOP || errexit "Can't free $LOOP"
mksquashfs ${ESYSTEM} ${FSYSSFS} || errexit "Error making squash filesystem"
rm -rf ${ESYSTEM}

ERAMDISK=${FROM}/${EISOD}/${ERAMDISK}
FRAMDISK=${FROM}/${NISOD}/${FRAMDISK}
cd ${ERAMDISK} || errexit "Can not cd into ${ERAMDISK}"
find . | cpio --create --format='newc' | gzip -c > ${FRAMDISK} || errexit "Can not cpio ${FRAMDISK}"

EINSTALL=${FROM}/${EISOD}/${EINSTALL}
FINSTALL=${FROM}/${NISOD}/${FINSTALL}
cd ${EINSTALL} || errexit "Can not cd into ${EINSTALL}"
find . | cpio --create --format='newc' | gzip -c > ${FINSTALL} || errexit "Can not cpio ${FINSTALL}"

EINITRD=${FROM}/${EISOD}/${EINITRD}
FINITRD=${FROM}/${NISOD}/${FINITRD}
cd ${EINITRD} || errexit "Can not cd into ${EINITRD}"
find . | cpio --create --format='newc' | gzip -c > ${FINITRD} || errexit "Can not cpio ${FINITRD}"

cd ${FROM}/${EISOD}
for F in isolinux TRANS.TBL kernel ; do
  cp -arf $F ${FROM}/${NISOD} || errexit "Can't copy ${F} to ${FROM}/${NISOD}"
done

cd ${FROM}/${NISOD}
NISO=${FROM}/${NISO}
mkisofs -o $NISO  -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -J -R -V disks . || errexit "Can't create iso image"

cd ${FROM}

#isohybrid -o $NISO || errexit "Can not make iso hybrid. It will not be possible to boot it from USB key"

echo "Procedure seems to went fine, press ENTER"
read foo


