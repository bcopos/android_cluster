#!/bin/bash

FROM="$PWD"
OISOD="original_iso.d"
EISOD="edit_iso.d"
NISOD="new_iso.d"
EINITRD="einitrd.img"
EINSTALL="einstall.img"
ERAMDISK="eramdisk.img"
ESYSTEM="esystem.sfs"
ESYSTEMIMG="esystem.img"

FRAMDISK="ramdisk.img"
FINITRD="initrd.img"
FINSTALL="install.img"
FSYSSFS="system.sfs"
FSYSIMG="system.img"

function errexit(){
  echo "Error: $1"
  exit 1
} 

function loopit(){
  LOOP=$( losetup -f )
  [ -z "$LOOP" ] && errexit "Out of free loop devices for now"
  losetup $LOOP $1 || errexit "Can't loop '$1'"
  echo $LOOP
}
