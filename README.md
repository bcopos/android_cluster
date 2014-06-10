linux 2.6.29 kerrighed
======================

START KERRIGHED ON KRG ANDROID KERNEL:


INSTRUCTIONS FOR SETTING UP KERRIGHED NODES:

1. create tap interfaces: `openvpn –mktun –dev tap0` and `openvpn –mktun –dev tap1`
2. `brctl addbr [name]`
3. `brctl addif tap0`
4. `brctl addif tap1`
5. setup tap0, tap1 to have some IP addr (192.168.1.1/2.1)
6. start two qemu emulators running patched linux and rootfs, same session_id, *different* node_id, *different* tap interfaces, *different* macaddr
`qemu-system-x86_64 -kernel Downloads/good/bzImage -initrd Downloads/rootfs.ext2 -append "root=/dev/ram session_id=1 node_id=1 ramdisk_size=128000" -net nic,model=e1000,macaddr=00:11:22:33:44:55 -net tap,ifname=tap0,script=no,downscript=no`
== ON ANDROID KERRIGHED KERNEL ONLY ===
7. `/etc/init.d/kerrighed-host start`
8. `krgboot -imp -- /sbin/krginit-helper` (don't run krgboot_helper, the -u flag causes to crash)
==
9. inside one node, ssh into kerrighed-container: `ssh user@localhost -p 2222`
10. inside the kerrighed-container: `krgadm nodes add -a`
11. check proc/cpuinfo: `cat /proc/cpuinfo`


ANDROID_X86 donut (1.6)

1. get `repo` tool
2. `repo init -u git://android-x86.git.sf.net/gitroot/android-x86/manifest.git -b donut-x86` (other links don't work)
3. `repo sync`
4. To patch: `patch p1 -R < android.patch`

NETWORK IN QEMU:

1. `ifconfig eth0 up`
2. `udhcpc`
3. check ifconfig or try ping-ing


INSTRUCTIONS TO QUICKLY BOOT IMAGE:

1. install qemu
2. edit path in run.sh if bash shell is not located at /bin/bash
3. `./run.sh`


INSTRUCTIONS FOR ROOTFS:

1. Download Buildroot src
2. make help
3. choose an option from two and make
4. rootfs img will be in output/images

Hints:
- run menuconfig to add utilities and libraries (openssh, openssl, etc)
- if needed, use glibc toolchain (toolchain options)
- populate dev (tty, tty1, null, urandom)
- edit etc/network/interfaces to have internet access 
- mount rootfs image and install kerrighed there (prefix=/path/to/rootfs/mount)
- copy /lib/lsb/init-functions from ubuntu vm or somewhere... kerrighed-host uses it

INSTRUCTIONS FOR QEMU:

- qemu-system-x86_64 -kernel [path]/[to]/bzImage -initrd [path]/[to]/rootfs.img -append "root=/dev/ram"
	OR
- qemu-system-x86_64 -kernel [path]/[to]/bzImage -initrd [path]/[to]/rootfs.img -nographic -append "root=/dev/ram console=ttyS0,115200" -vga vmware

INSTRUCTIONS FOR SAVING VM IN QEMU:
- create QEMU disk image: `qemu-img create -f qcow2 test.qcow2 1G`
- add the disk image to run.sh: `-hda test.qcow2`
- `./run.sh`
- enter 'ctrl'+'alt'+'shift'+'2' to enter QEMU monitor mode
- `savevm newvm` -- your VM is now saved in test.qcow2
- enter 'ctrl'+'alt'+'shift'+'1' to exit QEMU monitor mode

INSTRUCTIONS FOR LOADING VM IN QEMU:
- add the existing disk image to the run.sh script: `-hda test.qcow2`
- `./run.sh`
- enter QEMU monitor mode
- `loadvm newvm`

Links:

1. http://www.tldp.org/HOWTO/Bootdisk-HOWTO/buildroot.html

INSTRUCTION FOR BUILDING KERRIGHED LIBS AND APPS:

1. inside kerrighed dir: `./configure -disable-kernel`
2. `make distclean`
3. `./autogen.sh`
4. `./configure --disable-kernel --prefix=/path/to/`
5. `make install`

INSTRUCTIONS FOR BUILDING KERNEL:

1. `cp -R linux-2.6.29 kerrighed/patches/.`
2. inside kerrighed dir: `./configure`
3. `cd _kernel`
4. `make x86_64_defconfig`
5. `make`
4. bzImage file will be in kerrighed/kernel/arch/x86/boot/

NOTES:
- use gcc-4.4
- kerrighed will download linux-2.6.29.tar.bz -- this is OK
- however, make sure that during the configuration process, it does NOT unzip the linux source it just downloaded and instead uses the one already in the patches directory
- the linux-2.6.29 in the kerrighed/patches directory is a symlink to the linux-2.6.29 in the root directory of the repo

