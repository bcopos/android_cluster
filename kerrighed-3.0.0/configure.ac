dnl configure.in for Kerrighed project.
dnl Copyright 2006 Jean Parpaillon <jean.parpaillon@irisa.fr>
dnl Copyright 2007-2009 Jean Parpaillon <jean.parpaillon@kerlabs.com>,
dnl                     Louis Rilling <louis.rilling@kerlabs.com>
dnl
dnl Process this file with autoconf to produce a configure script.

dnl autoconf version
AC_PREREQ(2.59)

dnl mandatory stuff
define([project], [kerrighed])
define([gitversion], esyscmd([sh -c "which git > /dev/null && git describe | sed -e 's/]project[-\([^-]\+\)//' | tr -d '\n' || true"]))dnl
AC_INIT(project, [3.0.0]gitversion, [kerrighed.users@irisa.fr])
AC_DEFINE(GITVERSION, "gitversion", [GIT version])

dnl check host and target
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([-Wno-portability])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES(yes)])
AC_CONFIG_MACRO_DIR([m4])

dnl Add strictness options to the compiler
CFLAGS="$CFLAGS -Wall"
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

srcdir=$(cd $srcdir && pwd)
builddir=$(pwd)

AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_PROG_INSTALL
AC_HEADER_STDC

AC_ARG_ENABLE([user-install],
              [AS_HELP_STRING([--enable-user-install],
                              [Use PREFIX for installing kernel, allowing non-root install @<:@default=disable@:>@])],
              [],
              [enable_user_install=no])
AM_CONDITIONAL([USER_INSTALL], [test "$enable_user_install" = "yes"])

###
### BEGIN KERNEL CHECK
###
vanilla_linux_version=2.6.29
AC_SUBST([vanilla_linux_version])

case $target_cpu in
     i?86)
	kernelarch=i386
       	;;
     x86_64)
	kernelarch=$target_cpu
	;;
     *)
	AC_MSG_ERROR([
       	*** Not available on this architecture: $target_cpu])
       	;;
esac
AC_SUBST(kernelarch)

AC_ARG_ENABLE([kernel],
              [AS_HELP_STRING([--disable-kernel],
                              [Disable automatic kernel build  @<:@default=enable@:>@])],
              [],
              [enable_kernel=yes])
AM_CONDITIONAL([ENABLE_KERNEL], [test "$enable_kernel" = "yes"])

AC_ARG_WITH([kernel-mirror],
            [AS_HELP_STRING([--with-kernel-mirror],
                            [kernel.org mirror used to get vanilla kernel @<:@default=ftp.eu.kernel.org@:>@])],
            [],
            [kernel_mirror="ftp.eu.kernel.org"])
AC_SUBST([kernel_mirror])

AC_ARG_WITH([kernel-config-file],
            [AS_HELP_STRING([--with-kernel-config-file],
                            [.config file for kernel building, do not use this option with --with-kernel-config @<:@default=none@:>@])],
            [kernel_config_file="$withval"])
AC_ARG_WITH([kernel-config],
            [AS_HELP_STRING([--with-kernel-config],
                            [config|menuconfig|xconfig|gconfig|defconfig|allmodconfig|allyesconfig|allnoconfig @<:@default=defconfig@:>@])],
            [kernel_config="$withval"])
if test -n "$kernel_config_file" -a -n "$kernel_config"; then
   AC_MSG_ERROR([
   *** --with-kernel-config and --with-kernel-config-file are incompatible])
fi
if test -z "$kernel_config_file" -a -z "$kernel_config"; then
   kernel_config=defconfig
fi
if test -n "$kernel_config"; then
   case $kernel_config in
     config|menuconfig|xconfig|gconfig|defconfig|allmodconfig|allyesconfig|allnoconfig) true;;
     *)
	AC_MSG_ERROR([
	*** Unknown kernel config target: $kernel_config])
   esac
fi
if test -n "$kernel_config_file"; then
   kernel_config_file=$(cd $(dirname $kernel_config_file) && pwd)/$(basename $kernel_config_file)
fi
AC_SUBST([kernel_config_file])
AC_SUBST([kernel_config])

if test "x$enable_kernel" = "xyes"; then
   AC_CHECK_PROG(bzip2, bzip2, yes,)
   if test -z "$bzip2"; then
     AC_MSG_ERROR([
       *** You need bzip2 tool])
   fi
   AC_CHECK_PROG(patch, patch, yes,)
   if test -z "$patch"; then
     AC_MSG_ERROR([
       *** You need patch tool])
   fi
   AC_CHECK_PROG(wget, wget, yes,)
   if test -z "$wget"; then
     AC_MSG_ERROR([
       *** You need wget tool])
   fi
fi

if test -e $srcdir/kernel/include/linux/kernel.h; then
   kernel_srcdir=\$\(top_srcdir\)/kernel
else
   kernel_srcdir=\$\(top_builddir\)/_kernel
fi
AC_SUBST([kernel_srcdir])
###
### END KERNEL CHECK
###

###
### BEGIN LIBRARIES CHECK
###
AC_ARG_ENABLE([libkerrighed],
	      [AS_HELP_STRING([--disable-libkerrighed],
			      [Disable libkerrighed @<:@default=enable@:>@])],
	      [],
	      [enable_libkerrighed=yes])
AM_CONDITIONAL([ENABLE_LIBKERRIGHED], [test "$enable_libkerrighed" = "yes"])

PYTHON_VERSION_MIN=2.5
AC_ARG_ENABLE([python],
				[AS_HELP_STRING([--disable-python],
								[Disable Python code @<:@default=enable@:>@])],
								[],
								[enable_python=yes])
if test "x$enable_python" = "xyes"; then
	 AM_PATH_PYTHON([$PYTHON_VERSION_MIN],, [:])
	 if test "$PYTHON" = ":"; then
	 		AC_MSG_ERROR([
        *** You need python >= $PYTHON_VERSION_MIN (or --disable-python)])
   fi
fi
AM_CONDITIONAL([ENABLE_PYTHON], [test "$enable_python" = "yes"])
###
### END LIBRARIES CHECK
###

###
### BEGIN TOOLS CHECK
###
AC_ARG_ENABLE([tools],
              [AS_HELP_STRING([--disable-tools],
                              [Disable tools @<:@default=enable@:>@])],
              [],
              [enable_tools=yes])
if test "x$enable_libkerrighed" != "xyes"; then
   enable_tools=no
   AC_MSG_WARN([Disabling libkerrighed also disable tools compilation])
fi
AM_CONDITIONAL([ENABLE_TOOLS], [test "$enable_tools" = "yes"])

AC_ARG_ENABLE([host-tools],
              [AS_HELP_STRING([--disable-host-tools],
                              [Disable kerrighed host tools @<:@default=enable@:>@])],
              [],
              [enable_host_tools="yes"])
AM_CONDITIONAL([ENABLE_HOST_TOOLS], [test "$enable_host_tools" = "yes"])

AC_ARG_ENABLE([preserve-conf],
              [AS_HELP_STRING([--enable-preserve-conf],
                              [Preserve configuration files if exist @<:@default=disable@:>@])],
              [],
              [enable_preserve_conf="no"])
AM_CONDITIONAL([ENABLE_PRESERVE_CONF], [test "$enable_preserve_conf" = "yes"])
###
### END TOOLS CHECK
###

###
### BEGIN TESTS CHECK
###
AC_ARG_ENABLE([tests],
              [AS_HELP_STRING([--enable-tests],
                              [Globally enable tests @<:@default=disable@:>@])],
              [],
              [enable_tests=no])
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])

AC_ARG_ENABLE([tests-ktp],
              [AS_HELP_STRING([--disable-tests-ktp],
                              [Disable 'ktp' tests @<:@default=enable@:>@])],
              [],
              [enable_tests_ktp=yes])
AC_ARG_ENABLE([tests-apps],
              [AS_HELP_STRING([--disable-tests-apps],
                              [Disable 'apps' tests @<:@default=enable@:>@])],
              [],
              [enable_tests_apps=yes])
AC_ARG_ENABLE([tests-proc],
              [AS_HELP_STRING([--disable-tests-proc],
                              [Disable 'proc' tests @<:@default=enable@:>@])],
              [],
              [enable_tests_proc=yes])
AC_ARG_ENABLE([tests-benchmark],
              [AS_HELP_STRING([--disable-tests-benchmark],
                              [Disable 'benchmark' tests @<:@default=enable@:>@])],
              [],
              [enable_tests_benchmark=yes])

AM_CONDITIONAL([ENABLE_KTP], [test "$enable_tests_ktp" = "yes" -a "x$enable_tests" = "xyes"])
AM_CONDITIONAL([ENABLE_APPS], [test "$enable_tests_apps" = "yes" -a "x$enable_tests" = "xyes"])
AM_CONDITIONAL([ENABLE_PROC], [test "$enable_tests_proc" = "yes" -a "x$enable_tests" = "xyes"])
AM_CONDITIONAL([ENABLE_BENCHMARK], [test "$enable_tests_benchmark" = "yes" -a "x$enable_tests" = "xyes"])

AC_ARG_WITH([ltp-base],
            [AS_HELP_STRING([--with-ltp-base=PATH],
                            [Path to ltp base dir @<:@default=DATAROOTDIR/ltp@:>@])],
            [ltpbase="$withval"],
            [ltpbase="${datadir}/ltp"])
AC_SUBST([ltpbase])
###
### END TESTS CHECK
###

###
### BEGIN CHECK FOR DOCBOOK TOOLS
###
AC_CHECK_PROG(xsltproc, xsltproc, yes, no)
###
### END CHECK FOR DOCBOOK TOOLS
###

AC_CONFIG_HEADERS([config.h])

dnl files to generate with automake
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([patches/Makefile])
AC_CONFIG_FILES([libs/Makefile libs/include/Makefile libs/libkerrighed/Makefile libs/libkerrighed/kerrighed.pc libs/libkrgcb/Makefile libs/libkrgcb/krgcb.pc libs/libkrgcheckpoint/Makefile libs/libkrgcheckpoint/krgcheckpoint.pc])
AC_CONFIG_FILES([tools/Makefile])
AC_CONFIG_FILES([tools-host/Makefile])
AC_CONFIG_FILES([man/Makefile])
AC_CONFIG_FILES([tests/Makefile tests/include/Makefile tests/apps/Makefile tests/proc/Makefile])
AC_CONFIG_FILES([tests/ktp/Makefile tests/ktp/cr/Makefile tests/benchmark/Makefile])

dnl write all stuff
AC_OUTPUT

if test "$enable_kernel" = "yes"; then
  dnl Prepare kernel sources
  AC_MSG_NOTICE([Prepare kernel sources])
  make --no-print-directory kernel-prepare
  AC_MSG_NOTICE([Configure kernel sources])
  make --no-print-directory kernel-config
fi

###
### Display results
###
echo "********************************************************************"
echo "  Kerrighed configuration is now complete"
echo "********************************************************************"
echo ""
echo -n "    - Kernel configuration     : "
if test -n "$kernel_config_file"; then
   echo "file:$kernel_config_file"
else
   echo "$kernel_config"
fi
echo "    - Target architecture      : $kernelarch"
echo "    - libkerrighed             : $enable_libkerrighed"
echo "    - libkerrighed Python      : $enable_python"
echo "    - Kerrighed tools          : $enable_tools"
echo "    - Kerrighed host tools     : $enable_host_tools"
echo "    - Manpages build           : $xsltproc (only needed in maintainer mode)"
echo ""
echo "    - Kerrighed tests          : $enable_tests"
if test "x$enable_tests" = "xyes"; then
echo "    - Kerrighed apps tests     : $enable_tests_apps"
echo "    - Kerrighed proc tests     : $enable_tests_proc"
echo "    - Kerrighed ktp tests      : $enable_tests_ktp"
echo "    - Kerrighed benchmark tests: $enable_tests_benchmark"
fi
echo "********************************************************************"
echo ""
echo " To build the system:"
echo ""

if test "$enable_kernel" = "no"; then
echo " - run 'make kernel-prepare' to fetch Linux sources and apply Kerrighed patch"
echo " - run 'make kernel-config' to configure kernel"
echo " - run 'make kernel' to build kernel"
echo ""
fi

echo " - run 'make'"
if test "$enable_kernel" = "no"; then
echo " - as root, run 'make kernel-install' "
fi
echo " - as root, run 'make install'"
echo ""

if test "$enable_kernel" = "yes"; then
  echo " If you want to configure, compile and install Kerrighed kernel manually, "
  echo " kernel/ dir contains the Kerrighed-patched Linux source tree"
fi
echo "********************************************************************"
