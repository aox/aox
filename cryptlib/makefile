#****************************************************************************
#*																			*
#*							Makefile for cryptlib 3.1						*
#*						Copyright Peter Gutmann 1995-2003					*
#*																			*
#****************************************************************************

# This makefile contains extensive amounts of, uhh, business logic which,
# alongside further logic in the cryptlib OS-specific header files, ensures
# that cryptlib auto-configures itself and builds out of the box on most
# systems.  Before you ask about redoing the makefile using autoconf, have a
# look at what it would take to move all of this logic across to another
# build mechanism.
#
# "The makefile is looking really perverse.  You're getting the hang of it"
#														- Chris Wedgwood.
# At least it doesn't pipe itself through sed yet.
#
# (Note that as of 3.1 beta 3, it does pipe itself through sed on non-Unix
#  systems to retarget Unix-specific files to OS-specific ones).
#
# The self-test program pulls in parts of cryptlib to ensure that the self-
# configuration works.  Because this is handled by the makefile, you can't
# just 'make testlib' after making changes, you need to use 'make; make
# testlib'.

# Naming information: Major and minor version numbers and project and library
# names (static lib, shared lib, and OS X dylib).  The patch level is always
# zero because patches imply bugs and my code is perfect.

MAJ		= 3
MIN		= 1
PLV		= 0
PROJ	= cl
LIBNAME	= lib$(PROJ).a
SLIBNAME = lib$(PROJ).so.$(MAJ).$(MIN).$(PLV)
DYLIBNAME = lib$(PROJ).$(MAJ).$(MIN).dylib

# Extra compiler options for debugging.  Add this to the CFLAGS to provide an
# extra level of warnings about potential problems when using gcc.  The
# -Wno-switch is necessary because all cryptlib attributes are declared from
# a single pool of enums, but only the values for a particular object class
# are used in the object-specific code, leading to huge numbers of warnings
# about unhandled enum values in case statements.  The additional warning
# types are:
#
# -Wshadow: Warn whenever a local variable shadows another local variable,
#		parameter or global variable (that is, a local of the same name as
#		an existing variable is declared in a nested scope).  Note that this
#		leads to some false positives as gcc treats forward declarations of
#		functions within earlier functions that have the same parameters as
#		the function they're declared within as shadowing.  This can be
#		usually detected in the output by noting that a pile of supposedly
#		shadow declarations occur within a few lines of one another.
#
# -Wpointer-arith: Warn about anything that depends on the "size of' a
#		function type or of "void".
#
# -Wcast-align: Warn whenever a pointer is cast such that the required
#		alignment of the target is increased, for example if a "char *" is
#		cast to an "int *".
#
# -Wstrict-prototypes: Warn if a function is declared or defined K&R-style.
#
# -Wredundant-decls: Warn if anything is declared more than once in the same
#		scope.
#
# Note that some of these require the use of at least -O2 in order to be
# detected because they require the use of various levels of data flow
# analysis by the compiler.  However, when this is used the optimiser
# interacts badly with -Wunreachable-code due to statements rearranged by
# the optimiser being declared unreachable, so we don't enable this warning.

DEBUG_FLAGS	= -Wall -Wno-switch -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wredundant-decls

# Compiler options.  The IRIX cc doesn't recognise -fPIC, but generates PIC
# by default anyway, so to make this work under IRIX just remove the -fPIC.
# The PHUX compiler requires +z for PIC.  OS X generates PIC by default, but
# doesn't mind having -fPIC specified anyway.
#
# By default this builds the release version of the code, to build the debug
# version (which is useful for finding compiler bugs and system-specific
# peculiarities) remove the NDEBUG define.  Many problems will now trigger an
# assertion at the point of failure rather than returning an error status
# from 100 levels down in the code.
#
# Note that the gcc build uses -fomit-frame-pointer to free up an extra
# register on x86 (which desperately needs it), this will screw up gdb if
# you try and debug a version compiled with this option.
#
# If the OS supports it, the multithreaded version of cryptlib will be built.
# To specifically disable this, add -DNO_THREADS.

CFLAGS		= -c -D__UNIX__ -DNDEBUG -I.
SCFLAGS 	= -fPIC -c -D__UNIX__ -DNDEBUG -I.

# Symbian OS: Usually handled via cross-compilation, which requires custom
# code paths to build using the Symbian SDK rather than the native compiler.
# The following defines are for Symbian OS 7.x as the SDK and ARM as the
# architecture.

# EPOC		= /usr/local/symbian/7.0
# CXX		= ${EPOC}/bin/arm-epoc-pe-g++
# CC		= ${EPOC}/bin/arm-epoc-pe-gcc
# AR		= ${EPOC}/bin/arm-epoc-pe-ar
# LD		= ${EPOC}/bin/arm-epoc-pe-ld
# CPP		= ${EPOC}/bin/arm-epoc-pe-cpp
# RANLIB	= ${EPOC}/bin/arm-epoc-pe-ranlib
# STRIP		= ${EPOC}/bin/arm-epoc-pe-strip
# INCS		= -I$(EPOC)/include/libc

# To link the self-test code with a key database, uncomment the following
# and substitute the name or names of the database libraries you'll be using.

# TESTLIB	= -lmysql
# TESTLIB	= -L/oracle/product/server/9i/lib -lclient9

# Paths and command names.  We have to be careful with comments attached to
# path defines because some makes don't strip trailing spaces.
#
# The reason for the almost-identical defines for path and dir is because of
# the braindamaged BSDI mkdir (and rmdir) that break if the path ends in a
# '/', it's easier to have separate defines than to drop a '/' into every
# path.
#
# The options for the shared library link should work on most systems that
# handle shared libraries, but may need to be tuned for some systems since
# there's no standard for shared libraries, and different versions of gcc
# also changed the way this was handled.  If the current line doesn't work,
# try one of the following ones:
#
# AIX:			AIX requires some weird voodoo which is unlike any other
#				system's way of doing it (probably done by the MVS team,
#				see "AIX Linking and Loading Mechanisms" for a starter).
#				In addition to this, the shared lib (during development)
#				must be given permissions 750 to avoid loading it
#				permanently into the shared memory segment (only root can
#				remove it).  The production shared library must have a
#				555 (or whatever) permission.  The various options are:
#				-bnoentry = don't look for a main(), -bE = export the symbols
#				in cryptlib.exp, -bM:SRE = make it a shared library.
#				$(LD) -ldl -bE:cryptlib.exp -bM:SRE -bnoentry
# BeOS:			$(LD) -nostart
# *BSD's:		$(LD) -Bshareable -o lib$(PROJ).so.$(MAJ)
# Cygwin:		$(LD) -L/usr/local/lib -lcygipc
# HPUX:			$(LD) -shared -Wl,-soname,lib$(PROJ).so.$(MAJ)
# IRIX, OSF/1:	$(LD) -shared -o lib$(PROJ).so.$(MAJ)
# Linux:		$(LD) -Bshareable -ldl -o lib$(PROJ).so.$(MAJ)
# Solaris:		$(LD) -G -ldl -o lib$(PROJ).so.$(MAJ)

STATIC_OBJ_PATH = ./static-obj/
STATIC_OBJ_DIR = ./static-obj
SHARED_OBJ_PATH = ./shared-obj/
SHARED_OBJ_DIR = ./shared-obj
CPP			= $(CC) -E
LD			= $(CC)					# Static link
SLD			= $(LD) -shared			# Shared link
SHELL		= /bin/sh
OSNAME		= `uname`

# Default target and obj file path.  This is changed depending on whether
# we're building the static or shared library, the default is to build the
# static library.

TARGET		= $(LIBNAME)
OBJPATH		= $(STATIC_OBJ_PATH)

# Some makes don't pass defines down when they recursively invoke make, so we
# need to manually pass them along.  The following macro contains all defines
# that we want to pass to recursive calls to make.

DEFINES		= $(TARGET) OBJPATH=$(OBJPATH) OSNAME=$(OSNAME)

# Cross-compilation/non-Unix options, which are just the standard ones with
# Unix-specific entries (-D__UNIX__, use of uname to identify the system)
# removed.  The actual values are explicitly given in the rules for each non-
# Unix target.

XCFLAGS		= -c -DNDEBUG -I.
XDEFINES	= $(TARGET) OBJPATH=$(OBJPATH)

#****************************************************************************
#*																			*
#*								Common Dependencies							*
#*																			*
#****************************************************************************

# The object files that make up the library.  When building the Java version,
# $(OBJPATH)cryptjni.o should be added to the OBJS line to replace the
# cryptapi.o used to provide the C interface.

ASMOBJS		= $(OBJPATH)md5asm.o $(OBJPATH)rmdasm.o $(OBJPATH)sha1asm.o

BNOBJS		= $(OBJPATH)bn_add.o $(OBJPATH)bn_asm.o $(OBJPATH)bn_ctx.o \
			  $(OBJPATH)bn_div.o $(OBJPATH)bn_exp.o $(OBJPATH)bn_exp2.o \
			  $(OBJPATH)bn_gcd.o $(OBJPATH)bn_lib.o $(OBJPATH)bn_mod.o \
			  $(OBJPATH)bn_mont.o $(OBJPATH)bn_mul.o $(OBJPATH)bn_recp.o \
			  $(OBJPATH)bn_shift.o $(OBJPATH)bn_sqr.o $(OBJPATH)bn_word.o

CERTOBJS	= $(OBJPATH)certcget.o $(OBJPATH)certchk.o  $(OBJPATH)certchn.o \
			  $(OBJPATH)certcset.o $(OBJPATH)certdn.o $(OBJPATH)certechk.o \
			  $(OBJPATH)certedef.o $(OBJPATH)certexrd.o $(OBJPATH)certext.o \
			  $(OBJPATH)certexwr.o $(OBJPATH)certio.o $(OBJPATH)certrd.o \
			  $(OBJPATH)certrev.o $(OBJPATH)certsig.o $(OBJPATH)certstr.o \
			  $(OBJPATH)certrust.o $(OBJPATH)certval.o $(OBJPATH)certwr.o

CRYPTOBJS	= $(OBJPATH)aescrypt.o $(OBJPATH)aeskey.o $(OBJPATH)aestab.o \
			  $(OBJPATH)bfecb.o $(OBJPATH)bfenc.o $(OBJPATH)bfskey.o \
			  $(OBJPATH)castecb.o $(OBJPATH)castenc.o $(OBJPATH)castskey.o \
			  $(OBJPATH)descbc.o $(OBJPATH)desecb.o $(OBJPATH)desecb3.o \
			  $(OBJPATH)desenc.o $(OBJPATH)desskey.o $(OBJPATH)icbc.o \
			  $(OBJPATH)iecb.o $(OBJPATH)iskey.o $(OBJPATH)rc2cbc.o \
			  $(OBJPATH)rc2ecb.o $(OBJPATH)rc2skey.o $(OBJPATH)rc4enc.o \
			  $(OBJPATH)rc4skey.o $(OBJPATH)rc5ecb.o $(OBJPATH)rc5enc.o \
			  $(OBJPATH)rc5skey.o $(OBJPATH)skipjack.o

DEVOBJS		= $(OBJPATH)dev_fort.o $(OBJPATH)dev_pk11.o $(OBJPATH)dev_sys.o

ENVOBJS		= $(OBJPATH)denv_cms.o $(OBJPATH)denv_pgp.o $(OBJPATH)env_cms.o \
			  $(OBJPATH)env_dec.o $(OBJPATH)env_enc.o $(OBJPATH)env_pgp.o \
			  $(OBJPATH)pgp_misc.o $(OBJPATH)resource.o

HASHOBJS	= $(OBJPATH)md2dgst.o $(OBJPATH)md4dgst.o $(OBJPATH)md5dgst.o \
			  $(OBJPATH)rmddgst.o $(OBJPATH)sha1dgst.o

KEYSETOBJS	= $(OBJPATH)dbxdbms.o $(OBJPATH)dbxdbx.o $(OBJPATH)dbxdca.o \
			  $(OBJPATH)dbxhttp.o $(OBJPATH)dbxldap.o $(OBJPATH)dbxmysql.o \
			  $(OBJPATH)dbxoracl.o $(OBJPATH)dbxpgp.o $(OBJPATH)dbxp12.o \
			  $(OBJPATH)dbxp15.o $(OBJPATH)dbxp15r.o $(OBJPATH)dbxp15w.o \
			  $(OBJPATH)dbxpostg.o

LIBOBJS		= $(OBJPATH)cryptapi.o $(OBJPATH)cryptcfg.o $(OBJPATH)cryptcrt.o \
			  $(OBJPATH)cryptctx.o $(OBJPATH)cryptdbx.o $(OBJPATH)cryptdev.o \
			  $(OBJPATH)cryptenv.o $(OBJPATH)cryptkey.o $(OBJPATH)cryptkrn.o \
			  $(OBJPATH)cryptlib.o $(OBJPATH)cryptmch.o $(OBJPATH)cryptmis.o \
			  $(OBJPATH)cryptses.o $(OBJPATH)cryptusr.o $(OBJPATH)lib_3des.o \
			  $(OBJPATH)lib_aes.o $(OBJPATH)lib_bf.o $(OBJPATH)lib_cast.o \
			  $(OBJPATH)lib_des.o $(OBJPATH)lib_dh.o $(OBJPATH)lib_dsa.o \
			  $(OBJPATH)lib_elg.o $(OBJPATH)lib_hmd5.o $(OBJPATH)lib_hrmd.o \
			  $(OBJPATH)lib_hsha.o $(OBJPATH)lib_idea.o $(OBJPATH)lib_kg.o \
			  $(OBJPATH)lib_md2.o $(OBJPATH)lib_md4.o $(OBJPATH)lib_md5.o \
			  $(OBJPATH)lib_rc2.o $(OBJPATH)lib_rc4.o $(OBJPATH)lib_rc5.o \
			  $(OBJPATH)lib_ripe.o $(OBJPATH)lib_rsa.o $(OBJPATH)lib_sha.o \
			  $(OBJPATH)lib_skip.o

MISCOBJS	= $(OBJPATH)asn1_rw.o $(OBJPATH)asn1s_rw.o $(OBJPATH)key_rw.o \
			  $(OBJPATH)keyex.o $(OBJPATH)keyex_rw.o $(OBJPATH)misc_rw.o \
			  $(OBJPATH)net_cmp.o $(OBJPATH)net_http.o $(OBJPATH)net_tcp.o \
			  $(OBJPATH)rndunix.o $(OBJPATH)sign.o $(OBJPATH)sign_rw.o \
			  $(OBJPATH)str_file.o $(OBJPATH)str_mem.o $(OBJPATH)str_net.o \
			  $(OBJPATH)stream.o

SESSOBJS	= $(OBJPATH)cmp.o $(OBJPATH)cmp_rd.o $(OBJPATH)cmp_wr.o \
			  $(OBJPATH)ocsp.o $(OBJPATH)pnppki.o $(OBJPATH)rtcs.o \
			  $(OBJPATH)scep.o $(OBJPATH)ssh.o $(OBJPATH)ssh1.o \
			  $(OBJPATH)ssh2.o $(OBJPATH)ssh2_cli.o $(OBJPATH)ssh2_svr.o \
			  $(OBJPATH)ssl.o $(OBJPATH)ssl_cli.o $(OBJPATH)ssl_svr.o \
			  $(OBJPATH)tsp.o

ZLIBOBJS	= $(OBJPATH)adler32.o $(OBJPATH)deflate.o $(OBJPATH)infblock.o \
			  $(OBJPATH)infcodes.o $(OBJPATH)inffast.o $(OBJPATH)inflate.o \
			  $(OBJPATH)inftrees.o $(OBJPATH)infutil.o $(OBJPATH)trees.o \
			  $(OBJPATH)zutil.o

OBJS		= $(BNOBJS) $(CERTOBJS) $(CRYPTOBJS) $(DEVOBJS) $(ENVOBJS) \
			  $(HASHOBJS) $(KEYSETOBJS) $(LIBOBJS) $(MISCOBJS) $(SESSOBJS) \
			  $(ZLIBOBJS) $(OSOBJS)

# Object files for the self-test code

TESTOBJS	= certutil.o testcert.o testdev.o testenv.o testhl.o testkeyd.o \
			  testkeyf.o testll.o testscrt.o testsess.o testsreq.o testlib.o

# Various functions all make use of certain headers so we define the
# dependencies once here

ASN1_DEP = misc/asn1_rw.h misc/asn1s_rw.h misc/ber.h misc/stream.h

CRYPT_DEP	= cryptlib.h cryptini.h crypt.h cryptos.h cryptkrn.h

ZLIB_DEP = zlib/zconf.h zlib/zlib.h zlib/zutil.h

#****************************************************************************
#*																			*
#*							Default and High-level Targets					*
#*																			*
#****************************************************************************

# Find the system type and use a conditional make depending on that and the
# endianness, which is piped in from the endianness-detection program (who
# needs autoconf in order to be ugly?).
#
# The unnecessary deletion of the '.' by the tr command is to work around a
# problem in the SunOS uname -r, which returns a number with no OS name so
# that tr can't find any alphabetics to delete.
#
# Slowaris doesn't ship with a compiler by default, so Sun had to provide
# something that pretends to be one for things that look for a cc.  This
# makes it really hard to figure out what's really going on.  The default cc,
# /usr/ucb/cc, is a script that looks for a real compiler elsewhere.  If the
# Sun compiler is installed, this will be via a link /usr/ccs/bin/ucbcc,
# which in turn points to /opt/SUNWspro.  If it's not installed, or installed
# incorrectly, it will bail out with a "package not installed" error.  Since
# many people fix this by just installing gcc, we fall back to explicitly
# invoking that if there's no trace of a Sun compiler, meaning that
# /usr/ucb/cc exists but the link at /usr/ccs/bin/ucbcc doesn't.
#
# Aches has a broken uname, which reports the OS minor version with uname -r
# instead of the major version.  The alternative command oslevel reports the
# full version number, which we can extract in the standard manner.
#
# The MVS USS c89 compiler has a strict ordering of options.  That ordering
# can be relaxed with the _C89_CCMODE environment variable to accept options
# and file names in any order, so we check to make sure that this is set.

default:
	@make directories
	@if [ `uname` = 'OS/390' -a "$(_C89_CCMODE)" != "1" ] ; then \
		echo "The c89 environment variable _C89_CCMODE must be set to 1." >&2 ; \
		exit 1 ; \
		fi
	@if [ ! -f endian ] ; then \
		if [ `uname` = 'SunOS' ] && gcc -v > /dev/null 2>&1 ; then \
			gcc endian.c -o endian > /dev/null ; \
		else \
			$(CC) endian.c -o endian > /dev/null ; \
		fi ; \
	fi
	@case `uname` in \
		'AIX') \
			make CFLAGS="$(CFLAGS) `./endian` \
				-DOSVERSION=`oslevel | cut -d'.' -f1`" `uname` ;; \
		'BeOS') \
			make CFLAGS="$(CFLAGS) `./endian` \
				-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` \
				-D_STATIC_LINKING" `uname` ;; \
		'HP-UX') \
			if gcc -v > /dev/null 2>&1 ; then \
				make CC=gcc CFLAGS="$(CFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			else \
				make CFLAGS="$(CFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			fi ;; \
		'SunOS') \
			if [ `which $(CC) | grep -c ucb` = '1' ] && \
			   [ `which ucbcc | grep -c ucb` = '0' ] ; then \
				make CC=gcc CFLAGS="$(CFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			else \
				make CFLAGS="$(CFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			fi ;; \
		*) \
			make CFLAGS="$(CFLAGS) `./endian` \
				-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
				`uname` ;; \
	esac

shared:
	@make directories
	@if [ `uname` = 'OS/390' -a "$(_C89_CCMODE)" != "1" ] ; then \
		echo "The c89 environment variable _C89_CCMODE must be set to 1." >&2 ; \
		exit 1; \
		fi
	@if [ `uname` = 'SunOS' ] && gcc -v > /dev/null 2>&1 ; then \
		make CC=gcc endian > /dev/null ; \
	else \
		make endian > /dev/null ; \
	fi
	@case `uname` in \
		'AIX') \
			make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
				CFLAGS="$(SCFLAGS) `./endian` \
				-DOSVERSION=`oslevel | cut -d'.' -f1`" `uname` ;; \
		'Darwin') \
			make TARGET=$(DYLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
				CFLAGS="$(SCFLAGS) -fno-common `./endian` \
				-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
				`uname` ;; \
		'SunOS') \
			if [ `which $(CC) | grep -c ucb` = '1' ] && \
			   [ `which ucbcc | grep -c ucb` = '0' ] ; then \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CC=gcc CFLAGS="$(SCFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			else \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CFLAGS="$(SCFLAGS) `./endian` \
					-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
					`uname` ; \
			fi ;; \
		*) \
			make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
				CFLAGS="$(SCFLAGS) `./endian` \
				-DOSVERSION=`uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'`" \
				`uname` ;; \
	esac

directories:
	@if [ ! -d $(STATIC_OBJ_PATH) ] ; then mkdir $(STATIC_OBJ_DIR) ; fi
	@if [ ! -d $(SHARED_OBJ_PATH) ] ; then mkdir $(SHARED_OBJ_DIR) ; fi

# Frohe Ostern.

babies:
	@echo "Good grief, what do you think I am?  Unix is capable, but not that capable."

cookies:
	@echo "Mix 250g flour, 150g sugar, 125g butter, an egg, a few drops of vanilla"
	@echo "essence, and 1 tsp baking powder into a dough, cut cookies from rolls of"
	@echo "dough, bake for about 15 minutes at 180C until they turn very light brown"
	@echo "at the edges."

love:
	@echo "Nicht wahr?"

#****************************************************************************
#*																			*
#*							Rules to build the cryptlib						*
#*																			*
#****************************************************************************

# Main directory

$(OBJPATH)cryptapi.o:	$(CRYPT_DEP) crypt/md2.h crypt/md4.h crypt/md5.h \
						crypt/sha.h cryptapi.c
						$(CC) $(CFLAGS) cryptapi.c -o $(OBJPATH)cryptapi.o

$(OBJPATH)cryptcfg.o:	$(CRYPT_DEP) cryptcfg.c
						$(CC) $(CFLAGS) cryptcfg.c -o $(OBJPATH)cryptcfg.o

$(OBJPATH)cryptcrt.o:	$(CRYPT_DEP) cert/cert.h cryptcrt.c
						$(CC) $(CFLAGS) cryptcrt.c -o $(OBJPATH)cryptcrt.o

$(OBJPATH)cryptctx.o:	$(CRYPT_DEP) misc/context.h cryptctx.c
						$(CC) $(CFLAGS) cryptctx.c -o $(OBJPATH)cryptctx.o

$(OBJPATH)cryptdbx.o:	$(CRYPT_DEP) keyset/keyset.h cryptdbx.c
						$(CC) $(CFLAGS) cryptdbx.c -o $(OBJPATH)cryptdbx.o

$(OBJPATH)cryptdev.o:	$(CRYPT_DEP) device/device.h cryptdev.c
						$(CC) $(CFLAGS) cryptdev.c -o $(OBJPATH)cryptdev.o

$(OBJPATH)cryptenv.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						cryptenv.c
						$(CC) $(CFLAGS) cryptenv.c -o $(OBJPATH)cryptenv.o

$(OBJPATH)cryptkey.o:	$(CRYPT_DEP) misc/context.h cryptkey.c
						$(CC) $(CFLAGS) cryptkey.c -o $(OBJPATH)cryptkey.o

$(OBJPATH)cryptkrn.o:	$(CRYPT_DEP) cryptkrn.c
						$(CC) $(CFLAGS) cryptkrn.c -o $(OBJPATH)cryptkrn.o

$(OBJPATH)cryptlib.o:	$(CRYPT_DEP) cryptlib.c
						$(CC) $(CFLAGS) cryptlib.c -o $(OBJPATH)cryptlib.o

$(OBJPATH)cryptmch.o:	$(CRYPT_DEP) cryptmch.c
						$(CC) $(CFLAGS) cryptmch.c -o $(OBJPATH)cryptmch.o

$(OBJPATH)cryptmis.o:	$(CRYPT_DEP) cryptmis.c
						$(CC) $(CFLAGS) cryptmis.c -o $(OBJPATH)cryptmis.o

$(OBJPATH)cryptses.o:	$(CRYPT_DEP) cryptses.c
						$(CC) $(CFLAGS) cryptses.c -o $(OBJPATH)cryptses.o

$(OBJPATH)cryptusr.o:	$(CRYPT_DEP) cryptusr.c
						$(CC) $(CFLAGS) cryptusr.c -o $(OBJPATH)cryptusr.o

# Additional modules that need to be explicitly enabled by the user

$(OBJPATH)cryptjni.o:	$(CRYPT_DEP) cryptjni.h cryptjni.c
						$(CC) $(CFLAGS) cryptjni.c -o $(OBJPATH)cryptjni.o

# bn subdirectory

$(OBJPATH)bn_add.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_add.c
						$(CC) $(CFLAGS) bn/bn_add.c -o $(OBJPATH)bn_add.o

$(OBJPATH)bn_asm.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_asm.c
						$(CC) $(CFLAGS) bn/bn_asm.c -o $(OBJPATH)bn_asm.o

$(OBJPATH)bn_ctx.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_ctx.c
						$(CC) $(CFLAGS) bn/bn_ctx.c -o $(OBJPATH)bn_ctx.o

$(OBJPATH)bn_div.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_div.c
						$(CC) $(CFLAGS) bn/bn_div.c -o $(OBJPATH)bn_div.o

$(OBJPATH)bn_exp.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_exp.c
						$(CC) $(CFLAGS) bn/bn_exp.c -o $(OBJPATH)bn_exp.o

$(OBJPATH)bn_exp2.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_exp2.c
						$(CC) $(CFLAGS) bn/bn_exp2.c -o $(OBJPATH)bn_exp2.o

$(OBJPATH)bn_gcd.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_gcd.c
						$(CC) $(CFLAGS) bn/bn_gcd.c -o $(OBJPATH)bn_gcd.o

$(OBJPATH)bn_lib.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_lib.c
						$(CC) $(CFLAGS) bn/bn_lib.c -o $(OBJPATH)bn_lib.o

$(OBJPATH)bn_mod.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mod.c
						$(CC) $(CFLAGS) bn/bn_mod.c -o $(OBJPATH)bn_mod.o

$(OBJPATH)bn_mont.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mont.c
						$(CC) $(CFLAGS) bn/bn_mont.c -o $(OBJPATH)bn_mont.o

$(OBJPATH)bn_mul.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mul.c
						$(CC) $(CFLAGS) bn/bn_mul.c -o $(OBJPATH)bn_mul.o

$(OBJPATH)bn_recp.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_recp.c
						$(CC) $(CFLAGS) bn/bn_recp.c -o $(OBJPATH)bn_recp.o

$(OBJPATH)bn_shift.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_shift.c
						$(CC) $(CFLAGS) bn/bn_shift.c -o $(OBJPATH)bn_shift.o

$(OBJPATH)bn_sqr.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_sqr.c
						$(CC) $(CFLAGS) bn/bn_sqr.c -o $(OBJPATH)bn_sqr.o

$(OBJPATH)bn_word.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_word.c
						$(CC) $(CFLAGS) bn/bn_word.c -o $(OBJPATH)bn_word.o

# cert subdirectory

$(OBJPATH)certcget.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certcget.c
						$(CC) $(CFLAGS) cert/certcget.c -o $(OBJPATH)certcget.o

$(OBJPATH)certchk.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certchk.c
						$(CC) $(CFLAGS) cert/certchk.c -o $(OBJPATH)certchk.o

$(OBJPATH)certchn.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certchn.c
						$(CC) $(CFLAGS) cert/certchn.c -o $(OBJPATH)certchn.o

$(OBJPATH)certcset.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certcset.c
						$(CC) $(CFLAGS) cert/certcset.c -o $(OBJPATH)certcset.o

$(OBJPATH)certdn.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certdn.c
						$(CC) $(CFLAGS) cert/certdn.c -o $(OBJPATH)certdn.o

$(OBJPATH)certechk.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certechk.c
						$(CC) $(CFLAGS) cert/certechk.c -o $(OBJPATH)certechk.o

$(OBJPATH)certedef.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certedef.c
						$(CC) $(CFLAGS) cert/certedef.c -o $(OBJPATH)certedef.o

$(OBJPATH)certexrd.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certexrd.c
						$(CC) $(CFLAGS) cert/certexrd.c -o $(OBJPATH)certexrd.o

$(OBJPATH)certext.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certext.c
						$(CC) $(CFLAGS) cert/certext.c -o $(OBJPATH)certext.o

$(OBJPATH)certexwr.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certexwr.c
						$(CC) $(CFLAGS) cert/certexwr.c -o $(OBJPATH)certexwr.o

$(OBJPATH)certio.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certio.c
						$(CC) $(CFLAGS) cert/certio.c -o $(OBJPATH)certio.o

$(OBJPATH)certrd.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certrd.c
						$(CC) $(CFLAGS) cert/certrd.c -o $(OBJPATH)certrd.o

$(OBJPATH)certrev.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certrev.c
						$(CC) $(CFLAGS) cert/certrev.c -o $(OBJPATH)certrev.o

$(OBJPATH)certsig.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certsig.c
						$(CC) $(CFLAGS) cert/certsig.c -o $(OBJPATH)certsig.o

$(OBJPATH)certstr.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/certstr.c
						$(CC) $(CFLAGS) cert/certstr.c -o $(OBJPATH)certstr.o

$(OBJPATH)certrust.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certrust.c
						$(CC) $(CFLAGS) cert/certrust.c -o $(OBJPATH)certrust.o

$(OBJPATH)certval.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certval.c
						$(CC) $(CFLAGS) cert/certval.c -o $(OBJPATH)certval.o

$(OBJPATH)certwr.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certwr.c
						$(CC) $(CFLAGS) cert/certwr.c -o $(OBJPATH)certwr.o

# crypt subdirectory - crypt algos

$(OBJPATH)aescrypt.o:	$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aescrypt.c
						$(CC) $(CFLAGS) crypt/aescrypt.c -o $(OBJPATH)aescrypt.o

$(OBJPATH)aeskey.o:		$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aeskey.c
						$(CC) $(CFLAGS) crypt/aeskey.c -o $(OBJPATH)aeskey.o

$(OBJPATH)aestab.o:		$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aestab.c
						$(CC) $(CFLAGS) crypt/aestab.c -o $(OBJPATH)aestab.o

$(OBJPATH)bfecb.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfecb.c
						$(CC) $(CFLAGS) crypt/bfecb.c -o $(OBJPATH)bfecb.o

$(OBJPATH)bfenc.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfenc.c
						$(CC) $(CFLAGS) crypt/bfenc.c -o $(OBJPATH)bfenc.o

$(OBJPATH)bfskey.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfpi.h \
						crypt/bfskey.c
						$(CC) $(CFLAGS) crypt/bfskey.c -o $(OBJPATH)bfskey.o

$(OBJPATH)castecb.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castecb.c
						$(CC) $(CFLAGS) crypt/castecb.c -o $(OBJPATH)castecb.o

$(OBJPATH)castenc.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castenc.c
						$(CC) $(CFLAGS) crypt/castenc.c -o $(OBJPATH)castenc.o

$(OBJPATH)castskey.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castsbox.h \
						crypt/castskey.c
						$(CC) $(CFLAGS) crypt/castskey.c -o $(OBJPATH)castskey.o

$(OBJPATH)descbc.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/descbc.c
						$(CC) $(CFLAGS) crypt/descbc.c -o $(OBJPATH)descbc.o

$(OBJPATH)desecb.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desecb.c
						$(CC) $(CFLAGS) crypt/desecb.c -o $(OBJPATH)desecb.o

$(OBJPATH)desecb3.o:	crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desecb3.c
						$(CC) $(CFLAGS) crypt/desecb3.c -o $(OBJPATH)desecb3.o

$(OBJPATH)desenc.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desenc.c
						$(CC) $(CFLAGS) crypt/desenc.c -o $(OBJPATH)desenc.o

$(OBJPATH)desskey.o:	crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desskey.c
						$(CC) $(CFLAGS) crypt/desskey.c -o $(OBJPATH)desskey.o

$(OBJPATH)icbc.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/icbc.c
						$(CC) $(CFLAGS) crypt/icbc.c -o $(OBJPATH)icbc.o

$(OBJPATH)iecb.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/iecb.c
						$(CC) $(CFLAGS) crypt/iecb.c -o $(OBJPATH)iecb.o

$(OBJPATH)iskey.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/iskey.c
						$(CC) $(CFLAGS) crypt/iskey.c -o $(OBJPATH)iskey.o

$(OBJPATH)rc2cbc.o:		crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2cbc.c
						$(CC) $(CFLAGS) crypt/rc2cbc.c -o $(OBJPATH)rc2cbc.o

$(OBJPATH)rc2ecb.o:		crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2ecb.c
						$(CC) $(CFLAGS) crypt/rc2ecb.c -o $(OBJPATH)rc2ecb.o

$(OBJPATH)rc2skey.o:	crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2skey.c
						$(CC) $(CFLAGS) crypt/rc2skey.c -o $(OBJPATH)rc2skey.o

$(OBJPATH)rc4enc.o:		crypt/osconfig.h crypt/rc4.h crypt/rc4locl.h crypt/rc4enc.c
						$(CC) $(CFLAGS) crypt/rc4enc.c -o $(OBJPATH)rc4enc.o

$(OBJPATH)rc4skey.o:	crypt/osconfig.h crypt/rc4.h crypt/rc4locl.h crypt/rc4skey.c
						$(CC) $(CFLAGS) crypt/rc4skey.c -o $(OBJPATH)rc4skey.o

$(OBJPATH)rc5ecb.o:		crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5ecb.c
						$(CC) $(CFLAGS) crypt/rc5ecb.c -o $(OBJPATH)rc5ecb.o

$(OBJPATH)rc5enc.o:		crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5enc.c
						$(CC) $(CFLAGS) crypt/rc5enc.c -o $(OBJPATH)rc5enc.o

$(OBJPATH)rc5skey.o:	crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5skey.c
						$(CC) $(CFLAGS) crypt/rc5skey.c -o $(OBJPATH)rc5skey.o

$(OBJPATH)skipjack.o:	crypt/skipjack.c
						$(CC) $(CFLAGS) crypt/skipjack.c -o $(OBJPATH)skipjack.o

# crypt subdirectory - hash algos

$(OBJPATH)md2dgst.o:	crypt/osconfig.h crypt/md2.h crypt/md2dgst.c
						$(CC) $(CFLAGS) crypt/md2dgst.c -o $(OBJPATH)md2dgst.o

$(OBJPATH)md4dgst.o:	crypt/osconfig.h crypt/md4.h crypt/md4locl.h \
						crypt/md4dgst.c
						$(CC) $(CFLAGS) crypt/md4dgst.c -o $(OBJPATH)md4dgst.o

$(OBJPATH)md5dgst.o:	crypt/osconfig.h crypt/md5.h crypt/md5locl.h \
						crypt/md5dgst.c
						$(CC) $(CFLAGS) crypt/md5dgst.c -o $(OBJPATH)md5dgst.o

$(OBJPATH)rmddgst.o:	crypt/osconfig.h crypt/ripemd.h crypt/rmdlocl.h \
						crypt/rmddgst.c
						$(CC) $(CFLAGS) crypt/rmddgst.c -o $(OBJPATH)rmddgst.o

$(OBJPATH)sha1dgst.o:	crypt/osconfig.h crypt/sha.h crypt/sha1locl.h \
						crypt/sha1dgst.c
						$(CC) $(CFLAGS) crypt/sha1dgst.c -o $(OBJPATH)sha1dgst.o

# device subdirectory

$(OBJPATH)dev_fort.o:	$(CRYPT_DEP) device/device.h device/dev_fort.c
						$(CC) $(CFLAGS) device/dev_fort.c -o $(OBJPATH)dev_fort.o

$(OBJPATH)dev_pk11.o:	$(CRYPT_DEP) device/device.h device/dev_pk11.c
						$(CC) $(CFLAGS) device/dev_pk11.c -o $(OBJPATH)dev_pk11.o

$(OBJPATH)dev_sys.o:	$(CRYPT_DEP) device/device.h device/capabil.h libs/libs.h \
						device/dev_sys.c
						$(CC) $(CFLAGS) device/dev_sys.c -o $(OBJPATH)dev_sys.o

# envelope subdirectory

$(OBJPATH)denv_cms.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/denv_cms.c
						$(CC) $(CFLAGS) envelope/denv_cms.c -o $(OBJPATH)denv_cms.o

$(OBJPATH)denv_pgp.o:	$(CRYPT_DEP) envelope/pgp.h envelope/denv_pgp.c
						$(CC) $(CFLAGS) envelope/denv_pgp.c -o $(OBJPATH)denv_pgp.o

$(OBJPATH)env_cms.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/env_cms.c
						$(CC) $(CFLAGS) envelope/env_cms.c -o $(OBJPATH)env_cms.o

$(OBJPATH)env_pgp.o:	$(CRYPT_DEP) envelope/pgp.h envelope/env_pgp.c
						$(CC) $(CFLAGS) envelope/env_pgp.c -o $(OBJPATH)env_pgp.o

$(OBJPATH)env_dec.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/env_dec.c
						$(CC) $(CFLAGS) envelope/env_dec.c -o $(OBJPATH)env_dec.o

$(OBJPATH)env_enc.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/env_enc.c
						$(CC) $(CFLAGS) envelope/env_enc.c -o $(OBJPATH)env_enc.o

$(OBJPATH)pgp_misc.o:	$(CRYPT_DEP) envelope/pgp.h envelope/pgp_misc.c
						$(CC) $(CFLAGS) envelope/pgp_misc.c -o $(OBJPATH)pgp_misc.o

$(OBJPATH)resource.o:	$(CRYPT_DEP) envelope/envelope.h envelope/resource.c
						$(CC) $(CFLAGS) envelope/resource.c -o $(OBJPATH)resource.o

# keyset subdirectory

$(OBJPATH)dbxdbms.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxdbms.c
						$(CC) $(CFLAGS) keyset/dbxdbms.c -o $(OBJPATH)dbxdbms.o

$(OBJPATH)dbxdbx.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbxdbx.c
						$(CC) $(CFLAGS) keyset/dbxdbx.c -o $(OBJPATH)dbxdbx.o

$(OBJPATH)dbxdca.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbxdca.c
						$(CC) $(CFLAGS) keyset/dbxdca.c -o $(OBJPATH)dbxdca.o

$(OBJPATH)dbxhttp.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxhttp.c
						$(CC) $(CFLAGS) keyset/dbxhttp.c -o $(OBJPATH)dbxhttp.o

$(OBJPATH)dbxldap.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxldap.c
						$(CC) $(CFLAGS) keyset/dbxldap.c -o $(OBJPATH)dbxldap.o

$(OBJPATH)dbxmysql.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxmysql.c
						$(CC) $(CFLAGS) keyset/dbxmysql.c -o $(OBJPATH)dbxmysql.o

$(OBJPATH)dbxoracl.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxoracl.c
						$(CC) $(CFLAGS) keyset/dbxoracl.c -o $(OBJPATH)dbxoracl.o

$(OBJPATH)dbxpgp.o:		$(CRYPT_DEP) envelope/pgp.h keyset/dbxpgp.c
						$(CC) $(CFLAGS) keyset/dbxpgp.c -o $(OBJPATH)dbxpgp.o

$(OBJPATH)dbxp12.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbxp12.c
						$(CC) $(CFLAGS) keyset/dbxp12.c -o $(OBJPATH)dbxp12.o

$(OBJPATH)dbxp15.o:		$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/dbxp15.c
						$(CC) $(CFLAGS) keyset/dbxp15.c -o $(OBJPATH)dbxp15.o

$(OBJPATH)dbxp15r.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/dbxp15r.c
						$(CC) $(CFLAGS) keyset/dbxp15r.c -o $(OBJPATH)dbxp15r.o

$(OBJPATH)dbxp15w.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/dbxp15w.c
						$(CC) $(CFLAGS) keyset/dbxp15w.c -o $(OBJPATH)dbxp15w.o

$(OBJPATH)dbxpostg.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbxpostg.c
						$(CC) $(CFLAGS) keyset/dbxpostg.c -o $(OBJPATH)dbxpostg.o

# libs subdirectory

$(OBJPATH)lib_3des.o:	$(CRYPT_DEP) misc/context.h crypt/des.h libs/lib_3des.c
						$(CC) $(CFLAGS) libs/lib_3des.c -o $(OBJPATH)lib_3des.o

$(OBJPATH)lib_aes.o:	$(CRYPT_DEP) misc/context.h crypt/aes.h crypt/aesopt.h \
						libs/lib_aes.c
						$(CC) $(CFLAGS) libs/lib_aes.c -o $(OBJPATH)lib_aes.o

$(OBJPATH)lib_bf.o:		$(CRYPT_DEP) misc/context.h crypt/blowfish.h libs/lib_bf.c
						$(CC) $(CFLAGS) libs/lib_bf.c -o $(OBJPATH)lib_bf.o

$(OBJPATH)lib_cast.o:	$(CRYPT_DEP) misc/context.h crypt/cast.h libs/lib_cast.c
						$(CC) $(CFLAGS) libs/lib_cast.c -o $(OBJPATH)lib_cast.o

$(OBJPATH)lib_des.o:	$(CRYPT_DEP) misc/context.h crypt/testdes.h crypt/des.h \
						libs/lib_des.c
						$(CC) $(CFLAGS) libs/lib_des.c -o $(OBJPATH)lib_des.o

$(OBJPATH)lib_dh.o:		$(CRYPT_DEP) misc/context.h bn/bn.h libs/lib_dh.c
						$(CC) $(CFLAGS) libs/lib_dh.c -o $(OBJPATH)lib_dh.o

$(OBJPATH)lib_dsa.o:	$(CRYPT_DEP) misc/context.h bn/bn.h libs/lib_dsa.c
						$(CC) $(CFLAGS) libs/lib_dsa.c -o $(OBJPATH)lib_dsa.o

$(OBJPATH)lib_elg.o:	$(CRYPT_DEP) misc/context.h bn/bn.h libs/lib_elg.c
						$(CC) $(CFLAGS) libs/lib_elg.c -o $(OBJPATH)lib_elg.o

$(OBJPATH)lib_hmd5.o:	$(CRYPT_DEP) misc/context.h crypt/md5.h libs/lib_hmd5.c
						$(CC) $(CFLAGS) libs/lib_hmd5.c -o $(OBJPATH)lib_hmd5.o

$(OBJPATH)lib_hrmd.o:	$(CRYPT_DEP) misc/context.h crypt/ripemd.h libs/lib_hrmd.c
						$(CC) $(CFLAGS) libs/lib_hrmd.c -o $(OBJPATH)lib_hrmd.o

$(OBJPATH)lib_hsha.o:	$(CRYPT_DEP) misc/context.h crypt/sha.h libs/lib_hsha.c
						$(CC) $(CFLAGS) libs/lib_hsha.c -o $(OBJPATH)lib_hsha.o

$(OBJPATH)lib_idea.o:	$(CRYPT_DEP) misc/context.h crypt/idea.h libs/lib_idea.c
						$(CC) $(CFLAGS) libs/lib_idea.c -o $(OBJPATH)lib_idea.o

$(OBJPATH)lib_kg.o:		$(CRYPT_DEP) misc/context.h bn/bn_prime.h libs/lib_kg.c
						$(CC) $(CFLAGS) libs/lib_kg.c -o $(OBJPATH)lib_kg.o

$(OBJPATH)lib_md2.o:	$(CRYPT_DEP) misc/context.h crypt/md2.h libs/lib_md2.c
						$(CC) $(CFLAGS) libs/lib_md2.c -o $(OBJPATH)lib_md2.o

$(OBJPATH)lib_md4.o:	$(CRYPT_DEP) misc/context.h crypt/md4.h libs/lib_md4.c
						$(CC) $(CFLAGS) libs/lib_md4.c -o $(OBJPATH)lib_md4.o

$(OBJPATH)lib_md5.o:	$(CRYPT_DEP) misc/context.h crypt/md5.h libs/lib_md5.c
						$(CC) $(CFLAGS) libs/lib_md5.c -o $(OBJPATH)lib_md5.o

$(OBJPATH)lib_rc2.o:	$(CRYPT_DEP) misc/context.h crypt/rc2.h libs/lib_rc2.c
						$(CC) $(CFLAGS) libs/lib_rc2.c -o $(OBJPATH)lib_rc2.o

$(OBJPATH)lib_rc4.o:	$(CRYPT_DEP) misc/context.h crypt/rc4.h libs/lib_rc4.c
						$(CC) $(CFLAGS) libs/lib_rc4.c -o $(OBJPATH)lib_rc4.o

$(OBJPATH)lib_rc5.o:	$(CRYPT_DEP) misc/context.h crypt/rc5.h libs/lib_rc5.c
						$(CC) $(CFLAGS) libs/lib_rc5.c -o $(OBJPATH)lib_rc5.o

$(OBJPATH)lib_ripe.o:	$(CRYPT_DEP) misc/context.h crypt/ripemd.h libs/lib_ripe.c
						$(CC) $(CFLAGS) libs/lib_ripe.c -o $(OBJPATH)lib_ripe.o

$(OBJPATH)lib_rsa.o:	$(CRYPT_DEP) misc/context.h bn/bn.h libs/lib_rsa.c
						$(CC) $(CFLAGS) libs/lib_rsa.c -o $(OBJPATH)lib_rsa.o

$(OBJPATH)lib_sha.o:	$(CRYPT_DEP) misc/context.h crypt/sha.h libs/lib_sha.c
						$(CC) $(CFLAGS) libs/lib_sha.c -o $(OBJPATH)lib_sha.o

$(OBJPATH)lib_skip.o:	$(CRYPT_DEP) misc/context.h libs/lib_skip.c
						$(CC) $(CFLAGS) libs/lib_skip.c -o $(OBJPATH)lib_skip.o

# misc subdirectory

$(OBJPATH)asn1_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1_rw.c
						$(CC) $(CFLAGS) misc/asn1_rw.c -o $(OBJPATH)asn1_rw.o

$(OBJPATH)asn1s_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1s_rw.c
						$(CC) $(CFLAGS) misc/asn1s_rw.c -o $(OBJPATH)asn1s_rw.o

$(OBJPATH)key_rw.o:		$(CRYPT_DEP) $(ASN1_DEP) misc/key_rw.c
						$(CC) $(CFLAGS) misc/key_rw.c -o $(OBJPATH)key_rw.o

$(OBJPATH)keyex.o:		$(CRYPT_DEP) $(ASN1_DEP) misc/objinfo.h misc/keyex.c
						$(CC) $(CFLAGS) misc/keyex.c -o $(OBJPATH)keyex.o

$(OBJPATH)keyex_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/objinfo.h misc/keyex_rw.c
						$(CC) $(CFLAGS) misc/keyex_rw.c -o $(OBJPATH)/keyex_rw.o

$(OBJPATH)misc_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/objinfo.h misc/misc_rw.c
						$(CC) $(CFLAGS) misc/misc_rw.c -o $(OBJPATH)/misc_rw.o

$(OBJPATH)net_cmp.o:	$(CRYPT_DEP) misc/net_cmp.c
						$(CC) $(CFLAGS) misc/net_cmp.c -o $(OBJPATH)net_cmp.o

$(OBJPATH)net_http.o:	$(CRYPT_DEP) misc/net_http.c
						$(CC) $(CFLAGS) misc/net_http.c -o $(OBJPATH)net_http.o

$(OBJPATH)net_tcp.o:	$(CRYPT_DEP) misc/net_tcp.c
						$(CC) $(CFLAGS) misc/net_tcp.c -o $(OBJPATH)net_tcp.o

$(OBJPATH)rndunix.o:	$(CRYPT_DEP) misc/rndunix.c
						$(CC) $(CFLAGS) misc/rndunix.c -o $(OBJPATH)rndunix.o

$(OBJPATH)sign.o:		$(CRYPT_DEP) $(ASN1_DEP) misc/objinfo.h misc/sign.c
						$(CC) $(CFLAGS) misc/sign.c -o $(OBJPATH)sign.o

$(OBJPATH)sign_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/objinfo.h misc/sign_rw.c
						$(CC) $(CFLAGS) misc/sign_rw.c -o $(OBJPATH)sign_rw.o

$(OBJPATH)str_file.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/str_file.c
						$(CC) $(CFLAGS) misc/str_file.c -o $(OBJPATH)str_file.o

$(OBJPATH)str_mem.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/str_mem.c
						$(CC) $(CFLAGS) misc/str_mem.c -o $(OBJPATH)str_mem.o

$(OBJPATH)str_net.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/str_net.c
						$(CC) $(CFLAGS) misc/str_net.c -o $(OBJPATH)str_net.o

$(OBJPATH)stream.o:		$(CRYPT_DEP) $(ASN1_DEP) misc/stream.c
						$(CC) $(CFLAGS) misc/stream.c -o $(OBJPATH)stream.o

# session subdirectory

$(OBJPATH)cmp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp.c
						$(CC) $(CFLAGS) session/cmp.c -o $(OBJPATH)cmp.o

$(OBJPATH)cmp_rd.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp_rd.c
						$(CC) $(CFLAGS) session/cmp_rd.c -o $(OBJPATH)cmp_rd.o

$(OBJPATH)cmp_wr.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp_wr.c
						$(CC) $(CFLAGS) session/cmp_wr.c -o $(OBJPATH)cmp_wr.o

$(OBJPATH)ocsp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/ocsp.c
						$(CC) $(CFLAGS) session/ocsp.c -o $(OBJPATH)ocsp.o

$(OBJPATH)pnppki.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/pnppki.c
						$(CC) $(CFLAGS) session/pnppki.c -o $(OBJPATH)pnppki.o

$(OBJPATH)rtcs.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/rtcs.c
						$(CC) $(CFLAGS) session/rtcs.c -o $(OBJPATH)rtcs.o

$(OBJPATH)scep.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/scep.c
						$(CC) $(CFLAGS) session/scep.c -o $(OBJPATH)scep.o

$(OBJPATH)ssh.o:		$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssh.h session/ssh.c
						$(CC) $(CFLAGS) session/ssh.c -o $(OBJPATH)ssh.o

$(OBJPATH)ssh1.o:		$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssh.h session/ssh1.c
						$(CC) $(CFLAGS) session/ssh1.c -o $(OBJPATH)ssh1.o

$(OBJPATH)ssh2.o:		$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssh.h session/ssh2.c
						$(CC) $(CFLAGS) session/ssh2.c -o $(OBJPATH)ssh2.o

$(OBJPATH)ssh2_cli.o:	$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssh.h session/ssh2_cli.c
						$(CC) $(CFLAGS) session/ssh2_cli.c -o $(OBJPATH)ssh2_cli.o

$(OBJPATH)ssh2_svr.o:	$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssh.h session/ssh2_svr.c
						$(CC) $(CFLAGS) session/ssh2_svr.c -o $(OBJPATH)ssh2_svr.o

$(OBJPATH)ssl.o:		$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssl.h session/ssl.c
						$(CC) $(CFLAGS) session/ssl.c -o $(OBJPATH)ssl.o

$(OBJPATH)ssl_cli.o:	$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssl.h session/ssl_cli.c
						$(CC) $(CFLAGS) session/ssl_cli.c -o $(OBJPATH)ssl_cli.o

$(OBJPATH)ssl_svr.o:	$(CRYPT_DEP) misc/stream.h session/session.h \
						session/ssl.h session/ssl_svr.c
						$(CC) $(CFLAGS) session/ssl_svr.c -o $(OBJPATH)ssl_svr.o

$(OBJPATH)tsp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/tsp.c
						$(CC) $(CFLAGS) session/tsp.c -o $(OBJPATH)tsp.o

# zlib subdirectory

$(OBJPATH)adler32.o:	$(ZLIB_DEP) zlib/adler32.c
						$(CC) $(CFLAGS) zlib/adler32.c -o $(OBJPATH)adler32.o

$(OBJPATH)deflate.o:	$(ZLIB_DEP) zlib/deflate.c
						$(CC) $(CFLAGS) zlib/deflate.c -o $(OBJPATH)deflate.o

$(OBJPATH)infblock.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inftrees.h \
						zlib/infcodes.h zlib/infutil.h zlib/infblock.c
						$(CC) $(CFLAGS) zlib/infblock.c -o $(OBJPATH)infblock.o

$(OBJPATH)infcodes.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.h \
						zlib/infcodes.c
						$(CC) $(CFLAGS) zlib/infcodes.c -o $(OBJPATH)infcodes.o

$(OBJPATH)inffast.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.h \
						zlib/inffast.c
						$(CC) $(CFLAGS) zlib/inffast.c -o $(OBJPATH)inffast.o

$(OBJPATH)inflate.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inflate.c
						$(CC) $(CFLAGS) zlib/inflate.c -o $(OBJPATH)inflate.o

$(OBJPATH)inftrees.o:	$(ZLIB_DEP) zlib/inftrees.h zlib/inftrees.c
						$(CC) $(CFLAGS) zlib/inftrees.c -o $(OBJPATH)inftrees.o

$(OBJPATH)infutil.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.c
						$(CC) $(CFLAGS) zlib/infutil.c -o $(OBJPATH)infutil.o

$(OBJPATH)trees.o:		$(ZLIB_DEP) zlib/trees.c
						$(CC) $(CFLAGS) zlib/trees.c -o $(OBJPATH)trees.o

$(OBJPATH)zutil.o:		$(ZLIB_DEP) zlib/zutil.c
						$(CC) $(CFLAGS) zlib/zutil.c -o $(OBJPATH)zutil.o

# Build the asm equivalents of various C modules.  These are built before any
# other files and override the .o's that are produced by compiling the C
# equivalents of the asm files, so that (provided the build succeeds) the .o
# files that would be created from the C code will never be created because
# the asm-derived .o's already exist.
#
# Since these targets aren't files, we can't use make to build them as
# required (actually some makes will allow two sets of dependencies for a
# target, but this doesn't give us any control over whether we want the .o
# built from the .s or the .c).  A workaround for this is to use a quick
# shell hack to only build the files if they don't already exist - this is
# OK since they'll only be built once.
#
# The exception to this is the hash asm files, which use an incredible amount
# of preprocessor kludging that requires that both the .c and .s files are
# built.  To handle this we use EXTRAOBJS to include the extra asm-derived
# objs into the build.

asm_bn:					bn/bn-$(INFILE).s
						@if [ ! -f $(OBJPATH)bn_asm.o ] ; then \
							$(AS) bn/bn-$(INFILE).s -o $(OBJPATH)bn_asm.o; \
						fi

asm_bf:					crypt/b-$(INFILE).s
						@if [ ! -f $(OBJPATH)bfenc.o ] ; then \
							$(AS) crypt/b-$(INFILE).s -o $(OBJPATH)bfenc.o; \
						fi

asm_cast:				crypt/c-$(INFILE).s
						@if [ ! -f $(OBJPATH)castenc.o ] ; then \
							$(AS) crypt/c-$(INFILE).s -o $(OBJPATH)castenc.o; \
						fi

asm_des:				crypt/d-$(INFILE).s
						@if [ ! -f $(OBJPATH)desenc.o ] ; then \
							$(AS) crypt/d-$(INFILE).s -o $(OBJPATH)desenc.o; \
						fi

asm_rc4:				crypt/r4-$(INFILE).s
						@if [ ! -f $(OBJPATH)rc4enc.o ] ; then \
							$(AS) crypt/r4-$(INFILE).s -o $(OBJPATH)rc4enc.o;\
						fi

asm_rc5:				crypt/r5-$(INFILE).s
						@if [ ! -f $(OBJPATH)rc5enc.o ] ; then \
							$(AS) crypt/r5-$(INFILE).s -o $(OBJPATH)rc5enc.o; \
						fi

asm_md5:				crypt/m5-$(INFILE).s
						@if [ ! -f $(OBJPATH)md5asm.o ] ; then \
							$(AS) crypt/m5-$(INFILE).s -o $(OBJPATH)md5asm.o; \
						fi

asm_ripemd:				crypt/rm-$(INFILE).s
						@if [ ! -f $(OBJPATH)rmdasm.o ] ; then \
							$(AS) crypt/rm-$(INFILE).s -o $(OBJPATH)rmdasm.o; \
						fi

asm_sha1:				crypt/s1-$(INFILE).s
						@if [ ! -f $(OBJPATH)sha1asm.o ] ; then \
							$(AS) crypt/s1-$(INFILE).s -o $(OBJPATH)sha1asm.o; \
						fi

asm_targets:
		@make asm_bn INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_bf INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_cast INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_des INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_rc4 INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_rc5 INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_md5 INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_ripemd INFILE=$(INFILE) OBJPATH=$(OBJPATH)
		@make asm_sha1 INFILE=$(INFILE) OBJPATH=$(OBJPATH)

asm_elf:
		@make asm_targets INFILE=elf OBJPATH=$(OBJPATH)

asm_out:
		@make asm_targets INFILE=out OBJPATH=$(OBJPATH)

asm_sol:
		@make asm_targets INFILE=sol OBJPATH=$(OBJPATH)

# The pseudo-dependencies to build the asm modules for other processors.
# Only the bignum code is done in asm for these.  See the SunOS dependency
# for the explanation of the leading '-' in the asm_sparc rule.  For gas on
# OSF/1, it may be necessary to use -m<cpu_type> (where <cpu_type> is
# anything, e.g.21064, 21164, etc) if gas dies with an illegal operand error
# (this is a bug in some versions of gas).  For Sparc there are two lots of
# asm code, sparcv8 for SuperSparc (Sparc v8) and sparcv8plus for UltraSparc
# (Sparc v9 with hacks for when the kernel doesn't preserve the upper 32
# bits of some 64-bit registers).

asm_alpha:				bn/alpha.s
						$(AS) bn/alpha.s -o $(OBJPATH)bn_asm.o

asm_mips:				bn/mips3.s
						$(AS) bn/mips3.s -o $(OBJPATH)bn_asm.o

asm_mvs:				misc/mvsent.s
						$(CC) -c misc/mvsent.s -o $(OBJPATH)mvsent.o

asm_phux:				bn/pa-risc2.s
						$(AS) bn/pa-risc2.s -o $(OBJPATH)bn_asm.o

asm_sparc:				bn/sparcv8plus.S
						- if [ `which $(CC) | grep -c "no gcc"` = '1' ] ; then \
							$(AS) -V -Qy -s -xarch=v8plusa bn/sparcv8plus.S -o $(OBJPATH)bn_asm.o ; \
						else \
							if [ `uname -a | grep -c sun4m` = '1' ] ; then \
								gcc -mcpu=supersparc -c bn/sparcv8.S -o $(OBJPATH)bn_asm.o ; \
							else
								gcc -mcpu=ultrasparc -c bn/sparcv8plus.S -o $(OBJPATH)bn_asm.o ; \
							fi ; \
						fi

# The test code

certinst.o:				cryptlib.h crypt.h test/test.h test/certinst.c
						$(CC) $(CFLAGS) test/certinst.c

certutil.o:				cryptlib.h crypt.h test/test.h test/certutil.c
						$(CC) $(CFLAGS) test/certutil.c

testcert.o:				cryptlib.h crypt.h test/test.h test/testcert.c
						$(CC) $(CFLAGS) test/testcert.c

testdev.o:				cryptlib.h crypt.h test/test.h test/testdev.c
						$(CC) $(CFLAGS) test/testdev.c

testenv.o:				cryptlib.h crypt.h test/test.h test/testenv.c
						$(CC) $(CFLAGS) test/testenv.c

testhl.o:				cryptlib.h crypt.h test/test.h test/testhl.c
						$(CC) $(CFLAGS) test/testhl.c

testkeyd.o:				cryptlib.h crypt.h test/test.h test/testkeyd.c
						$(CC) $(CFLAGS) test/testkeyd.c

testkeyf.o:				cryptlib.h crypt.h test/test.h test/testkeyf.c
						$(CC) $(CFLAGS) test/testkeyf.c

testll.o:				cryptlib.h crypt.h test/test.h test/testll.c
						$(CC) $(CFLAGS) test/testll.c

testscrt.o:				cryptlib.h crypt.h test/test.h test/testscrt.c
						$(CC) $(CFLAGS) test/testscrt.c

testsess.o:				cryptlib.h crypt.h test/test.h test/testsess.c
						$(CC) $(CFLAGS) test/testsess.c

testsreq.o:				cryptlib.h crypt.h test/test.h test/testsreq.c
						$(CC) $(CFLAGS) test/testsreq.c

testlib.o:				cryptlib.h crypt.h test/test.h test/testlib.c
						$(CC) $(CFLAGS) test/testlib.c

# Create the library, either as a static or shared library.  The main test
# program is also listed as a dependency since we need to use OS-specific
# compiler options for it that a simple 'make testlib' won't give us (the
# test program checks whether the compiler options were set correctly when
# building the library, so it needs to include a few library-specific files
# that wouldn't be used in an normal program).
#
# The use of ar and ranlib is rather system-dependant.  Some ar's (e.g.OSF1)
# create the .SYMDEF file by default, some require the 's' option, and some
# require the use of ranlib altogether because ar doesn't recognise the 's'
# option.  If we know what's required we use the appropriate form, otherwise
# we first try 'ar rcs' (which works on most systems) and if that fails fall
# back to 'ar rc' followed by ranlib.
#
# Because the macros expand to rather large lists of files, we use an extra
# level of indirection for the ar commands (at least one system, MP-RAS, will
# dump core trying to process the command if it's expanded inline).
#
# Building the shared library is even more system-dependant, we check for
# various OS's that we know about and adjust the link as appropriate.

ar_rcs:
						@ar rcs $(LIBNAME) $(OBJS) $(EXTRAOBJS)

ranlib:
						@ar rc $(LIBNAME) $(OBJS) $(EXTRAOBJS)
						@ranlib $(LIBNAME) ; \

ar_guess:
						@ar rcs $(LIBNAME) $(OBJS) $(EXTRAOBJS) || \
						( ar rc $(LIBNAME) $(OBJS) $(EXTRAOBJS) && \
						  ranlib $(LIBNAME) )

$(LIBNAME):				$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
						@case $(OSNAME) in \
							'AIX'|'HP-UX'|'Linux'|'OSF1'|'SunOS'|'UNIX_SV') \
								make ar_rcs ;; \
							'Atmel') \
								echo "Need to set up Atmel link command" ;; \
							'BSD/OS'|'FreeBSD'|'iBSD'|'OpenBSD') \
								make ranlib ;; \
							*) \
								make ar_guess ;; \
						esac

$(SLIBNAME):			$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
						@case $(OSNAME) in \
							'AIX') \
								cc -o shrlibcl.o -bE:cryptlib.exp \
									-bM:SRE -bnoentry -lpthread $(OBJS) ; \
								ar -q $(SLIBNAME).a shrlibcl.o; \
								rm -f shrlibcl.o; \
								chmod 750 $(SLIBNAME).a ;; \
							'BeOS' ) \
								$(LD) -nostart -o $(SLIBNAME) $(OBJS) $(EXTRAOBJS) ; \
								strip $(SLIBNAME) ;; \
							'HP-UX') \
								ld -b -o lib$(PROJ).sl $(OBJS) $(EXTRAOBJS) ; \
								strip lib$(PROJ).sl ;; \
							*) \
								$(SLD) -o $(SLIBNAME) $(OBJS) $(EXTRAOBJS) ; \
								strip $(SLIBNAME) ;; \
						esac

$(DYLIBNAME):			$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
						@$(LD) -dynamiclib -compatibility_version $(MAJ).$(MIN) \
							-current_version $(MAJ).$(MIN).$(PLV) \
							-o $(DYLIBNAME) $(OBJS) $(EXTRAOBJS)

# Link everything into the test programs.  Some OS's require the linking of
# various special libraries, unfortunately we can't do this via the OS-
# specific makefile rules since they're not invoked to build the test
# programs so we have to specify everything explicitly here.  Note that we
# don't include $(LIBNAME) as a dependency because building it this way
# bypasses the use of system-specific options.  The user has to explicitly
# build this separately.
#
# The OS's and the required libraries are:
#
#	AIX:						-lc_r -lpthreads
#	BeOS:						None
#	BSDI:						-lgcc
#	Cygwin:						None
#	FreeBSD:					-lc_r
#	Irix:						-lw
#	Linux/OSF1/DEC Unix:		-lpthread -lresolv
#	NCR MP-RAS (threads):		-Xdce -lnsl -lsocket -lc89 -lpthread -lresolv
#	NCR MP-RAS (no.threads):	-lnsl -lsocket -lc89
#	PHUX 11.x:					-lpthread
#	PHUX 10.x, 9.x:				None
#	Solaris 7+ (SunOS 5.7+):	-lw -lkstat -lthread -ldl -lnsl -lrt
#	SunOS 5.5 and 5.6:			-lw -lkstat -lthread -ldl -lnsl -lposix4
#	SunOS 4.x:					-ldl -lnsl -lposix4
#	UnixWare (SCO):				-lsocket -Kthread
#
# Comments:
#
#	-lc_r = libc extended with re-entrant functions needed for threading.
#			This is required by FreeBSD 5.1-RELEASE but not FreeBSD 5.1-
#			CURRENT, which has the standard libc re-entrant.  Because there's
#			no easy way to tell what we're running under (they both have the
#			same version numbers) we use it for both.
#	-ldl = dload support for dynamically loaded PKCS #11 drivers.
#	-lgcc = Extra gcc support lib needed for BSDI, which ships with gcc but
#			not the proper libs for it.
#	-lkstat = kstat functions for Solaris randomness gathering.
#	-lsocket = Resolver functions.
#	-lnsl = Socket support for Slowaris, which doesn't have it in libc.
#   -lposix4 = Solaris 2.5 and 2.6 library for sched_yield.
#	-lresolv = Resolver functions.
# 	-lrt = Solaris 2.7 and above realtime library for sched_yield().
#	-lthread = pthreads support.  Note that this generally has to be linked
#			as late as possible (and in particular after the implied -lc)
#			because libpthread overrides non-thread-safe and stub functions
#			in libraries linked earlier on with thread-safe alternatives.
#	-lw = Widechar support.
#
# The OS-specific linking is handled through multiple levels of indirection.
# At the top level we specify the target and library to link with (static or
# shared).  We pass this down to test_link, which sorts out the OS-specific
# linker options, and then finally passes the whole lot down to link, which
# performs the actual link.
#
# After the shared stuff is built, you can test it with:
#
#	/sbin/ldconfig . >& /dev/null
#	LD_LIBRARY_PATH=.
#	ldd ./testlib
#
# BeOS uses LIBRARY_PATH instead, and needs to have it pointed to . to find
# the shared lib, otherwise it fails with a "Missing library" error without
# indicating which library is missing.

LDFLAGS_AIX		= -lc_r -lpthreads
LDFLAGS_BEOS	=
LDFLAGS_BEOS_BONE = -lbind -lsocket
LDFLAGS_BSDI	= -lgcc
LDFLAGS_CYGWIN	=
LDFLAGS_FREEBSD	= -lc_r
LDFLAGS_HPUX10	=
LDFLAGS_HPUX11	= -lpthread
LDFLAGS_IRIX	= -lw
LDFLAGS_LINUX	= -lpthread -lresolv
LDFLAGS_MPRAS	= -K xpg42 -lnsl -lsocket -lc89
LDFLAGS_SCO		= -lsocket -Kthread
LDFLAGS_SUNOS	= -ldl -lnsl -lposix4
LDFLAGS_SOLARIS5 = -lw -lsocket -lkstat -lthread -lnsl -lposix4
LDFLAGS_SOLARIS7 = -lw -lsocket -lkstat -lthread -lrt -lnsl

link:		$(TESTOBJS)
			@$(LD) -o $(OUT) $(LDFLAGS) $(TESTOBJS) -L. $(LIB) $(OS_LDFLAGS) $(TESTLIBS)

test_link:	$(TESTOBJS)
			@case $(OSNAME) in \
				'AIX') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_AIX)" ;; \
				'BeOS') \
					if [ -f /system/lib/libbind.so ] ; then \
						make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_BEOS_BONE)" ; \
					else \
						make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_BEOS)" ; \
					fi ;; \
				'BSD/OS') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_BSDI)" ;; \
				'CYGWIN_NT-5.0') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_CYGWIN)" ;; \
				'FreeBSD') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_FREEBSD)" ;; \
				'HP-UX') \
					case `uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` in \
						10) \
							if gcc -v > /dev/null 2>&1; then \
								make link LD=gcc LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_HPUX10)" ; \
							else \
								make link LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_HPUX10)" ; \
							fi ;; \
						11) \
							if gcc -v > /dev/null 2>&1; then \
								make link LD=gcc LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_HPUX11)" ; \
							else \
								make link LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_HPUX11)" ; \
							fi ;; \
					esac ;; \
				'IRIX'|'IRIX64') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_IRIX)" ;; \
				'Linux'|'OSF1') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_LINUX)" ;; \
				'SunOS') \
					case `uname -r | cut -f 1 -d '.'` in \
						4) \
							make link LIB=$(LIB) OUT=$(OUT) \
								OS_LDFLAGS="$(LDFLAGS_SUNOS)" ;; \
						5) \
							if [ `which $(LD) | grep -c ucb/cc` = '1' ] && \
							   [ `which ucbcc | grep -c ucbcc` = '0' ] ; then \
								make link LD=gcc LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_SOLARIS5)" ; \
							else \
								make link LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_SOLARIS5)" ; \
							fi ;; \
						6|7|8|9) \
							if [ `which $(LD) | grep -c ucb/cc` = '1' ] && \
							   [ `which ucbcc | grep -c ucbcc` = '0' ] ; then \
								make link LD=gcc LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_SOLARIS7)" ; \
							else \
								make link LIB=$(LIB) OUT=$(OUT) \
									OS_LDFLAGS="$(LDFLAGS_SOLARIS7)" ; \
							fi ;; \
					esac ;; \
				'UNIX_SV') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_MPRAS)" ;; \
				'UnixWare') \
					make link LIB=$(LIB) OUT=$(OUT) OS_LDFLAGS="$(LDFLAGS_SCO)" ;; \
				*) \
					make link LIB=$(LIB) OUT=$(OUT) ;; \
			esac

testlib:	$(TESTOBJS)
			@make test_link OUT=testlib LIB=-l$(PROJ)

stestlib:	$(TESTOBJS)
			@make test_link OUT=stestlib LIB=$(SLIBNAME)

certinst:	$(LIBNAME) certinst.o
			@make test_link OUT=certinst LIB=-l$(PROJ)

#****************************************************************************
#*																			*
#*						Defines for each variation of Unix					*
#*																			*
#****************************************************************************

# Aches: A vaguely Unix-compatible OS designed by IBM.  The maxmem option
#		 is to give the optimizer more headroom, it's not really needed
#		 but avoids millions of informational messages telling you to
#		 increase it from the default 2048.  The roconst puts const data
#		 into read-only memory (this may happen anyway on some versions of
#		 the compiler).

AIX:
	@if [ -f /usr/include/stdint.h ] ; then \
		make $(DEFINES) CFLAGS="$(CFLAGS) -O2 -qmaxmem=-1 -qroconst -DHAS_STDINT_H -D_REENTRANT" ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -O2 -qmaxmem=-1 -qroconst -D_REENTRANT" ; \
	fi

# Apollo: Yeah, this makefile has been around for awhile.  Why do you ask?

Apollo:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# AUX: su root; rm -rf /; echo "Now install MkLinux"

A/UX:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# Millions of Intel BSD's (many are really BSE's, with incredibly archaic
#			development tools and libs, although it's slowly getting better):
#			cc is gcc except when it isn't.  Most are still using a.out,
#			although some are slowly going to ELF, which we can autodetect by
#			checking whether the compiler defines __ELF__.  If the compiler
#			check doesn't work then [ `uname -r | cut -f 1` -ge 4 ] (for
#			FreeBSD) and -ge 2 (for OpenBSD) should usually work.
#
#			NetBSD for many years (up until around 1999-2000) used an
#			incredibly old version of as that didn't handle 486 opcodes (!!),
#			so the asm code was disabled by default.  In addition it used an
#			equally archaic version of gcc, requiring manual fiddling with
#			the compiler type and options.

BSD386:
	@make asm_out OBJPATH=$(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -mcpu=pentium"
iBSD:
	@make asm_out OBJPATH=$(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -mcpu=pentium"
BSD/OS:
	@if test "`echo __ELF__ | $(CC) -E - | grep __ELF__`" = "" ; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
	else \
		make asm_out OBJPATH=$(OBJPATH) ; \
	fi
	@make $(DEFINES) CC=gcc EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -mcpu=pentium"
FreeBSD:
	@if test "`echo __ELF__ | $(CC) -E - | grep __ELF__`" = "" ; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
	else \
		make asm_out OBJPATH=$(OBJPATH) ; \
	fi
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -mcpu=pentium"
OpenBSD:
	@if test "`echo __ELF__ | $(CC) -E - | grep __ELF__`" = "" ; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
	else \
		make asm_out OBJPATH=$(OBJPATH) ; \
	fi
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -mcpu=pentium"

# Convex:

Convex:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# Cygwin32: cc is gcc

CYGWIN_NT-5.0:
	@make CC=gcc $(DEFINES) CFLAGS="$(CFLAGS) -O3 -mcpu=pentium -D__CYGWIN__ -I/usr/local/include"

# DGUX: cc is a modified gcc.

dgux:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -ansi -fomit-frame-pointer -O3"

# PHUX: A SYSVR2 layer with a SYSVR3 glaze on top of an adapted BSD 4.2
#		kernel.  Use cc, the exact incantation varies somewhat depending on
#		which version of PHUX you're running.  For 9.x you need to use
#		'-Aa -D_HPUX_SOURCE' to get the compiler into ANSI mode, in 10.x this
#		changed to just '-Ae', and after 10.30 -Ae was the default mode.
#		With PA-RISC 2 you should probably also define +DD64 to compile in
#		64-bit mode under PHUX 11.x, under even newer versions this becomes
#		+DA2.0w (note that building 64-bit versions of anything will probably
#		cause various build problems arising from the compiler and linker
#		because although the CPU may be 64 bit the software development tools
#		really, really want to give you 32-bit versions of everything and it
#		takes quite some cajoling to actually get them to spit out a 64-bit
#		result).  In addition the PHUX compilers don't recognise -On like the
#		rest of the universe but use +On instead so if you're using gcc
#		instead of cc/c89 you'll need to change things to use the standard gcc
#	    options.  Finally, we only build the asm code under 11 since it
#		doesn't like 10.x and earlier systems.
#
#		Newer compilers can use +Oall to apply all optimisations (even the
#		dodgy ones).  Typically going from +O2 -> +O3 -> +O4 gives a ~10-15%
#		improvement at each step.  Finally, when making the shared lib you
#		can only use +O2, not +O3, because it gives the compiler the speed
#		wobbles.  In theory we could also use +ESlit to force const data
#		into a read-only segment, but this is defeated by a compiler bug
#		that doesn't initialise non-explicitly-initialised struct elements
#		to zero any more when this option is enabled (this is a double-bug
#		that violates two C rules because if there are insufficient
#		initialisers the remaining elements should be set to zero, and for
#		static objects they should be set to zero even if there are no
#		initialisers).
#
#		Note that the PHUX compilers (especially the earlier ones) are
#		horribly broken and will produce all sorts of of bogus warnings of
#		non-problems, eg:
#
#			/usr/ccs/bin/ld: (Warning) Quadrant change in relocatable
#							 expression in subspace $CODE$
#
#		(translation: Klingons off the starboard bow!).  The code contains
#		workarounds for non-errors (for example applying a cast to anything
#		magically turns it into an rvalue), but it's not worth fixing the
#		warnings for an OS as broken as this.
#
#		This PHUX compiler bugs comment is really starting to give the SCO
#		one a run for its money.

HP-UX:
	@if [ `uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` -eq 11 ] ; then \
		make asm_phux OBJPATH=$(OBJPATH) || exit 1 ; \
		make $(DEFINES) CFLAGS="$(CFLAGS) +O3 -D_REENTRANT" ; \
	elif [ `uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` -eq 10 ] ; then \
		if [ $(CC) = "gcc" ] ; then \
			make $(DEFINES) CFLAGS="$(CFLAGS) -O3" ; \
		else \
			make $(DEFINES) CFLAGS="$(CFLAGS) -Ae +O3" ; \
		fi ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -Aa -D_HPUX_SOURCE +O3" ; \
	fi

# Irix: Use cc

IRIX:
	@make asm_mips OBJPATH=$(OBJPATH)
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"
IRIX64:
	@make asm_mips OBJPATH=$(OBJPATH)
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"

# ISC Unix: Use gcc

ISC:
	@make asm_out OBJPATH=$(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -mcpu=pentium"

# Linux: cc is gcc.  The 1e-5 users with rather old versions of x86 Linux
#		 will need to make the asm targets with ASMFLAGS=OUT to build the
#		 a.out version of the asm core routines.

Linux:
	@if uname -m | grep "i[3,4,5,6]86" > /dev/null; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
			-fomit-frame-pointer -O3 -mcpu=pentium -D_REENTRANT"; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -D_REENTRANT"; \
	fi

# Mac OS X: BSD variant.

Darwin:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3" \
		LDFLAGS="-object -s"

# NCR MP-RAS 3.02: Using the NCR High Performance C Compiler R3.0c
#				   The options below don't use threads.  To use threads,
#				   remove the cryptlib define -DNO_THREADS and add the MP-RAS
#				   define "-DNCR_UST to enable User Space Threads."

UNIX_SV:
	@make $(DEFINES) ARMETHOD=rcs CFLAGS="$(CFLAGS) -D_MPRAS -DNO_THREADS \
		-O2 -Xa -Hnocopyr -K xpg42 -K catchnull '-Hpragma=Offwarn(39)' \
		'-Hpragma=Offwarn(73)'"

# NeXT 3.0:

NeXT:
	@make $(DEFINES) LDFLAGS="-object -s"

# OSF 1: Use gcc and the asm version of the bn routines.  If you're using
#		 the OSF1 cc you need to use "-std1" to force ANSI compliance and
#		 change the optimization CFLAGS.

OSF1:
	@make asm_alpha OBJPATH=$(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -D_REENTRANT"

# QNX 4.x:

QNX:
	@make asm_elf OBJPATH=$(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM -O4"

# SCO: Unlike the entire rest of the world, SCO doesn't use -On, although it
#	   does recognise -O3 to mean "turn off pass 3 optimization".  The SCO cc
#	   is in fact a mutant version of Microsoft C 6.0, so we use the usual
#	   MSC optimization options except for the unsafe ones.  -Olx is
#	   equivalent to -Oegilt.  Unless SCO rewrote half the compiler when
#	   no-one was looking, you won't be getting much optimization for your
#	   -O.
#
#	   Actually it turns out that the only thing you get with -Olx is
#	   compiler bugs, so we only use -O, and even with that you get internal
#	   compiler faults that it traps and forces a compiler restart on,
#	   presumably with optimisations disabled.
#
#	   SCO is basically too braindamaged to support any of the asm builds.
#	   as won't take input from stdin and dumps core on the crypto .S files,
#	   and cc/as barf on bni80386.s.  Even compiling the straight C code
#	   gives a whole slew of internal compiler errors/failed assertions.  If
#	   you have a setup that works (i.e.with GNU tools installed) then you
#	   can add the following to build the library.
#
#		@make asm_elf
#
#	   For another taste of the wonderful SCO compiler, take the trivial lex
#	   example from the dragon book, lex it, and compile it.  Either the
#	   compiler will core dump from a SIGSEGV or the resulting program will
#	   from a SIGILL, depending on what level of optimization you use (a
#	   compiler that'll produce illegal code as output is pretty impressive).
#
#	   In addition the SCO cc ignores the path for output files and dumps the
#	   whole mess in the same directory as the source files.  This means you
#	   need to set STATIC_OBJ_PATH = . in order for the library to be built,
#	   however the following rule does this for you by forwarding down the
#	   $(TARGET) define rather than $(DEFINES) that also includes the output
#	   path.
#
#	   If you're building the shared version after building the static one
#	   you need to manually remove all the object files before trying to
#	   build it, although it's extremely unlikely that SCO can handle this
#	   anyway so it's probably not worth bothering with.
#
#	   The SCO/UnixWare sockets libraries are extraordinarily buggy, make
#	   sure that you've got the latest patches installed if you plan to use
#	   cryptlib's secure session interface.  Note that some bugs reappear in
#	   later patches, so you should make sure that you really do have the
#	   very latest patch installed ("SCO - Where Quality is Job #9" -
#	   unofficial company motto following a SCO employee survey).
#
#	   In terms of straight compiling of code, UnixWare (SCO 7.x) is only
#	   marginally better.  as now finally accepts input from stdin if '-' is
#	   specified as a command-line arg, but it doesn't recognise 486
#	   instructions yet (they've only been with us for over a decade for
#	   crying out loud), even using the BSDI-format kludge doesn't quite
#	   work since as just terminates with an internal error.
#
#	   The compiler breaks when processing the aestab.c file, if you want to
#	   use the SCO cc to build cryptlib you'll have to do without AES (or
#	   use gcc, see below).
#
#	   UnixWare also finally supports threads, but it's not possible to build
#	   cryptlib with threading support because of a compiler bug in which the
#	   preprocessor sprays random spaces around any code in which token-
#	   pasting is used.  Although having foo##->mutex turn into
#	   "certInfo -> mutex" is OK, foo##.mutex turns into "certInfo. mutex"
#	   which the compiler chokes on (the appearances of spaces in different
#	   places doesn't seem to follow any pattern, the quoted strings above
#	   are exactly as output by the preprocessor).
#
#	   To avoid this mess, you can build the code using the SCO-modified gcc
#	   which has been hacked to work with cc-produced libraries.  In that
#	   case you should build with -pthread -D__SCO_VERSION__ -D_REENTRANT
#	   instead of -Kthread.
#
#	   Cool, the SCO comment is now longer than the comments for all the
#	   other Unix variants put together.

SCO:
	@echo "Please read the entry for SCO in the makefile before continuing."
	@make $(TARGET) CFLAGS="$(CFLAGS) -O"
UnixWare:
	@echo "Please read the entry for UnixWare in the makefile before continuing."
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O"
itgoaway:
	@echo "You poor bastard."
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O"

# Sun/Slowaris: An OS named after the 1972 Andrei Tarkovsky film about a space
#				station that drives people who work there mad.  Use gcc, but
#				fall back to the SUNSwspro compiler if necessary (in the c
#				checks below, the '-' is necessary because one of the checks
#				returns a nonzero status somewhere that causes make to bail
#				out, and the error suppression is necessary to avoid dozens of
#				bogus warnings about signed vs.unsigned chars).

SunOS:
	@if [ "$(USE_ASM)" != "no" -a `uname -m` = 'i86pc' ] ; then \
		make asm_sol OBJPATH=$(OBJPATH) ; \
	elif [ "$(USE_ASM)" != "no" ] ; then \
		make asm_sparc OBJPATH=$(OBJPATH) CC=$(CC) ; \
	fi
	@- if [ `uname -r | tr -d '[A-Z].' | cut -c 1` = '4' ] ; then \
		make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3" ; \
	else \
		if [ `which $(CC) | grep -c ucb/cc` = '1' ] && \
		   [ `which ucbcc | grep -c ucbcc` = '0' ] ; then \
			make $(DEFINES) CC=$(CC) CFLAGS="$(CFLAGS) -fomit-frame-pointer \
				-O3 -D_REENTRANT" ; \
		else \
			make $(DEFINES) CFLAGS="$(CFLAGS) -erroff=E_ARG_INCOMPATIBLE_WITH_ARG \
				-xO3 -D_REENTRANT" ; \
		fi ; \
	fi

# SVR4: Better results can be obtained by upgrading your OS to 4.4 BSD.
#		A few SVR4 unames don't report the OS name properly (Olivetti Unix)
#		so it's necessary to specify the SVR4 target on the command line.

SVR4:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"

# Ultrix: Use vcc or gcc

ULTRIX:
	@make asm_mips OBJPATH=$(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3"

# Amdahl UTS 4:

UTS4:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -Xc -O4"

#****************************************************************************
#*																			*
#*								Defines for other OS'es						*
#*																			*
#****************************************************************************

# BeOS: By default we use the newer BeOS development environment, which uses
#		gcc.  Since BeOS doesn't use the default Unix environment, we use
#		XCFLAGS and insert __BEOS__ as the OS.
#
#		The older BeOS development environment can still be used with:
#
#	@make $(DEFINES) CC=mwcc AR="mwcc -xml -o" SLD="mwcc -xms -f crypt.exp"

BeOS:
	@if grep "[r]ndunix" makefile > /dev/null ; then \
		sed s/[r]ndunix/rndbeos/g makefile > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@if [ `uname -m` = 'BePC' ]; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(XCFLAGS) -DUSE_ASM \
			-D__BEOS__ -fomit-frame-pointer -O3 -mcpu=pentium -D_REENTRANT" ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -U__UNIX__ -D__BEOS__ \
			-fomit-frame-pointer -O3 -D_REENTRANT" ; \
	fi

# EPOC.

EPOC:
	@make CFLAGS="$(XCFLAGS) -D__EPOC__" $(DEFINES)

# IBM MVS (a.k.a.OS/390, z/OS): The __MVS__ define is defined by the c89
#	compiler.  File naming behaviour is controlled by the DDNAME_IO define:
#
#	DDNAME_IO defined:
#		Use ddnames for all I/O.  User options will be saved in dynamically
#		allocated datasets userid.CRYPTLIB.filename.
#	DDNAME_IO not defined:
#		Use HFS for all I/O.  User options will be saved in directory
#		$HOME/.cryptlib.
#
#	Note: Tested on OS/390 2.10.

OS/390:
	@if grep "[r]ndunix" makefile > /dev/null ; then \
		sed s/[r]ndunix/rndmvs/g makefile > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@make asm_mvs OBJPATH=$(OBJPATH)
	@make $(DEFINES) OSOBJS="$(OBJPATH)mvsent.o" CFLAGS="$(XCFLAGS) -O2 \
		-W c,'langlvl(extended) csect rent roc ros targ(osv2r7) enum(4)' \
		-W c,'CONVLIT(ISO8859-1)' -DDDNAME_IO -D_OPEN_THREADS \
		-D_XOPEN_SOURCE_EXTENDED=1"

#****************************************************************************
#*																			*
#*							Cross-Compilation Builds						*
#*																			*
#****************************************************************************

# Generic entry for cross-compilation.  You need to provide at least the
# following:
#
#	-DCONFIG_DATA_LITTLEENDIAN/-DCONFIG_DATA_LITTLEENDIAN
#		Override endianness auto-detection.
#
#	-DOSVERSION=major_version
#		OS major version number.
#
#	$(OSNAME)
#		The target OS name, to select the appropriate compiler/link
#		options further down.
#
# For further options, see the cryptlib manual.
#
# Since we're cross-compiling here, we use $(XCFLAGS) and $(XDEFINES) instead
# if the usual $(CFLAGS) and $(DEFINES), which assume the target is a Unix
# system.

target-X:
	@make directories
	make $(DEFINES) OSNAME=target-X CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_xxxENDIAN -DOSVERSION=major_version \
		-fomit-frame-pointer -O3 -D_REENTRANT"

# Specific cross-compilation entries.
#
# MIPS running Linux: Little-endian, 2.x kernel.  Note that we use $(CFLAGS)
# rather than $(XCFLAGS) since this is a Unix system, just not the same as
# the source one.

target-mips:
	@make directories
	make $(XDEFINES) OSNAME=Linux CFLAGS="$(CFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DOSVERSION=2 \
		-fomit-frame-pointer -O3 -D_REENTRANT"

# Atmel ARM7 TDMI: Little-endian, no OS, maximum restrictions on resource
# usage since it's running on the bare metal.

target-atmel:
	@make directories
	@if grep "[r]ndunix" makefile > /dev/null ; then \
		sed s/[r]ndunix/rndatmel/g makefile > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=Atmel CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DCONFIG_NO_STDIO -DCONFIG_CONSERVE_MEMORY \
		-DCONFIG_NO_DYNALLOC -fomit-frame-pointer -O3"

#****************************************************************************
#*																			*
#*						Clean up after make has finished					*
#*																			*
#****************************************************************************

# The removal of the object file directories is silenced since the
# directories may not exist and we don't want unnecessary error messages
# arising from trying to remove them

clean:
	rm -f *.o core testlib stestlib endian $(LIBNAME) $(SLIBNAME)
	@rm -f $(STATIC_OBJ_PATH)*.o
	@if [ -d $(STATIC_OBJ_PATH) ] ; then rmdir $(STATIC_OBJ_DIR) ; fi
	@rm -f $(SHARED_OBJ_PATH)*.o
	@if [ -d $(SHARED_OBJ_DIR) ] ; then rmdir $(SHARED_OBJ_DIR) ; fi
	@if [ `uname -s` = 'CYGWIN_NT-5.0' ] ; then rm -f *.exe; fi
