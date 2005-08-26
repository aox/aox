#ifndef _OSCONFIG_DEFINED
#define _OSCONFIG_DEFINED

/* OpenSSL-specific defines */

#define OPENSSL_EXTERN	extern
#define OPENSSL_GLOBAL
#if defined( _WINDOWS ) && !defined( WINDOWS )
  #define WINDOWS				/* Old format */
  #define OPENSSL_SYS_WINDOWS	/* New fomat */
#endif /* OpenSSL Windows not defined */
#if defined( _WIN32 ) && !defined( WIN32 )
  #define WIN32					/* Old format */
  #define OPENSSL_SYS_WIN32		/* New format */
#endif /* OpenSSL Win32 not defined */
#include <stdlib.h>			/* For malloc() */
#include <string.h>			/* For memset() */
#ifdef USE_ASM
  #define MD5_ASM
  #define RMD160_ASM
  #define SHA1_ASM
#endif /* USE_ASM */

/* General defines */

#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define SIXTY_FOUR_BIT
#else
  #define THIRTY_TWO_BIT
#endif /* Machine word size */

#if defined( _MSC_VER )
  /* cryptlib is built with the highest warning level, disable some of the
     more irritating warnings produced by the OpenSSL code */
  #pragma warning( disable: 4244 )	/* int <-> unsigned char/short */
  #pragma warning( disable: 4100 )	/* Unreferenced parameter */
  #pragma warning( disable: 4127 )	/* Conditional is constant: while( TRUE ) */
#endif /* Visual C++ */

/* Aches */
#ifdef _AIX
  #define B_ENDIAN
  #define BN_LLONG
  #define RC4_CHAR
#endif /* AIX */

/* Alpha */
#if defined( __osf__ ) || defined( __alpha__ )
  #define L_ENDIAN
  #define SIXTY_FOUR_BIT_LONG
  #define DES_UNROLL
  #define DES_RISC1
  #define RC4_CHUNK
#endif /* Alpha */

/* BeOS */
#ifdef __BEOS__
  #if defined( __i386__ ) || defined( __i486__ ) || \
	  defined( __pentium__ ) || defined( __pentiumpro__ ) || \
	  defined( __k6__ ) || defined( __athlon__ )
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __ppc__ )
	#define B_ENDIAN
	#define BN_LLONG
	#define BF_PTR
	#define DES_UNROLL
	#define RC4_CHAR
	#define RC4_CHUNK
  #else
	#error Need to define CPU type for non-x86/non-PPC BeOS
  #endif /* BeoS variants */
#endif /* BeOS */

/* The BSDs */
#if defined( __FreeBSD__ ) || defined( __bsdi__ ) || \
	defined( __OpenBSD__ ) || defined( __NetBSD__ )
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX
#endif /* The BSDs */

/* Cray Unicos */
#ifdef _CRAY
  /* Crays are big-endian, but if B_ENDIAN is defined the code implicitly
     assumes 32-bit ints whereas Crays have 64-bit ints and longs.  However,
     the non-B/L_ENDIAN code happens to work, so we don't define either */
  #undef SIXTY_FOUR_BIT
  #define SIXTY_FOUR_BIT_LONG
  #define DES_INT
#endif /* Cray Unicos */

/* DGUX */
#ifdef __dgux
  #define L_ENDIAN
  #define RC4_INDEX
  #define DES_UNROLL
#endif /* DGUX */

/* Irix */
#ifdef __sgi

  /* Irix 5.x and lower */
  #if ( OSVERSION <= 5 )
	#define B_ENDIAN
	#define BN_LLONG
	#define BF_PTR
	#define DES_RISC2
	#define DES_PTR
	#define DES_UNROLL
	#define RC4_INDEX
	#define RC4_CHAR
	#define RC4_CHUNK
	#define MD2_CHAR

  /* Irix 6.x and higher */
  #else
	#define B_ENDIAN
	#define BN_DIV3W
	#define MD2_CHAR
	#define RC4_INDEX
	#define RC4_CHAR
	#define RC4_CHUNK_LL
	#define DES_UNROLL
	#define DES_RISC2
	#define DES_PTR
	#define BF_PTR
	#define SIXTY_FOUR_BIT
	/* Pure 64-bit should also define SIXTY_FOUR_BIT_LONG */
  #endif /* Irix versions */
#endif /* Irix */

/* Linux */
#ifdef __linux__
  #if defined( __i386__ ) || defined( __i486__ ) || \
	  defined( __pentium__ ) || defined( __pentiumpro__ ) || \
	  defined( __k6__ ) || defined( __athlon__ )
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __x86_64__ )
	/* 'long' and 'long long' are both 64 bits, we also use DES_INT since
	   int's are 64-bit */
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define DES_INT
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __ppc__ )
	#define B_ENDIAN
	#define BN_LLONG
	#define BF_PTR
	#define DES_UNROLL
	#define RC4_CHAR
	#define RC4_CHUNK
  #elif defined( __arm ) || defined( __arm__ )
	#define L_ENDIAN
	/* Not sure what other options the ARM build should enable... */
  #else
	#error Need to define CPU type for non-x86/non-PPC Linux
  #endif /* Linux variants */
#endif /* Linux */

/* Mac */
#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define B_ENDIAN
  #define BN_LLONG
  #define BF_PTR
  #define DES_UNROLL
  #define RC4_CHAR
  #define RC4_CHUNK
#endif /* Mac */

/* Darwin PPC / Mac OS X */
#if defined( __APPLE__ ) && !defined( __MAC__ )
  #if defined( __ppc__ )
	#define B_ENDIAN
  #else
	#define L_ENDIAN
  #endif
  #define BN_LLONG
  #define BF_PTR
  #define DES_UNROLL
  #define RC4_CHAR
  #define RC4_CHUNK
#endif /* Mac OS X */

/* MVS */
#ifdef __MVS__
  #define B_ENDIAN
#endif /* MVS */

/* NCR MP-RAS */
#ifdef __UNIX_SV__
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX
#endif /* UNIX_SV */

/* Palm OS: ARM */
#if defined( __PALMSOURCE__ )
  #if defined( __arm ) || defined( __arm__ )
	#define L_ENDIAN
	/* Not sure what other options the ARM build should enable... */
  #else
	#error Need to define architecture-specific values for crypto code
  #endif /* Palm OS variants */
#endif /* Palm OS */


/* PHUX */
#ifdef __hpux

  /* PHUX 9.x (some versions report it as 09 so we also check for 0) */
  #if ( OSVERSION == 0 || OSVERSION == 9 )
	#define B_ENDIAN
	#define BN_DIV2W
	#define BN_LLONG
	#define DES_PTR
	#define DES_UNROLL
	#define DES_RISC1
	#define MD32_XARRAY

  /* PHUX 10.x, 11.x */
  #else
	#define B_ENDIAN
	#define BN_DIV2W
	#define BN_LLONG
	#define DES_PTR
	#define DES_UNROLL
	#define DES_RISC1
	#define MD32_XARRAY
	/* Pure 64-bit should also define SIXTY_FOUR_BIT_LONG MD2_CHAR RC4_INDEX
	   RC4_CHAR DES_INT */
  #endif /* PHUX versions */
#endif /* PHUX */

/* QNX */
#ifdef __QNX__
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX
  #if OSVERSION <= 4
	/* The Watcom compiler can't handle 64-bit ints even though the hardware
	   can, so we have to build it as 16-bit code with 16x16 -> 32 multiplies
	   rather than 32x32 -> 64 */
	#undef THIRTY_TWO_BIT
	#define SIXTEEN_BIT
  #endif /* QNX 4.x */
#endif /* QNX */

/* SCO/UnixWare */
#ifdef __SCO_VERSION__

  /* SCO gcc */
  #if defined( __GNUC__ )
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX

  /* SCO cc */
  #else
    #define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
	#define MD2_CHAR
  #endif /* SCO	gcc/cc */
#endif /* SCO */

/* Solaris */
#ifdef sun

  /* Solaris Sparc */
  #ifdef sparc

	/* Solaris Sparc gcc */
	#if defined( __GNUC__ )
	  #define B_ENDIAN
	  #define BN_DIV2W
	  #define BN_LLONG
	  #define BF_PTR
	  #define DES_UNROLL
	  #define RC4_CHAR
	  #define RC4_CHUNK

	/* Solaris Sparc Sun C */
	#else
	  #define B_ENDIAN
	  #define BN_DIV2W
	  #define BN_LLONG
	  #define BF_PTR
	  #define DES_PTR
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_CHAR
	  #define RC4_CHUNK
	  /* Pure 64-bit should also define SIXTY_FOUR_BIT_LONG and DES_INT */
	#endif /* Solaris Sparc */

  /* Solaris x86 */
  #else

	/* Solaris x86 gcc */
	#if defined( __GNUC__ )
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define DES_PTR
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_INDEX

	/* Solaris x86 Sun C */
	#else
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define BF_PTR
	  #define DES_PTR
	  #define DES_UNROLL
	  #define RC4_CHAR
	  #define RC4_CHUNK
	#endif /* Solaris x86 */
  #endif /* Solaris Sparc vs x86 */
#endif /* Slowaris */

/* Symbian OS: ARM */
#if defined( __SYMBIAN32__ )
  #ifdef __MARM__
	#define L_ENDIAN
	/* Not sure what other options the ARM build should enable... */
  #else
	#error Need to define architecture-specific values for crypto code
  #endif /* Symbian OS variants */
#endif /* Symbian OS */

/* Tandem NSK/OSS */
#ifdef __TANDEM
  #define B_ENDIAN
  #define BF_PTR
  #define DES_RISC2
  #define DES_PTR
  #define DES_UNROLL
  #define RC4_INDEX
  #define RC4_CHAR
  #define RC4_CHUNK
  #define MD2_CHAR
#endif /* Tandem */

/* Ultrix */
#ifdef __ultrix__
  #define L_ENDIAN
  #define DES_PTR
  #define DES_RISC2
  #define DES_UNROLL
#endif /* Ultrix */

/* VM/CMS */
#ifdef __VMCMS__
  #define B_ENDIAN
#endif /* VM/CMS */

/* Windows */
#if ( defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 ) )

  /* VC++ */
  #if defined( _MSC_VER )

	/* VC++ 32-bit */
	#if ( _MSC_VER >= 1000 )
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define RC4_INDEX

	/* VC++ 16-bit */
	#else
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define MD2_CHAR
	  #define DES_UNROLL
	  #define DES_PTR
	  #define RC4_INDEX
	  #undef THIRTY_TWO_BIT
	  #define SIXTEEN_BIT
	#endif /* VC++ 32 vs 16-bit */

  /* BC++ */
  #elif defined( __BORLANDC__ )
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define RC4_INDEX

  /* gcc */
  #else
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #endif /* Assorted Windows compilers */
#endif /* Windows */
#ifdef __CYGWIN__
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX
#endif /* gcc native under Cygwin (i.e. not a Cygwin-hosted 
		  cross-development toolchain */

/* Xilinx XMK */

#if defined ( _XMK )
  #if defined( __mb__ )
	#define B_ENDIAN
	/* Not sure what other options the MicroBlaze build should enable... */
  #elif defined( __ppc__ )
	#define B_ENDIAN
	#define BN_LLONG
	#define BF_PTR
	#define DES_UNROLL
	#define RC4_CHAR
	#define RC4_CHUNK
  #else
	#error Need to define CPU type for non-MicroBlaze/non-PPC XMK
  #endif /* XMK target variants */
#endif /* Xilinx XMK */

/* RC4_CHUNK is actually a data type rather than a straight define, so we
   redefine it as a data type if it's been defined */

#ifdef RC4_CHUNK
  #undef RC4_CHUNK
  #define RC4_CHUNK	unsigned long
#endif /* RC4_CHUNK */

/* Make sure we weren't missed out.  See the comment in the Cray section
   for the exception for Crays */

#if !defined( _CRAY ) && !defined( L_ENDIAN ) && !defined( B_ENDIAN )
  #error You need to add system-specific configuration settings to osconfig.h
#endif /* Endianness not defined */
#ifdef CHECK_ENDIANNESS		/* One-off check in des_enc.c */
  #if defined( INC_CHILD )
	#include "../crypt.h"
  #else
	#include "crypt.h"
  #endif /* Compiler-specific includes */
  #if ( defined( L_ENDIAN ) && !defined( DATA_LITTLEENDIAN ) ) || \
	  ( defined( B_ENDIAN ) && !defined( DATA_BIGENDIAN ) )
	#error You need to update the system-specific configuration settings in osconfig.h
  #endif /* Endianness conflict */
#endif /* One-off check */

#endif /* _OSCONFIG_DEFINED */
