/****************************************************************************
*																			*
*					  cryptlib OS-Specific Defines Header File 				*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _OSSPEC_DEFINED

#define _OSSPEC_DEFINED

/* To build the static .LIB under Win32, uncomment the following define (this
   it not recommended since the init/shutdown is no longer completely thread-
   safe).  In theory it should be possible to detect the build of a DLL vs.a
   LIB with the _DLL define which is set when the /MD (multithreaded DLL)
   option is used, however VC++ only defines _DLL when /MD is used *and*
   it's linked with the MT DLL runtime.  If it's linked with the statically
   linked runtime, _DLL isn't defined, which would result in the unsafe LIB
   version being built as a DLL */

/* #define STATIC_LIB */

/* os_spec.h performs OS and compiler detection that's used by config.h, so
   this file must be applied before config.h */

#ifdef _CONFIG_DEFINED
  #error "os_spec.h must be included before config.h"
#endif /* _CONFIG_DEFINED */

/****************************************************************************
*																			*
*									OS Detection							*
*																			*
****************************************************************************/

/* Try and figure out if we're running under Windows and Win16/Win32/WinCE.
   We have to jump through all sorts of hoops later on, not helped by the
   fact that the method of detecting Windows at compile time changes with
   different versions of Visual C (it's different for each of VC 2.0, 2.1,
   4.0, and 4.1.  It actually remains the same after 4.1) */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* Win16 */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
	#define __WINDOWS__		/* Win32 or WinCE */
  #endif /* __WINDOWS__ */
  #ifdef _WIN32_WCE
	#define __WINCE__
  #else
	#define __WIN32__
  #endif /* WinCE vs. Win32 */
#endif /* Win32 or WinCE */
#if defined( __WINDOWS__ ) && \
	!( defined( __WIN32__ ) || defined( __WINCE__ ) )
  #define __WIN16__
#endif /* Windows without Win32 or WinCE */

/* If we're using a DOS compiler and it's not a 32-bit one, record this.
   __MSDOS__ is predefined by a number of compilers, so we use __MSDOS16__
   for stuff that's 16-bit DOS specific, and __MSDOS32__ for stuff that's
   32-bit DOS specific */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* 16-bit DOS */
#if defined( __WATCOMC__ ) && defined( __DOS__ )
  #ifndef __MSDOS__
	#define __MSDOS__
  #endif /* 16- or 32-bit DOS */
  #if defined( __386__ ) && !defined( __MSDOS32__ )
	#define __MSDOS32__
  #endif /* 32-bit DOS */
#endif /* Watcom C under DOS */

/* Make the Tandem, Macintosh, AS/400, PalmOS, and VMS defines look a bit 
   more like the usual ANSI defines used to identify the other OS types */

#ifdef __TANDEM
  #if defined( _OSS_TARGET )
	#define __TANDEM_OSS__
  #elif defined( _GUARDIAN_TARGET )
	#define __TANDEM_NSK__
  #else
	#error "Can't determine Tandem OS target type (NSK or OSS)"
  #endif /* Tandem OSS vs. NSK */
#endif /* Tandem */

#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define __MAC__
#endif /* Macintosh */

#if defined( __OS400__ ) || defined( __ILEC400__ )
  #define __AS400__
#endif /* AS/400 */

#ifdef __PALMSOURCE__
  #define __PALMOS__
#endif /* Palm OS */

#ifdef __VMS
  #define __VMS__
#endif /* VMS */

/* In some cases we're using a DOS or Windows system as a cross-development
   platform, if we are we add extra defines to turn off some Windows-
   specific features */

#ifdef _SCCTK
  #define __IBM4758__
#endif /* IBM 4758 cross-compiled under Windows */

/****************************************************************************
*																			*
*						OS-Specific Compiler Configuration					*
*																			*
****************************************************************************/

/* Visual C++ capabilities have changed somewhat over the years, the 
   following defines make explicit what we're testing for in a check of 
   _MSC_VER.

	Visual C++ 1.5 _MSC_VER = 800
	Visual C++ 5.0 _MSC_VER = 1100
	Visual C++ 6.0 _MSC_VER = 1200
	Visual C++ 7.0 (VC2002) _MSC_VER = 1300
	Visual C++ 7.1 (VC2003) _MSC_VER = 1310
	Visual C++ 8.0 (VC2005) _MSC_VER = 1400 */

#ifdef _MSC_VER
  #define VC_16BIT( _MSC_VER )		( _MSC_VER <= 800 )
  #define VC_LT_2005( _MSC_VER )	( _MSC_VER < 1400 )
  #define VC_GE_2005( _MSC_VER )	( _MSC_VER >= 1400 )
#else
  /* These aren't specifically required on non-VC++ systems, but some 
     preprocessors get confused if they aren't defined since they're used */
  #define VC_16BIT( _MSC_VER )		0
  #define VC_LT_2005( _MSC_VER )	0
  #define VC_GE_2005( _MSC_VER )	0
#endif /* Visual C++ */

/* If we're compiling under VC++ with the maximum level of warnings, turn
   off some of the more irritating warnings */

#if defined( _MSC_VER )
  #if VC_16BIT( _MSC_VER )
	#pragma warning( disable: 4135 )/* Conversion bet.diff.integral types */
	#pragma warning( disable: 4761 )/* Integral size mismatch in argument */
  #endif /* 16-bit VC++ */

  /* Warning level 3 */
  #pragma warning( disable: 4018 )	/* Comparing signed <-> unsigned value */
  #pragma warning( disable: 4127 )	/* Conditional is constant: while( TRUE ) */

  /* Warning level 4.  The function <-> data pointer cast warnings are
	 orthogonal and impossible to disable (they override the universal
	 'void *' pointer type), the signed/unsigned and size warnings are
	 more compiler peeves as for the level 3 warnings, and the struct
	 initialisation warnings are standards extensions that the struct
	 STATIC_INIT macros manage for us */
  #pragma warning( disable: 4054 )	/* Cast from fn.ptr -> generic (data) ptr.*/
  #pragma warning( disable: 4055 )	/* Cast from generic (data) ptr. -> fn.ptr.*/
  #pragma warning( disable: 4057 )	/* char vs.unsigned char use */
  #pragma warning( disable: 4204 )	/* Struct initialised with non-const value */
  #pragma warning( disable: 4221 )	/* Struct initialised with addr.of auto.var */
  #pragma warning( disable: 4244 )	/* int <-> unsigned char/short */
  #pragma warning( disable: 4245 )	/* int <-> unsigned long */
  #pragma warning( disable: 4267 )	/* int <-> size_t */
  #pragma warning( disable: 4305 )	/* long <-> size_t */
  #pragma warning( disable: 4389 )	/* signed ==/!= unsigned compare */

  /* gcc -wall type warnings.  The highest warning level generates large
     numbers of spurious warnings (including ones in VC++ headers), so it's
	 best to only enable them for one-off test builds requiring manual
	 checking for real errors.  The used-before-initialised is particularly
	 common during the code generation phase, when the compiler flags all
	 values initialised in conditional code blocks as potential problems */
  #if 1
	#pragma warning( disable: 4100 )	/* Unreferenced parameter */
	#pragma warning( disable: 4201 )	/* Nameless struct/union in VC++ header */
	#pragma warning( disable: 4701 )	/* Variable used before initialised */
  #endif /* 1 */
#endif /* Visual C++ */

/* VC++ 2005 implements the TR 24731 security extensions but doesn't yet 
   define __STDC_LIB_EXT1__, so if we detect this version of the compiler we 
   define it ourselves */

#if defined( _MSC_VER ) && VC_GE_2005( _MSC_VER ) && \
	!defined( __STDC_LIB_EXT1__ )
  #define __STDC_LIB_EXT1__
#endif /* VC++ 2005 without __STDC_LIB_EXT1__ defined */

/* The ability to modify warnings via the project file in BC++ 5.0x is
   completely broken, the only way to do this is via pragmas in the source
   code */

#if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 )
  /* Spurious warnings to disable */
  #pragma warn -aus						/* Assigned but never used.  This is
										   frequently misreported even when
										   the value is quite obviously used */
  #pragma warn -csu						/* Comparing signed/unsigned value */
  #pragma warn -par						/* Parameter is never used	*/
  #pragma warn -sig						/* Conversion may lose significant digits */
  #pragma warn -ucp						/* Signed/unsigned char assignment */

  /* Useful warnings to enable */
  #pragma warn +amb						/* Ambiguous operators need parentheses */
  #pragma warn +amp						/* Superfluous & with function */
  #pragma warn +asm						/* Unknown assembler instruction */
  #pragma warn +ccc						/* Condition is always true/false */
  #pragma warn +cln						/* Constant is long */
  #pragma warn +def						/* Use of ident before definition */
  #pragma warn +stv						/* Structure passed by value */
#endif /* Broken BC++ 5.0x warning handling */

/* All Windows CE functions are Unicode-only, this was an attempt to clean
   up the ASCII vs. Unicode kludges in Win32 but unfortunately was made just
   before UTF8 took off.  Because UTF8 allows everyone to keep using their
   old ASCII stuff while being nominally Unicode-aware, it's unlikely that
   any new Unicode-only systems will appear in the future, leaving WinCE's
   Unicode-only API an orphan.  The easiest way to handle this is to convert
   all strings to ASCII/8 bit as they come in from the external cryptlib API
   and convert them back to Unicode as required when they're passed to WinCE
   OS functions.  In other words Unicode is treated just like EBCDIC and
   pushed out to the edges of cryptlib.  This requires the minimum amount of
   conversion and special-case handling internally */

#ifdef __WINCE__
  #define UNICODE_CHARS
#endif /* WinCE */

/* If we're compiling on the AS/400, make enums a fixed size rather than
   using the variable-length values that IBM compilers default to, and force
   strings into a read-only segment (by default they're writeable) */

#ifdef __AS400__
  #pragma enumsize( 4 )
  #pragma strings( readonly )
  #define EBCDIC_CHARS
#endif /* AS/400 */

/* If we're compiling under MVS or VM/CMS, make enums a fixed size rather
   than using the variable-length values that IBM compilers default to */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma enum( 4 )
  #define USE_ETOA		/* Use built-in ASCII <-> EBCDIC conversion */
  #define EBCDIC_CHARS
#endif /* __MVS__ */

/* If we're compiling under QNX, make enums a fixed size rather than using
   the variable-length values that the Watcom compiler defaults to */

#if defined( __QNX__ ) && defined( __WATCOMC__ )
  #pragma enum int
#endif /* QNX and Watcom C */

/* If it's a C99-compliant compiler, enable the use of varags macros */

#if ( defined( __STDC_VERSION__ ) && ( __STDC_VERSION__ >= 199901L ) ) || \
	( defined( __GNUC__ ) && ( __GNUC__ >= 3 ) )
  #define VARARGS_MACROS
#endif /* C99 compilers with varargs macro support */

/* A few rare operations are word-size-dependant, which we detect via
   limits.h */

#include <limits.h>
#if INT_MAX <= 32768L
  #define SYSTEM_16BIT
#elif ULONG_MAX > 0xFFFFFFFFUL
  #define SYSTEM_64BIT
#else
  #define SYSTEM_32BIT
#endif /* 16- vs.32- vs.64-bit system */

/* Useful data types */

typedef unsigned char		BYTE;
#if defined( __WIN32__ ) || defined( __WINCE__ )
  #define BOOLEAN			int
#else
  typedef int				BOOLEAN;
#endif /* __WIN32__ || __WINCE__ */

/* If we're building the Win32 kernel driver version, include the DDK
   headers */

#if defined( __WIN32__ ) && defined( NT_DRIVER )
  #include <ntddk.h>
#endif /* NT kernel driver */

/* In 16-bit environments the BSS data is large enough that it overflows the
   (64K) BSS segment.  Because of this we move as much of it as possible into
   its own segment with the following define */

#if defined( __WIN16__ )
  #ifdef _MSC_VER
	#define FAR_BSS	__far
  #else
	#define FAR_BSS	far
  #endif /* VC++ vs.other compilers */
#else
  #define FAR_BSS
#endif /* 16-bit systems */

/* If we're using DOS or Windows as a cross-development platform, we need
   the OS-specific values defined initially to get the types right but don't
   want it defined later on since the target platform won't really be
   running DOS or Windows, so we undefine them after the types have been
   sorted out */

#ifdef __IBM4758__
  #undef __MSDOS__
  #undef __WINDOWS__
  #undef __WIN32__
#endif /* IBM 4758 */

/* Some systems (typically 16-bit or embedded ones) have rather limited
   amounts of memory available, if we're building on one of these we limit
   the size of some of the buffers that we use and the size of the object
   table */

#if defined( __MSDOS16__ ) || defined( __uClinux__ )
  #define CONFIG_CONSERVE_MEMORY
  #define CONFIG_NUM_OBJECTS		128
#endif /* Memory-starved systems */

/* Win32 consists of Win95/98/ME and WinNT/2000/XP, Win95 doesn't have a
   number of the functions and services that exist in NT so we need to adapt
   the code based on the Win32 variant.  The following flag records which OS
   variant we're crawling under */

#ifdef __WIN32__
  extern BOOLEAN isWin95;
#endif /* Win32 */

/* Since the Win32 randomness-gathering uses a background randomness polling
   thread, we can't build a Win32 version with NO_THREADS */

#if defined( __WIN32__ ) && defined( NO_THREADS )
  #error The Win32 version of cryptlib must have threading enabled
#endif /* Win32 without threading */

/* Boolean constants */

#ifndef TRUE
  #define FALSE			0
  #define TRUE			!FALSE
#endif /* Boolean values */

/* cryptlib contains a few locations that require forward declarations for
   static data:

	extern const int foo[];

	foo[ i ] = bar;

	static const int foo[] = { ... };

   Compiler opinions on how to handle this vary.  Some compile it as is
   (i.e. 'static const ...'), some don't allow the 'static', some allow both
   variants, and some produce warnings with both but allow them anyway
   (there are probably more variants with further compilers).  To get around
   this, we use the following define and then vary it for broken compilers
   (the following is the minimum required to get it to compile, other broken
   compilers will still produce warnings) */

#if ( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 ) ) || \
	defined( __VMCMS__ ) || defined( __MVS__ ) || defined( __MRC__ ) || \
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	( defined( __UNIX__ ) && defined( _MPRAS ) )
  #define STATIC_DATA
#else
  #define STATIC_DATA	static
#endif /* Fn.prototyping workarounds for borken compilers */

/* A few compilers won't allow initialisation of a struct at runtime, so
   we have to kludge the init with macros.  This is rather ugly since
   instead of saying "struct = { a, b, c }" we have to set each field
   individually by name.  The real reason for doing this though is that
   if the compiler can initialise the struct directly, we can make the
   fields const for better usage checking by the compiler.

   There are two forms of this, one for simple structs and one for arrays
   of structs.  At the moment the only use for the array-init is for the
   situation where the array represents a sequence of search options with
   the last one being a terminator entry, so we provide a simplified form
   that only sets the required fields */

#if ( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 ) ) || \
	( defined( __hpux ) && !defined( __GNUC__ ) ) || \
	( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
	defined( __SUNPRO_C ) || defined( __SCO_VERSION__ ) || \
	defined( _CRAY )
  #define CONST_INIT
  #define CONST_INIT_STRUCT_3( decl, init1, init2, init3 ) \
		  decl
  #define CONST_INIT_STRUCT_4( decl, init1, init2, init3, init4 ) \
		  decl
  #define CONST_INIT_STRUCT_5( decl, init1, init2, init3, init4, init5 ) \
		  decl
  #define CONST_SET_STRUCT( init ) \
		  init

  #define CONST_INIT_STRUCT_A2( decl, init1, init2 ) \
		  decl
  #define CONST_SET_STRUCT_A( init ) \
		  init
#else
  #define CONST_INIT	const
  #define CONST_INIT_STRUCT_3( decl, init1, init2, init3 ) \
		  decl = { init1, init2, init3 }
  #define CONST_INIT_STRUCT_4( decl, init1, init2, init3, init4 ) \
		  decl = { init1, init2, init3, init4 }
  #define CONST_INIT_STRUCT_5( decl, init1, init2, init3, init4, init5 ) \
		  decl = { init1, init2, init3, init4, init5 }
  #define CONST_SET_STRUCT( init )

  #define CONST_INIT_STRUCT_A2( decl, init1, init2 ) \
		  const decl = { { init1, 0 }, { init2, 0 } }
  #define CONST_SET_STRUCT_A( init )
#endif /* Watcom C || SunPro C || SCO C */

/* gcc provides extra parameter checking for printf-like functions, which
   we enable for the extended-return functions */

#ifdef __GNUC__
  #define PRINTF_FN		__attribute__ (( format( printf, 3, 4 ) ))
  #define PRINTF_FN_EX	__attribute__ (( format( printf, 4, 5 ) ))
#else
  #define PRINTF_FN
  #define PRINTF_FN_EX
#endif /* gcc */

/* The Tandem mktime() is broken and can't convert dates beyond 2023, so we
   replace it with our own version which can */

#if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
  #define mktime	my_mktime
#endif /* __TANDEM_NSK__ || __TANDEM_OSS__ */

/* Support for vsnprintf() (used for assembling the
   CRYPT_ATTRIBUTE_INT_ERRORMESSAGE value) is a bit hit-and-miss on non-Unix
   systems and also on older Unixen, if it's not available we alias it to
   vsprintf().  Luckily this works because vs{n}printf() has a fixed arg
   count, unlike s{n}printf(), which are varargs functions */

#if defined( __ITRON__ ) || \
	defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 ) || \
	defined( __UNIX__ ) && \
		( ( defined( __SCO_VERSION__ ) && OSVERSION < 5 ) || \
		  ( defined( sun ) && OSVERSION < 5 ) || \
		  defined( __SYMBIAN32__ ) )
  #define vsnprintf( buf, count, format, arg )	vsprintf( buf, format, arg )
#elif defined( 	__WINDOWS__ )
  /* Microsoft provides vsnprintf() in all VC++ and eVC++ libraries, but
     it's given as _vsnprintf() since it's not an ANSI/ISO C (pre-C99)
	 function */
  #define vsnprintf		_vsnprintf
#endif /* Systems without vsnprintf() */

/* Enable use of assembly-language alternatives to C functions if possible */

#if defined( __WIN32__ ) && !defined( __BORLANDC__ )
  /* Unlike the equivalent crypto code, the MD5, RIPEMD-160, and SHA-1
	 hashing code needs special defines set to enable the use of asm
	 alternatives.  Since this works by triggering redefines of function
	 names in the source code, we can only do this under Windows because for
	 other systems you'd need to conditionally alter the makefile as well.
	 Since these two defines were left accidentally unset for about five
	 years and were only noticed when someone benchmarked the code against
	 BSAFE, it's unlikely that this is of any real concern */
  #define MD5_ASM
  #define SHA1_ASM
  #define RMD160_ASM

  /* Turn on bignum asm as well.  By default this is done anyway, but the
     x86 asm code contains some additional routines not present in the
     asm modules for other CPUs, so we have to define this to disable the
     equivalent C code, which must be present for non-x86 asm modules */
  #define USE_ASM

  /* Enable use of the AES ASM code */
  #define AES_ASM

  /* Enable use of zlib ASM longest-match code.  zlib comes with two asm
     files, of which match.asm (assemble with "ml /Zp /coff /c match.asm")
	 causes segfaults, so we use gvmat32.asm */
  #define ASMV
#endif /* Win32 */

/****************************************************************************
*																			*
*								Dynamic Loading Support						*
*																			*
****************************************************************************/

/* On systems that support dynamic loading, we bind various drivers and
   libraries at runtime rather than at compile time.  Under Windows this is
   fairly easy but under Unix it's supported somewhat selectively and may be
   buggy or platform-specific */

#if defined( __WINDOWS__ ) || \
	( defined( __UNIX__ ) && \
	  ( ( defined( sun ) && OSVERSION > 4 ) || defined( __linux__ ) || \
		defined( _AIX ) || ( defined( __APPLE__ ) && !defined( __MAC__ ) ) ) )
  #define DYNAMIC_LOAD

  /* Macros to map OS-specific dynamic-load values to generic ones */
  #if defined( __WINDOWS__ )
	#define INSTANCE_HANDLE		HINSTANCE
	#define NULL_INSTANCE		( HINSTANCE ) NULL
	#define DynamicLoad( name )	LoadLibrary( name )
	#define DynamicUnload		FreeLibrary
	#define DynamicBind			GetProcAddress
  #elif defined( __UNIX__ )
    /* Older versions of OS X didn't have dlopen() support but required
	   the use of the rather painful low-level dyld() interface.  If you're
	   running an older version of OS X and don't have the dlcompat wrapper
	   installed, get Peter O'Gorman's dlopen() implementation, which wraps
	   the dyld() interface */
	#if !( defined( __APPLE__ ) && OSVERSION < 7 )
	  #include <dlfcn.h>
	#endif /* Mac OS X */
	#define INSTANCE_HANDLE		void *
	#define NULL_INSTANCE		NULL
	#define DynamicLoad( name )	dlopen( name, RTLD_LAZY )
	#define DynamicUnload		dlclose
	#define DynamicBind			dlsym
  #elif defined __VMCMS__
	#include <dll.h>

	#define INSTANCE_HANDLE		dllhandle *
	#define NULL_INSTANCE		NULL
	#define DynamicLoad( name )	dllload( name, RTLD_LAZY )
	#define DynamicUnload		dllfree
	#define DynamicBind			dlqueryfn
  #endif /* OS-specific instance handles */
#endif /* Windows || Some Unix versions */

/****************************************************************************
*																			*
*								Endianness Defines							*
*																			*
****************************************************************************/

/* If the endianness isn't predefined and the compiler can tell us what
   endianness we've got, use this in preference to all other methods.  This
   is only really necessary on non-Unix systems since the makefile runtime
   test will tell us the endianness under Unix */

#if defined( CONFIG_DATA_LITTLEENDIAN ) || defined( CONFIG_DATA_BIGENDIAN )
  /* If we're cross-compiling for another system, the endianness auto-
	 detection will have been overridden.  In this case we force it to be
	 what the user has specified rather than what we've auto-detected */
  #undef DATA_LITTLEENDIAN
  #undef DATA_BIGENDIAN
  #ifdef CONFIG_DATA_LITTLEENDIAN
	#define DATA_LITTLEENDIAN
  #else
	#define DATA_BIGENDIAN
  #endif /* CONFIG_DATA_LITTLEENDIAN */
#endif /* Forced big vs.little-endian */

#if !defined( DATA_LITTLEENDIAN ) && !defined( DATA_BIGENDIAN )
  #if defined( BIG_ENDIAN ) && defined( LITTLE_ENDIAN ) && defined( BYTE_ORDER )
	/* Some systems define both BIG_ENDIAN and LITTLE_ENDIAN, then define
	   BYTE_ORDER to the appropriate one, so we check this and define the
	   appropriate value */
	#if ( BYTE_ORDER == BIG_ENDIAN ) && !defined( DATA_BIGENDIAN )
	  #define DATA_BIGENDIAN
	#elif ( BYTE_ORDER == LITTLE_ENDIAN ) && !defined( DATA_LITTLEENDIAN )
	  #define DATA_LITTLEENDIAN
	#else
	  #error BYTE_ORDER is neither BIG_ENDIAN nor LITTLE_ENDIAN
	#endif /* BYTE_ORDER-specific define */
  #elif defined( _M_I86 ) || defined( _M_IX86 ) || defined( __TURBOC__ ) || \
		defined( __OS2__ )
	#define DATA_LITTLEENDIAN	/* Intel architecture always little-endian */
  #elif defined( __WINCE__ )
	/* For WinCE it can get a bit complicated, however because of x86 cargo
	   cult programming WinCE systems always tend to be set up in little-
	   endian mode */
	#define DATA_LITTLEENDIAN	/* Intel architecture always little-endian */
  #elif defined( AMIGA ) || defined( __MWERKS__ ) || defined( SYMANTEC_C ) || \
		defined( THINK_C ) || defined( applec ) || defined( __MRC__ )
	#define DATA_BIGENDIAN		/* Motorola architecture always big-endian */
  #elif defined( VMS ) || defined( __VMS )
	#define DATA_LITTLEENDIAN	/* VAX architecture always little-endian */
  #elif defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
	#define DATA_BIGENDIAN		/* Tandem architecture always big-endian */
  #elif defined( __AS400__ ) || defined( __VMCMS__ ) || defined( __MVS__ )
	#define DATA_BIGENDIAN		/* IBM big iron always big-endian */
  #elif defined __GNUC__
	#ifdef BYTES_BIG_ENDIAN
	  #define DATA_BIGENDIAN	/* Big-endian byte order */
	#else
	  #define DATA_LITTLEENDIAN	/* Undefined = little-endian byte order */
	#endif /* __GNUC__ */
  #endif /* Compiler-specific endianness checks */
#endif /* !( DATA_LITTLEENDIAN || DATA_BIGENDIAN ) */

/* The last-resort method.  Thanks to Shawn Clifford
   <sysop@robot.nuceng.ufl.edu> for this trick.

   NB: A number of compilers aren't tough enough for this test */

#if !defined( DATA_LITTLEENDIAN ) && !defined( DATA_BIGENDIAN )
  #if ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'B' )
	#define DATA_LITTLEENDIAN
  #elif ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'A' )
	#define DATA_BIGENDIAN
  #else
	#error "Cannot determine processor endianness - edit misc/os_spec.h and recompile"
  #endif /* Endianness test */
#endif /* !( DATA_LITTLEENDIAN || DATA_BIGENDIAN ) */

/* Sanity check to catch both values being defined */

#if defined( DATA_LITTLEENDIAN ) && defined( DATA_BIGENDIAN )
  #error Both DATA_LITTLEENDIAN and DATA_BIGENDIAN are defined
#endif /* DATA_LITTLEENDIAN && DATA_BIGENDIAN */

/****************************************************************************
*																			*
*								Filesystem Values							*
*																			*
****************************************************************************/

/* When performing file I/O we need to know how large path names can get in
   order to perform range checking and allocate buffers.  This gets a bit
   tricky since not all systems have PATH_MAX, so we first try for PATH_MAX,
   if that fails we try _POSIX_PATH_MAX (which is a generic 255 bytes and if
   defined always seems to be less than whatever the real PATH_MAX should be),
   if that also fails we grab stdio.h and try and get FILENAME_MAX, with an
   extra check for PATH_MAX in case it's defined in stdio.h instead of
   limits.h where it should be.  FILENAME_MAX isn't really correct since it's
   the maximum length of a filename rather than a path, but some environments
   treat it as if it were PATH_MAX and in any case it's the best that we can
   do in the absence of anything better */

#if defined( PATH_MAX )
  #define MAX_PATH_LENGTH		PATH_MAX
#elif defined( _POSIX_PATH_MAX )
  #define MAX_PATH_LENGTH		_POSIX_PATH_MAX
#else
  #ifndef FILENAME_MAX
	#include <stdio.h>
  #endif /* FILENAME_MAX */
  #if defined( PATH_MAX )
	#define MAX_PATH_LENGTH		PATH_MAX
  #elif defined( MAX_PATH )
	#define MAX_PATH_LENGTH		MAX_PATH
  #else
	#define MAX_PATH_LENGTH		FILENAME_MAX
  #endif /* PATH_MAX, MAX_PATH, or FILENAME_MAX */
#endif /* PATH_MAX */
#ifdef __UNIX__
  /* SunOS 4.1.x doesn't define FILENAME_MAX in limits.h, however it does
	 define a POSIX path length limit so we use that instead.  There are a
	 number of places in various headers in which a max.path length is
	 defined either as 255 or 1024, but we use the POSIX limit since this is
	 the only thing defined in limits.h */
  #if defined( sun ) && ( OSVERSION == 4 ) && !defined( FILENAME_MAX )
	#define FILENAME_MAX		_POSIX_PATH_MAX
  #endif /* SunOS 4.1.x FILENAME_MAX define */
#endif /* __UNIX__ */

/* SunOS 4 doesn't have memmove(), but Solaris does, so we define memmove()
   to bcopy() under 4.  In addition SunOS doesn't define the fseek()
   position indicators so we define these as well */

#if defined( __UNIX__ ) && defined( sun ) && ( OSVERSION == 4 )
  #define memmove	bcopy

  #define SEEK_SET	0
  #define SEEK_CUR	1
  #define SEEK_END	2
#endif /* SunOS 4 */

/****************************************************************************
*																			*
*									Charset Support							*
*																			*
****************************************************************************/

/* Widechar handling.  Most systems now support this, the only support that
   we only require is the wchar_t type define.

   Unfortunately in order to check for explicitly enabled widechar support
   via config.h we have to include config.h at this point, because this
   file, containing OS- and compiler-specific settings, both detects the
   OSes and compilers that support widechars in the "OS Detection" section
   above, and then sets the appropriate widechar settings here.  In between
   the two, config.h uses the OS/compiler-detection output to enable or
   disable widechars as required, so we need to slip it in between the two
   sections */

#if defined( INC_ALL )
  #include "config.h"
#else
  #include "misc/config.h"
#endif /* Compiler-specific includes */

#ifdef USE_WIDECHARS
  #if !( ( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
		 ( defined( __WIN32__ ) && defined( __BORLANDC__ ) ) || \
		 ( defined( __WINCE__ ) && _WIN32_WCE < 400 ) || \
		 defined( __XMK__ ) )
	#include <wchar.h>
  #endif /* Systems with widechar support in stdlib.h */
  #define WCSIZE	( sizeof( wchar_t ) )

  #if defined( __MSDOS16__ ) && !defined( __BORLANDC__ )
	typedef unsigned short int wchar_t;	/* Widechar data type */
  #endif /* OSes that don't support widechars */
  #if defined( __BORLANDC__ ) && ( __BORLANDC__ == 0x410 )
	#define wchar_t unsigned short int;	/* BC++ 3.1 has an 8-bit wchar_t */
  #endif /* BC++ 3.1 */
#else
  /* No native widechar support, define the necesary types ourselves unless
	 we're running under older OS X (Darwin 6.x), which defines wchar_t in
	 stdlib.h even though there's no wchar support present, or PalmOS, which
	 defines it in wchar.h but then defines it differently in stddef.h, and
	 in any case has no wchar support present */
  #if !( defined( __APPLE__ ) || defined( __OpenBSD__ ) || \
		 defined( __PALMOS__ ) )
	typedef unsigned short int wchar_t;
  #endif /* __APPLE__ */
  #define WCSIZE	( sizeof( wchar_t ) )
#endif /* USE_WIDECHARS */

/* The EOL convention used when outputting text.  Technically speaking
   XMK doesn't use any particular EOL convention, but since the
   typical development environment is debug output sent to a Windows
   terminal emulator, we use CRLF */

#if defined( __MSDOS16__ ) || defined( __MSDOS32__ ) || \
	defined( __OS2__ ) || defined( __SYMBIAN32__ ) || \
	defined( __WINDOWS__ ) || defined( __XMK__ )
  #define EOL		"\r\n"
  #define EOL_LEN	2
#elif ( defined( __APPLE__ ) && !defined( __MAC__ ) ) || \
	  defined( __BEOS__ ) || defined( __IBM4758__ ) || \
	  defined( __PALMOS__ ) || defined( __TANDEM_NSK__ ) || \
	  defined( __TANDEM_OSS__ ) || defined( __UNIX__ ) || \
	  defined( __VMCMS__ )
  #define EOL		"\n"
  #define EOL_LEN	1
#elif defined( __MAC__ )
  #define EOL		"\r"
  #define EOL_LEN	1
#else
  #error "You need to add the OS-specific define to enable end-of-line handling"
#endif /* OS-specific EOL markers */

/* If we're compiling on IBM mainframes, enable EBCDIC <-> ASCII string
   conversion.  Since cryptlib uses ASCII internally for all strings, we
   need to check to make sure it's been built with ASCII strings enabled
   before we go any further */

#ifdef EBCDIC_CHARS
  #if 'A' != 0x41
	#error cryptlib must be compiled with ASCII literals
  #endif /* Check for use of ASCII */

  int asciiToEbcdic( char *dest, const char *src, const int length );
  int ebcdicToAscii( char *dest, const char *src, const int length );
  char *bufferToEbcdic( char *buffer, const char *string );
  char *bufferToAscii( char *buffer, const char *string );
#endif /* IBM mainframes */

/* If we're compiling on Windows CE, enable Unicode <-> ASCII string
   conversion */

#ifdef UNICODE_CHARS
  int asciiToUnicode( wchar_t *dest, const char *src, const int length );
  int unicodeToAscii( char *dest, const wchar_t *src, const int length );
#endif /* Windows CE */

/* Since cryptlib uses ASCII internally, we have to force the use of
   ASCII-compatible versions of system library functions if the system
   uses EBCDIC */

#ifdef EBCDIC_CHARS
  #define ASCII_ALPHA		0x01
  #define ASCII_LOWER		0x02
  #define ASCII_NUMERIC		0x04
  #define ASCII_SPACE		0x08
  #define ASCII_UPPER		0x10
  #define ASCII_HEX			0x20
  extern const BYTE asciiCtypeTbl[];

  #define isAlnum( ch ) \
		  ( asciiCtypeTbl[ ch ] & ( ASCII_ALPHA | ASCII_NUMERIC ) )
  #define isAlpha( ch ) \
		  ( asciiCtypeTbl[ ch ] & ASCII_ALPHA )
  #define isDigit( ch ) \
		  ( asciiCtypeTbl[ ch ] & ASCII_NUMERIC )
  #define isPrint( ch ) \
		  ( ( ch ) >= 0x20 && ( ch ) <= 0x7E )
  #define isXDigit( ch ) \
		  ( asciiCtypeTbl[ ch ] & ASCII_HEX )
  #define toLower( ch ) \
		  ( ( asciiCtypeTbl[ ch ] & ASCII_UPPER ) ? ( ch ) + 32 : ( ch ) )
  #define toUpper( ch ) \
		  ( ( asciiCtypeTbl[ ch ] & ASCII_LOWER ) ? ( ch ) - 32 : ( ch ) )
  int strCompareZ( const char *src, const char *dest );
  int strCompare( const char *src, const char *dest, int length );
  int sPrintf_s( char *buffer, const int bufSize, const char *format, ... );
  int aToI( const char *str );
#else
  #include <ctype.h>

  #define isAlnum( ch )		isalnum( ch )
  #define isAlpha( ch )		isalpha( ch )
  #define isDigit( ch )		isdigit( ch )
  #define isPrint( ch )		isprint( ch )
  #define isXDigit( ch )	isxdigit( ch )
  #define toLower( ch )		tolower( ch )
  #define toUpper( ch )		toupper( ch )
  #define strCompareZ( str1, str2 )	\
							stricmp( str1, str2 )
  #define strCompare( str1, str2, len )	\
							strnicmp( str1, str2, len )
  #define sPrintf_s			sprintf_s
  #define aToI				atoi
#endif /* EBCDIC_CHARS */

/* SunOS and older Slowaris have broken sprintf() handling.  In SunOS 4.x
   this was documented as returning a pointer to the output data as per the
   Berkeley original.  Under Slowaris the manpage was changed so that it
   looks like any other sprintf(), but it still returns the pointer to the
   output buffer in some versions so we use a wrapper that checks at
   runtime to see what we've got and adjusts its behaviour accordingly */

#if defined( sun ) && ( OSVERSION <= 5 )
  int fixedSprintf( char *buffer, const int bufSize,
					const char *format, ... );

  #undef sPrintf_s
  #define sPrintf_s			fixedSprintf
#endif /* Old SunOS */

/* Borland C++ before 5.50 doesn't have snprintf() */

#if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 )
  int bcSnprintf( char *buffer, const int bufSize,
				  const char *format, ... );
#endif /* BC++ before 5.50 */

/****************************************************************************
*																			*
*						TR 24731 Safe stdlib Extensions						*
*																			*
****************************************************************************/

/* ISO/IEC TR 24731 defines alternative stdlib functions designed to perform
   additional parameter checking and avoid some types of common buffer
   overflows.  We use these if possible, if they're not available we map
   them down to the traditional stdlib equivalents, via the preprocessor if
   possible or using wrapper functions if not */

#ifdef __STDC_LIB_EXT1__
  #if defined( _MSC_VER ) && VC_GE_2005( _MSC_VER )
	/* The VC++ implementation of TR 24731 is based on preliminary versions 
	   of the design for the spec, and in some cases needs re-mapping onto 
	   the final versions.  Instances of this are:
   
		TR 24731: struct tm *gmtime_s( const time_t *timer, struct tm *result );
		VC++: errno_t gmtime_s( struct tm *result, const time_t timer );

	   Because this could potentially result in a circular definition, we 
	   have to kludge in an intermediate layer by renaming the call to 
	   gmTime_s(), which we then re-map to the VC++ gmtime_s() */
	#define gmTime_s( timer, result )	\
			( ( gmtime_s( result, timer ) == 0 ) ? result : NULL )
  #else
	#define gmTime_s						gmtime_s
  #endif /* VC++ 2005 */
#else
  /* String functions */
  #define strcpy_s( s1, s1max, s2 )		strcpy( s1, s2 )

  /* Widechar functions */
  int mbstowcs_s( size_t *retval, wchar_t *dst, size_t dstmax, \
				  const char *src, size_t len );
  int wcstombs_s( size_t *retval, char *dst, size_t dstmax, \
				  const wchar_t *src, size_t len );

  /* printf() */
  #define vsprintf_s					vsnprintf
  #if defined( _MSC_VER ) && VC_LT_2005( _MSC_VER )
	#define sprintf_s					_snprintf
  #elif defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 )
	#define sprintf_s					bcSnprintf
  #else
	#define sprintf_s					snprintf
  #endif /* VC++ 6 or below */

  /* Misc.functions */
  #define gmTime_s( timer, result )		gmtime( timer )
#endif /* TR 24731 safe stdlib extensions */

#endif /* _OSSPEC_DEFINED */
