/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* Various compilers handle includes in subdirectories differently.  Most
   will work with paths from a root directory.  Macintoshes don't recognise
   '/'s as path delimiters, but work around it by scanning all subdirectories
   and treating the files as if they were in the same directory (INC_ALL).
   Microsoft C, in a braindamaged exception to all other compilers, treats
   the subdirectory as the root (INC_CHILD).  The Tandem NSK (Guardian) 
   doesn't have subdirectories, and the C compiler zaps '.'s, truncates 
   filenames to 7 characters, and appends a 'h' to the name (so that 
   asn1misc.h becomes asn1mish).  This unfortunately requires a bit of 
   renaming for header files.  Tandem OSS (Unix services) on the other hand 
   is just like Unix, so we explicitly distinguish between the two.

   There are also a few systems that have somewhat special requirements,
   these get their own OS-specific include defines */

#if defined( SYMANTEC_C ) && !defined( INC_ALL )
  #error You need to predefine INC_ALL in your project file
#elif defined( _MSC_VER ) && !defined( INC_CHILD )
  #error You need to predefine INC_CHILD in your project/make file
#endif /* Checks for various compiler/OS-dependant include paths */

/* If we're on a new enough version of VC++ or Metrowerks, set a flag to
   only include header files once */

#if ( defined( _MSC_VER ) && ( _MSC_VER >= 1000 ) ) || defined ( __MWERKS__ )
  #pragma once
#endif /* VC++ 5.0 or higher, Metrowerks */

/* If we're building under Win32, don't haul in the huge amount of cruft
   that windows.h brings with it.  We need to define these values before
   we include cryptlib.h since this is where windows.h is included */

#if ( defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 ) || \
	  defined( __WIN32__ ) ) && !defined( _SCCTK )
  #define NOATOM			/* Atom Manager routines */
  #define NOMCX				/* Modem Configuration Extensions */
/*#define NOCLIPBOARD		// Clipboard routines, needed for randomness polling */
  #define NOCOLOR			/* Screen colors */
  #define NOCOMM			/* COMM driver routines */
  #define NOCTLMGR			/* Control and Dialog routines */
  #define NODEFERWINDOWPOS	/* DeferWindowPos routines */
  #define NODRAWTEXT		/* DrawText() and DT_* */
  #define NOGDI				/* All GDI defines and routines */
  #define NOGDICAPMASKS		/* CC_*, LC_*, PC_*, CP_*, TC_*, RC_ */
  #define NOHELP			/* Help engine interface */
  #define NOICONS			/* IDI_* */
  #define NOKANJI			/* Kanji support stuff */
  #define NOKEYSTATES		/* MK_* */
  #define NOMB				/* MB_* and MessageBox() */
  #define NOMCX				/* Modem Configuration Extensions */
  #define NOMEMMGR			/* GMEM_*, LMEM_*, GHND, LHND, etc */
  #define NOMENUS			/* MF_* */
  #define NOMETAFILE		/* typedef METAFILEPICT */
  #define NOMSG				/* typedef MSG and associated routines */
  #define NONLS				/* NLS routines, needed for cert charset handling */
  #define NOPROFILER		/* Profiler interface */
  #define NORASTEROPS		/* Binary and Tertiary raster ops */
  #define NOSCROLL			/* SB_* and scrolling routines */
  #define NOSERVICE			/* All Service Controller routines, SERVICE_* */
  #define NOSHOWWINDOW		/* SW_* */
  #define NOSOUND			/* Sound driver routines */
  #define NOSYSCOMMANDS		/* SC_* */
  #define NOSYSMETRICS		/* SM_* */
  #define NOTEXTMETRIC		/* typedef TEXTMETRIC and associated routines */
  #define NOVIRTUALKEYCODES	/* VK_* */
  #define NOWH				/* SetWindowsHook and WH_* */
  #define NOWINMESSAGES		/* WM_*, EM_*, LB_*, CB_* */
  #define NOWINOFFSETS		/* GWL_*, GCL_*, associated routines */
  #define NOWINSTYLES		/* WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_* */
  #define OEMRESOURCE		/* OEM Resource values */
#endif /* Win32 */

/* If the global cryptlib header hasn't been included yet, include it now */

#ifndef _CRYPTLIB_DEFINED
  #include "cryptlib.h"
#endif /* _CRYPTLIB_DEFINED */

/****************************************************************************
*																			*
*								OS-Specific Defines							*
*																			*
****************************************************************************/

/* To build the static .LIB under Win32, uncomment the following define (this
   it not recommended since the init/shutdown is no longer thread-safe).  In
   theory it should be possible to detect the build of a DLL vs a LIB with
   the _DLL define which is set when the /MD (multithreaded DLL) option is
   used, however fscking VC++ only defines _DLL when /MD is used *and* it's
   linked with the MT DLL runtime.  If it's linked with the statically
   linked runtime, _DLL isn't defined, which would result in the unsafe
   LIB version being built as a DLL */

/* #define STATIC_LIB */

/* Try and figure out if we're running under Windows and/or Win32.  We have
   to jump through all sorts of hoops later on, not helped by the fact that
   the method of detecting Windows at compile time changes with different
   versions of Visual C (it's different for each of VC 2.0, 2.1, 4.0, and
   4.1.  It actually remains the same after 4.1) */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* !__WINDOWS__ && ( _Windows || _WINDOWS ) */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
	#define __WINDOWS__
  #endif /* __WINDOWS__ */
  #define __WIN32__
#endif /* !__WIN32__ && ( WIN32 || _WIN32 ) */
#if defined( __WINDOWS__ ) && !defined( __WIN32__ )
  #define __WIN16__
#endif /* __WINDOWS__ && !__WIN32__ */

/* In some cases we're using a DOS or Windows system as a cross-development
   platform, if we are we add extra defines to turn off some Windows-
   specific features */

#ifdef _SCCTK
  #define __IBM4758__
#endif /* IBM 4758 cross-compiled under Windows */

/* If we're compiling under VC++ with the maximum level of warning, turn off
   some of the more irritating warnings */

#if defined( _MSC_VER )
  #pragma warning( disable: 4018 )	/* Comparing signed <-> unsigned value */
  #pragma warning( disable: 4127 )	/* Conditional is constant: while( TRUE ) */
#endif /* Visual C++ */

/* If we're using a DOS compiler and it's not a 32-bit one, record this.
   __MSDOS__ is predefined by a number of compilers, so we use __MSDOS16__
   for stuff that is 16-bit DOS specific, and __MSDOS32__ for stuff that
   is 32-bit DOS specific */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* 16-bit DOS */

/* Make the Tandem NSK and Macintosh defines look a bit more like the usual
   ANSI defines used to identify the other OS types */

#ifdef __TANDEM
  #define __TANDEMNSK__
#endif /* Tandem NSK */

#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define __MAC__
#endif /* Macintosh */

/* If we're compiling on the AS/400, make enums a fixed size rather than
   using the variable-length values that IBM compilers default to, and force
   strings into a readonly segment (by default they're writeable) */

#if defined( __OS400__ ) || defined( __ILEC400__ )
  #define __AS400__
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

/* Some encryption algorithms that rely on longints having 32 bits won't
   work on 64- or 128-bit machines due to problems with sign extension and
   whatnot.  The following define can be used to enable special handling for
   processors with a > 32 bit word size */

#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define _BIG_WORDS
#endif /* 64-bit system */

/* Useful data types */

typedef unsigned char		BYTE;
#ifdef __WIN32__
  #define BOOLEAN			int
#else
  typedef int				BOOLEAN;
#endif /* __WIN32__ */

/* If we're using DOS or Windows as a cross-development platform, we need
   the OS-specific value defined initially to get the types right but don't
   want it defined later on since the target platform won't really be
   running DOS or Windows, so we undefine it after the types have been sorted
   out */

#ifdef __IBM4758__
  #undef __MSDOS__
  #undef __WINDOWS__
  #undef __WIN32__
#endif /* IBM 4758 */

/* If we're building the Win32 kernel driver version, include the DDK
   headers */

#if defined( __WIN32__ ) && defined( NT_DRIVER )
  #include <ntddk.h>
#endif /* NT kernel driver */

/* In 16-bit environments the BSS data is large enough that it overflows the
   (64K) BSS segment.  Because of this we move as much of it as possible into
   its own segment with the following define */

#if defined( __WIN16__ )
  #define FAR_BSS	far
#else
  #define FAR_BSS
#endif /* 16-bit systems */

/* Some systems (typically 16-bit or embedded ones) have rather limited 
   amounts of memory available, if we're building on one of these we limit 
   the size of some of the buffers that we use */

#if defined( __MSDOS16__ ) || defined( __TANDEMNSK__ ) || \
	defined( __uClinux__ )
  #define CONFIG_CONSERVE_MEMORY
#endif /* MSDOS || Win16 || Tandem NSK */

/* On systems that support dynamic loading, we bind various drivers and
   libraries at runtime rather than at compile time.  Under Windows this is
   fairly easy but under Unix it's only supported selectively and may be
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
	#if !defined( __APPLE__ )
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

/* If the endianness is not defined and the compiler can tell us what
   endianness we've got, use this in preference to all other methods.  This
   is only really necessary on non-Unix systems since the makefile runtime
   test will tell us the endianness under Unix */

#if defined( CONFIG_LITTLE_ENDIAN ) || defined( CONFIG_BIG_ENDIAN )
  /* If we're cross-compiling for another system, the endianness auto-
	 detection will have been overridden.  In this case we force it to be
	 what the user has specified rather than what we've auto-detected */
  #undef DATA_LITTLEENDIAN
  #undef DATA_BIGENDIAN
  #ifdef CONFIG_LITTLE_ENDIAN
	#define DATA_LITTLEENDIAN
  #else
	#define DATA_BIGENDIAN
  #endif /* CONFIG_LITTLE_ENDIAN */
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
  #elif defined( AMIGA ) || defined( __MWERKS__ ) || defined( SYMANTEC_C ) || \
		defined( THINK_C ) || defined( applec ) || defined( __MRC__ )
	#define DATA_BIGENDIAN		/* Motorola architecture always big-endian */
  #elif defined( VMS ) || defined( __VMS )
	#define DATA_LITTLEENDIAN	/* VAX architecture always little-endian */
  #elif defined( __TANDEMNSK__ )
	#define DATA_BIGENDIAN		/* Tandem NSK architecture always big-endian */
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
	#error Cannot determine processor endianness - edit crypt.h and recompile
  #endif /* Endianness test */
#endif /* !( DATA_LITTLEENDIAN || DATA_BIGENDIAN ) */

/* Sanity check to catch both values being defined */

#if defined( DATA_LITTLEENDIAN ) && defined( DATA_BIGENDIAN )
  #error Both DATA_LITTLEENDIAN and DATA_BIGENDIAN are defined
#endif /* DATA_LITTLEENDIAN && DATA_BIGENDIAN */

/* When performing file I/O we need to know how large path names can get in
   order to perform range checking and allocate buffers.  This gets a bit
   tricky since not all systems have PATH_MAX, so we first try for PATH_MAX,
   if that fails we try _POSIX_PATH_MAX (which is a generic 255 bytes and if
   defined always seems to be less than whatever the real PATH_MAX should be),
   if that also fails we grab stdio.h and try and get FILENAME_MAX, with an
   extra check for PATH_MAX in case it's defined in stdio.h instead of
   limits.h where it should be.  FILENAME_MAX isn't really correct since it's
   the maximum length of a filename rather than a path, but some environments
   treat it as if it were PATH_MAX and in any case it's the best we can do in
   the absence of anything better */

#if defined( PATH_MAX )
  #define MAX_PATH_LENGTH		PATH_MAX
#elif defined( _POSIX_PATH_MAX )
  #define MAX_PATH_LENGTH		_POSIX_PATH_MAX
#else
  #ifndef FILENAME_MAX
	#include <stdio.h>
  #endif /* FILENAME_MAX */
  #ifdef PATH_MAX
	#define MAX_PATH_LENGTH		PATH_MAX
  #else
	#define MAX_PATH_LENGTH		FILENAME_MAX
  #endif /* PATH_MAX or FILENAME_MAX */
#endif /* PATH_MAX */
#ifdef __UNIX__
  /* SunOS 4.1.x doesn't define FILENAME_MAX in limits.h, however it does
	 define a POSIX path length limit so we use that instead.  There are a
	 number of places in various headers in which a max.path length is
	 defined either as 255 or 1024, but we use the POSIX limit since this is
	 the only thing defined in limits.h */
  #if defined( sun ) && ( OSVERSION == 4 ) && !defined( FILENAME_MAX )
	#define FILENAME_MAX  _POSIX_PATH_MAX
  #endif /* SunOS 4.1.x FILENAME_MAX define */
#endif /* __UNIX__ */

/* SunOS 4 doesn't have memmove(), but Solaris does, so we define memmove() 
   to bcopy() under 4.  In addition SunOS doesn't define the fseek position 
   indicators so we define these as well */

#if defined( __UNIX__ ) && defined( sun ) && ( OSVERSION == 4 )
  #define memmove	bcopy

  #define SEEK_SET	0
  #define SEEK_CUR	1
  #define SEEK_END	2
#endif /* SunOS 4 */

/* If we're compiling on IBM mainframes, enable EBCDIC <-> ASCII string
   conversion.  Since cryptlib uses ASCII internally for all strings, we
   need to check to make sure it's been built with ASCII strings enabled
   before we go any further */

#ifdef EBCDIC_CHARS
  #if 'A' != 0x41
	#error cryptlib must be compiled with ASCII literals
  #endif /* Check for use of ASCII */

  int asciiToEbcdic( char *string, int stringLen );
  int ebcdicToAscii( char *string, int stringLen );
  char *bufferToEbcdic( char *buffer, const char *string );
  char *bufferToAscii( char *buffer, const char *string );
#endif /* IBM mainframes */

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
  int sPrintf( char *buffer, const char *format, ... );
  int aToI( const char *str );
#else
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
  #define sPrintf			sprintf
  #define aToI				atoi
#endif /* EBCDIC_CHARS */

/* cryptlib contains a few static functions where are prototyped with block
   scope inside a preceding function:

		{
		static int foo( int bar );

		foo( 1 );
		}

	static int foo( int bar )
		{
		[...]
		}

   There are also one or two locations that do the same thing for static
   data.  Compiler opinions on this vary.  Some compile it as is, some don't
   allow the 'static', some allow both variants, and some produce warnings
   with both but allow them anyway (there are probably more variants with
   further compilers).  To get around this, we use the following define and
   then vary it for broken compilers (the following is the minimum required
   to get it to compile, other broken compilers will still produce
   warnings) */

#if ( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x600 ) ) || \
	defined( __VMCMS__ ) || defined( __MVS__ ) || defined( __MRC__ ) || \
	( defined( __UNIX__ ) && defined( _MPRAS ) )
  #define STATIC_FN
  #define STATIC_DATA
#else
  #define STATIC_FN		static
  #define STATIC_DATA	static
#endif /* Fn.prototyping workarounds for borken compilers */

/* Unlike the equivalent crypto code, the MD5, RIPEMD-160, and SHA-1 hashing
   code needs special defines set to enable the use of asm alternatives.
   Since this works by triggering redefines of function names in the source
   code, we can only do this under Windows because for other systems you'd
   need to conditionally alter the makefile as well.  Since these two defines
   were left accidentally unset for about five years and were only noticed
   when someone benchmarked the code against BSAFE, it's unlikely that this
   is of any real concern */

#ifdef __WIN32__
  #define MD5_ASM
  #define SHA1_ASM
  #define RMD160_ASM
#endif /* Win32 */

/* Enable use of the AES ASM code where possible */

#ifdef __WIN32__
  #define AES_ASM
#endif /* Win32 */

/* Enable use of zlib ASM longest-match code where possible.  Actually
   neither of the two asm files that come with zlib work, the older
   gvmat32.asm uses a custom match that requires wmask = 0x7FFF and
   match.asm from the zlib web site (assemble with "ml /Zp /coff /c
   match.asm") causes segfaults, so we can't use either */

#if defined( __WIN32__ ) && 0
  #define ASMV
#endif /* Win32 */

/* Pull in the cryptlib initialisation options file, which contains the
   various USE_xxx defines that enable different cryptlib features */

#include "cryptini.h"

/****************************************************************************
*																			*
*								OS-Specific Macros							*
*																			*
****************************************************************************/

/* cryptlib provides support for a number of extended OS-specific services
   such as multithreading, resource locking, bounds checking, and so on.
   The macros for the OS-specific services and resource management are
   defined in their own include file */

#include "cryptos.h"

/* The cryptlib kernel has its own interface, defined in the kernel include
   file */

#include "cryptkrn.h"

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* Read/write values as 16- and 32-bit big-endian data, required for some
   non-ASN.1 data formats */

#define mgetWord( memPtr ) \
		( ( ( unsigned int ) memPtr[ 0 ] << 8 ) | \
			( unsigned int ) memPtr[ 1 ] ); \
		memPtr += 2

#define mputWord( memPtr, data ) \
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 2

#define mgetLong( memPtr ) \
		( ( ( unsigned long ) memPtr[ 0 ] << 24 ) | \
		  ( ( unsigned long ) memPtr[ 1 ] << 16 ) | \
		  ( ( unsigned long ) memPtr[ 2 ] << 8 ) | \
		    ( unsigned long ) memPtr[ 3 ] ); \
		memPtr += 4

#define mputLong( memPtr, data ) \
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4

/* The EOL convention used when outputting text */

#if defined( __MSDOS16__ ) || defined( __MSDOS32__ ) || \
	defined( __OS2__ ) || defined( __SYMBIAN32__ ) || \
	defined( __WINDOWS__ )
  #define EOL		"\r\n"
  #define EOL_LEN	2
#elif ( defined( __APPLE__ ) && !defined( __MAC__ ) ) || \
	  defined( __BEOS__ ) || defined( __IBM4758__ ) || \
	  defined( __TANDEMNSK__ ) || defined( __TANDEMOSS__ ) || \
	  defined( __UNIX__ ) || defined( __VMCMS__ )
  #define EOL		"\n"
  #define EOL_LEN	1
#elif defined( __MAC__ )
  #define EOL		"\r"
  #define EOL_LEN	1
#else
  #error You need to add the OS-specific define to enable end-of-line handling
#endif /* OS-specific EOL markers */

/* Widechar handling.  Most systems now support this, we only require wchar_t
   (not supported for older DOS compilers and some (now-rare) Unixen) */

#ifdef USE_WIDECHARS
  #ifndef __APPLE__
	#include <wchar.h>
  #endif /* Mac OS X */
  #define WCSIZE	( sizeof( wchar_t ) )

  #if defined( __MSDOS16__ ) && !defined( __BORLANDC__ )
	typedef unsigned short int wchar_t;	/* Widechar data type */
  #endif /* OSes that don't support widechars */
  #if defined( __BORLANDC__ ) && ( __BORLANDC__ == 0x410 )
	#define wchar_t unsigned short int;	/* BC++ 3.1 has an 8-bit wchar_t */
  #endif /* BC++ 3.1 */
#endif /* USE_WIDECHARS */

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* The maximum length that can be safely handled using an integer.  We don't
   quite allow the maximum possible length since most data/message formats
   impose some extra overhead themselves */

#if INT_MAX < 0x10000L
  #define MAX_INTLENGTH_DELTA	8192
#else
  #define MAX_INTLENGTH_DELTA	1048576
#endif /* 16- vs. 32-bit systems */
#define MAX_INTLENGTH			( INT_MAX - MAX_INTLENGTH_DELTA )

/* The size of a cryptlib key ID, an SHA-1 hash of the SubjectPublicKeyInfo,
   and the PGP key ID */

#define KEYID_SIZE				20
#define	PGP_KEYID_SIZE			8

/* The maximum private key data size.  This is used when buffering the last
   read private key from a keyset in case the password used to decrypt it is
   incorrect, and is equal to the overall size of the total number of
   possible PKC parameters in an encryption context, plus a little extra for
   encoding and encryption */

#define MAX_PRIVATE_KEYSIZE		( ( CRYPT_MAX_PKCSIZE * 8 ) + 256 )

/* The minimum and maximum conventional key size in bits.  In order to avoid
   problems with space inside shorter RSA-encrypted blocks, we limit the
   total keysize to 256 bits, which is adequate for all purposes - the
   limiting factor is three-key triple DES, which requires 3 * 64 bits of key
   and absolutely must have that many bits or it just reduces to two-key
   triple-DES.  Unfortunately when loading a default-length key into a
   context we can't tell what the user is going to do with the generated key
   (for example whether they will export it using a very short public key) so
   we have to take the approach of using a practical length that will work
   even with a 512-bit public key.  This means that for Blowfish, RC2, RC4,
   and RC5 the keylength is shorter than strictly necessary (actually for RC2
   we have to limit the keysize to 128 bits for CMS/SMIME compatibility) */

#define MIN_KEYSIZE_BITS		40
#define MAX_KEYSIZE_BITS		256

/* The minimum and maximum public-key size in bits.  This is used to save
   having to do lots of bit -> byte conversion when checking the lengths of
   PKC values that have the length specified in bits.  The minimum size is
   a bit less than the actual size because keygen specifics can lead to keys
   that are slightly shorter than the nominal size */

#define MIN_PKCSIZE_BITS		( 512 - 8 )
#define MAX_PKCSIZE_BITS		bytesToBits( CRYPT_MAX_PKCSIZE )

/* The size of the largest public-key wrapped value, corresponding to an
   ASN.1-encoded Elgamal-encrypted key */

#define MAX_PKCENCRYPTED_SIZE	( 16 + ( CRYPT_MAX_PKCSIZE * 2 ) )

/* The maximum public-key object size.  This is used to allocate temporary
   buffers when working with signatures and PKC-encrypted keys.  The size
   estimate is somewhat crude and involves a fair safety margin, it usually
   contains a single PKC object (signature or encrypted key) along with
   algorithm and key ID information */

#define MAX_PKC_OBJECTSIZE		( CRYPT_MAX_PKCSIZE * 2 )

/* The minimum size of an encoded signature or exported key object.  This is
   used by the pointer-check macros (for the OS's that support this) to
   check that the pointers to objects that are passed to functions point to
   the minimal amount of valid memory required for an object, and also to
   zero the buffer for the object to ensure the caller gets invalid data if
   the function fails */

#define MIN_CRYPT_OBJECTSIZE	64

/* The minimum size of a certificate.  This is used by the pointer-check
   macros (for the OS's that support this) to check that the pointers being
   passed to these functions point to the minimal amount of valid memory
   required for an object */

#define MIN_CERTSIZE			256

/* The maximum size of an object attribute.  In theory this can be any size,
   but in practice we limit it to the following maximum to stop people
   creating things like certs containing MPEGs of themselves playing with
   their cat */

#define MAX_ATTRIBUTE_SIZE		1024

/* Some objects contain internal buffers used to process data whose size can
   be specified by the user, the following is the minimum size allowed for
   these buffers */

#define MIN_BUFFER_SIZE			8192

/* The minimum allowed length for object names (keysets, devices, users,
   etc).  In theory this could be a single character, but by default we
   make it 2 chars to make things more resistant to off-by-one errors in
   lengths, particularly since it applies to external objects outside
   cryptlib's control */

#define MIN_NAME_LENGTH			2

/* Some object types interact with exteral services that can return detailed
   error messages when problems occur, the following is the maximum length
   error string that we store.  Anything beyond this size is truncated */

#define MAX_ERRMSG_SIZE			512

/* The maximum number of iterations we allow for an iterated key setup such
   as a hashed password.  This is used to prevent DOS attacks from data
   containing excessive iteration counts */

#define MAX_KEYSETUP_ITERATIONS	20000

/* The minimum and maximum size of various Internet-related values, used for
   range checking */

#define MIN_DNS_SIZE			4			/* x.com */
#define MAX_DNS_SIZE			255			/* Max hostname size */
#define MIN_RFC822_SIZE			8			/* xx@yy.zz */
#define MAX_RFC822_SIZE			255
#define MIN_URL_SIZE			12			/* http://x.com */
#define MAX_URL_SIZE			MAX_DNS_SIZE

/* The HMAC input and output padding values.  These are defined here rather
   than in cryptctx.h because they're needed by some routines that perform
   HMAC operations using raw SHA-1 contexts, since some devices provide SHA-1
   but not HMAC-SHA1 so we have to build it ourselves where it's needed for
   things like key hashing */

#define HMAC_IPAD				0x36
#define HMAC_OPAD				0x5C

/* Generic error return code/invalid value code */

#define CRYPT_ERROR				-1

/* A special return code to inform asynchronous routines to abort the
   operation currently in progress */

#define ASYNC_ABORT				-1234

/* A special return code to indicate that everything went OK but there's
   some special action to perform.  This is generally used when a lower-level
   routine wants to return a CRYPT_OK with some condition attached, typically
   that the calling routine not update state information since it's already
   been done by the returning routine or because the returning routine has
   more work to do on a later call */

#define OK_SPECIAL				-4321

/* When parameters get passed in messages, their mapping to parameters passed
   to the calling function gets lost.  The following error codes are used to
   denote errors in message parameters that are mapped to function parameter
   error codes by the caller.  For a message call:

	krnlSendMessage( object, {args}, MESSAGE_TYPE, value );

   we have the following possible error codes */

#define CRYPT_ARGERROR_OBJECT	-1000		/* Error in object being sent msg.*/
#define CRYPT_ARGERROR_VALUE	-1001		/* Error in message value */
#define CRYPT_ARGERROR_STR1		-1002		/* Error in first string arg */
#define CRYPT_ARGERROR_STR2		-1003		/* Error in second string arg */
#define CRYPT_ARGERROR_NUM1		-1004		/* Error in first numeric arg */
#define CRYPT_ARGERROR_NUM2		-1005		/* Error in second numeric arg */

#define cryptArgError( status )	\
		( ( status ) >= CRYPT_ARGERROR_NUM2 && ( status ) <= CRYPT_ARGERROR_OBJECT )

/* The data formats for reading/writing public keys */

typedef enum {
	KEYFORMAT_NONE,		/* No key format */
	KEYFORMAT_CERT,		/* X.509 SubjectPublicKeyInfo */
/*	KEYFORMAT_PUBLIC,	// PKCS #15 public key - currently unused */
	KEYFORMAT_SSH1,		/* SSHv1 public key */
	KEYFORMAT_SSH2,		/* SSHv2 public key */
	KEYFORMAT_PGP,		/* PGP public key */
	KEYFORMAT_PRIVATE,	/* Private key */
	KEYFORMAT_PRIVATE_OLD,	/* Older format for backwards-compatibility */
	KEYFORMAT_LAST = 6	/* Last possible key format type */
	} KEYFORMAT_TYPE;

/* When importing certs for internal use we occasionally need to be able to
   handle things that aren't normal certs.  Alongside the CRYPT_CERTTYPE_xxx
   values to specify the data format, we can use the following values to tell
   the cert import code to handle special-case data formats.
   CERTFORMAT_DATAONLY is a special value that doesn't specifically contain
   a data format hint but indicates that the certificate should be
   instantiated without creating a corresponding context to contain the
   associated public key.  This value is used by certs contained in cert
   chains, where only the leaf cert actually needs to have a context
   instantiated.  CERTFORMAT_CTL is the same as CERTFORMAT_DATAONLY but
   covers cert chains, specifically CTLs which are used as containers for
   trusted certs but never as true cert chains */

typedef enum {
	CERTFORMAT_DATAONLY = 100,		/* Data-only cert */
	CERTFORMAT_CTL,					/* Data-only cert chain */
	CERTFORMAT_REVINFO,				/* Revocation info/single CRL entry */
	CERTFORMAT_LAST					/* Last cert format type */
	} CERTFORMAT_TYPE;

/* The different types of actions that can be signalled to the management
   function for each object class.  This instructs the management function
   to initialise or shut down any object-class-specific information that it
   may maintain */

typedef enum {
	MANAGEMENT_ACTION_NONE,				/* No management action */
	MANAGEMENT_ACTION_PRE_INIT,			/* Pre-initialisation */
	MANAGEMENT_ACTION_INIT,				/* Initialisation */
	MANAGEMENT_ACTION_PRE_SHUTDOWN,		/* Pre-shutdown */
	MANAGEMENT_ACTION_SHUTDOWN,			/* Shutdown */
	MANAGEMENT_ACTION_LAST				/* Last possible management action */
	} MANAGEMENT_ACTION_TYPE;

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on a exported key/signature data.  This is an extended version
   of the data returned by the externally-visible cryptQueryObject() routine */

typedef struct {
	/* Object format and status information */
	CRYPT_FORMAT_TYPE formatType;	/* Object format type */
	CRYPT_OBJECT_TYPE type;			/* Object type */
	long size;						/* Object size */
	int version;					/* Object format version */

	/* The encryption algorithm and mode */
	CRYPT_ALGO_TYPE cryptAlgo;		/* The encryption algorithm */
	CRYPT_MODE_TYPE cryptMode;		/* The encryption mode */

	/* The key ID for public key objects */
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];	/* PKC key ID */
	int keyIDlength;

	/* The IV for conventionally encrypted data */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* IV */
	int ivLength;

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO_TYPE keySetupAlgo;	/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Key setup salt */
	int saltLength;

	/* The hash algorithm for signatures */
	CRYPT_ALGO_TYPE hashAlgo;		/* Hash algorithm */

	/* The start and length of the payload data */
	void *dataStart;				/* Start of payload data */
	int dataLength;

	/* The start and length of the issuerAndSerialNumber and attributes for
	   CMS objects */
	void *iAndSStart;				/* Start of issuerAndSerialNumber */
	int iAndSLength;
	void *attributeStart;			/* Start of attributes */
	int attributeLength;
	void *unauthAttributeStart;		/* Start of unauthenticated attributes */
	int unauthAttributeLength;
	} QUERY_INFO;

/* DLP algorithms require composite parameters when en/decrypting and
   signing/sig checking, so we cant just pass in a single buffer full of
   data as we can with RSA.  In addition the data length changes, for
   example for a DSA sig we pass in a 20-byte hash and get back a ~50-byte
   sig, for sig.checking we pass in a 20-byte hash and ~50-byte sig and get
   back nothing.  Because of this we have to use the following structure to
   pass data to the DLP-based PKCs */

typedef struct {
	const BYTE *inParam1, *inParam2;	/* Input parameters */
	BYTE *outParam;						/* Output parameter */
	int inLen1, inLen2, outLen;			/* Parameter lengths */
	CRYPT_FORMAT_TYPE formatType;		/* Paramter format type */
	} DLP_PARAMS;

#define setDLPParams( dlpDataPtr, dataIn, dataInLen, dataOut, dataOutLen ) \
	{ \
	memset( ( dlpDataPtr ), 0, sizeof( DLP_PARAMS ) ); \
	( dlpDataPtr )->formatType = CRYPT_FORMAT_CRYPTLIB; \
	( dlpDataPtr )->inParam1 = ( dataIn ); \
	( dlpDataPtr )->inLen1 = ( dataInLen ); \
	( dlpDataPtr )->outParam = ( dataOut ); \
	( dlpDataPtr )->outLen = ( dataOutLen ); \
	}

/* When calling key agreement functions we have to pass a mass of cruft
   around instead of the usual flat data (even more than the generic DLP
   parameter information) for which we use the following structure.  The
   public value is the public key value used for the agreement process,
   typically y = g^x mod p for DH-like mechanisms.  The ukm is the user
   keying material, typically something which is mixed into the DH process
   to make the new key unique.  The wrapped key is the output (originator)/
   input(recipient) to the keyagreement process.  The session key context
   contains a context into which the derived key is loaded.  Typical
   examples of use are:

	PKCS #3: publicValue = y
	Fortezza: publicValue = y, ukm = Ra, wrappedKey = TEK-wrapped MEK
	S/MIME: publicValue = y, ukm = 512-bit nonce, wrappedKey = g^x mod p */

typedef struct {
	BYTE publicValue[ CRYPT_MAX_PKCSIZE ];
	int publicValueLen;				/* Public key value */
	BYTE ukm[ CRYPT_MAX_PKCSIZE ];
	int ukmLen;						/* User keying material */
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE ];
	int wrappedKeyLen;				/* Wrapped key */
	CRYPT_CONTEXT sessionKeyContext;/* Context for derived key */
	} KEYAGREE_PARAMS;

/****************************************************************************
*																			*
*								Useful General Macros						*
*																			*
****************************************************************************/

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner */

#define UNUSED( arg )	( ( arg ) = ( arg ) )

/* Although min() and max() aren't in the ANSI standard, most stdlib.h's have
   them anyway for historical reasons.  Just in case they're not defined
   there by some pedantic compiler (some versions of Borland C do this), we
   define them here */

#ifndef max
  #define max( a, b )	( ( ( a ) > ( b ) ) ? ( ( int ) ( a ) ) : \
											  ( ( int ) ( b ) ) )
#endif /* !max */
#ifndef min
  #define min( a, b )	( ( ( a ) < ( b ) ) ? ( ( int ) ( a ) ) : \
											  ( ( int ) ( b ) ) )
#endif /* !min */

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes( bits )			( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits( bytes )		( ( bytes ) << 3 )

/* Macro to round a value up to the nearest multiple of a second value,
   second value a power of 2 */

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter 0 all the time, and
   makes it obvious where sensitive data is being erased */

#define zeroise( memory, size )		memset( memory, 0, size )

/* A macro to check that a value is a possibly valid handle.  This doesn't
   check that the handle refers to a valid object, merely that the value is
   in the range for valid handles.  The alternative function isValidHandle()
   in cryptkrn.c does check that the handle (potentially) refers to a valid
   object, being more than just a range check */

#define checkHandleRange( handle ) \
		( ( handle ) > NO_SYSTEM_OBJECTS - 1 && ( handle ) < MAX_OBJECTS )

/* A macro to check whether an encryption mode needs an IV or not */

#define needsIV( mode )	( ( mode ) == CRYPT_MODE_CBC || \
						  ( mode ) == CRYPT_MODE_CFB || \
						  ( mode ) == CRYPT_MODE_OFB )

/* A macro to check whether an algorithm is a pure stream cipher (that is,
   a real stream cipher rather than a block cipher run in a stream mode) */

#define isStreamCipher( algorithm )		( ( algorithm ) == CRYPT_ALGO_RC4 )

/* A macro to check whether an algorithm is regarded as being (relatively)
   insecure or not.  This is used by some of the higher-level internal
   routines that normally use the default algorithm set in the configuration
   database if nothing else is explicitly specified, but that specifically
   check for the weaker algorithms and use something stronger instead if a
   weak algorithm is specified.  This is done both for luser-proofing and to
   avoid possible problems from a trojan patching the configuration
   database */

#define isWeakCryptAlgo( algorithm )	( ( algorithm ) == CRYPT_ALGO_DES || \
										  ( algorithm ) == CRYPT_ALGO_RC4 )

/* Macros to check whether a PKC algorithm is useful for a certain purpose or
   requires special-case handling */

#define isSigAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_DSA || \
	  ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isCryptAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isKeyxAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DH || ( algorithm ) == CRYPT_ALGO_KEA )
#define isDlpAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL || \
	  ( algorithm ) == CRYPT_ALGO_DH || ( algorithm ) == CRYPT_ALGO_KEA )

/* Almost all objects require object-subtype-specific amounts of memory to
   store object information.  In addition some objects such as certificates 
   contain arbitrary numbers of arbitrary-sized bits and pieces, most of 
   which are quite small.  To avoid having to allocate worst-case sized 
   blocks of memory for objects (a problem in embedded environments) or large
   numbers of tiny little blocks of memory for certificate attributes, we use 
   variable-length structures in which the payload is stored after the 
   structure, with a pointer inside the structure pointing into the payload 
   storage.  To make this easier to handle, we use macros to set up and tear 
   down the necessary variables */

#define DECLARE_VARSTRUCT_VARS \
		int storageSize; \
		BYTE storage[ 1 ]

#define initVarStruct( structure, structureType, size ) \
		memset( structure, 0, sizeof( structureType ) ); \
		structure->value = structure->storage; \
		structure->storageSize = size

#define copyVarStruct( destStructure, srcStructure, structureType ) \
		memcpy( destStructure, srcStructure, \
				sizeof( structureType ) + srcStructure->storageSize ); \
		destStructure->value = destStructure->storage;

#define endVarStruct( structure, structureType ) \
		zeroise( structure, sizeof( structureType ) + structure->storageSize )

#define sizeofVarStruct( structure, structureType ) \
		( sizeof( structureType ) + structure->storageSize )

/* Clear/set object error information */

#define clearErrorInfo( objectInfoPtr ) \
	{ \
	( objectInfoPtr )->errorLocus = CRYPT_ATTRIBUTE_NONE; \
	( objectInfoPtr )->errorType = CRYPT_OK; \
	}

#define setErrorInfo( objectInfoPtr, locus, type ) \
	{ \
	( objectInfoPtr )->errorLocus = locus; \
	( objectInfoPtr )->errorType = type; \
	}

/* Insert a new element into singly-linked and doubly-lined lists.  This is
   the sort of thing we'd really need templates for */

#define insertSingleListElement( listHead, insertPoint, newElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			/* It's an empty list, make this the new list */ \
			*( listHead ) = ( newElement ); \
		else \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newElement )->next = *( listHead ); \
				*( listHead ) = ( newElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newElement )->next = ( insertPoint )->next; \
				( insertPoint )->next = ( newElement ); \
				} \
		}

#define insertDoubleListElements( listHead, insertPoint, newStartElement, newEndElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			/* If it's an empty list, make this the new list */ \
			*( listHead ) = ( newStartElement ); \
		else \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newEndElement )->next = *( listHead ); \
				( *( listHead ) )->prev = ( newEndElement ); \
				*( listHead ) = ( newStartElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newEndElement )->next = ( insertPoint )->next; \
				\
				/* Update the links for the next and previous elements */ \
				if( ( insertPoint )->next != NULL ) \
					( insertPoint )->next->prev = ( newEndElement ); \
				( insertPoint )->next = ( newStartElement ); \
				( newStartElement )->prev = ( insertPoint ); \
				} \
		}

#define insertDoubleListElement( listHead, insertPoint, newElement ) \
		insertDoubleListElements( listHead, insertPoint, newElement, newElement )

/****************************************************************************
*																			*
*								Object Class Functions						*
*																			*
****************************************************************************/

/* Some operations apply to object classes rather than individual object
   types.  These have to be handled as globally visible functions rather than
   object messages */

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Internal forms of various external functions.  These work with internal
   resources that are marked as being inaccessible to the corresponding
   external functions, and don't perform all the checking that their
   external equivalents perform, since the parameters have already been
   checked by cryptlib */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const int sigMaxLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_CERTIFICATE iExtraData,
							 const CRYPT_SESSION iTspSession );
int iCryptCheckSignatureEx( const void *signature, const int signatureLength,
							const CRYPT_FORMAT_TYPE formatType,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData );
int iCryptImportKeyEx( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   CRYPT_CONTEXT *iReturnedContext );
int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iAuxContext );

/* Special-case certificate functions.  The indirect-import function works
   somewhat like the import cert messages, but reads certs by sending
   get_next_cert messages to the message source and provides extended control
   over the format of the imported object.  The public-key read function
   converts an X.509 SubjectPublicKeyInfo record into a context.  The first
   parameter for this function is actually a STREAM *, but we can't use this
   here since STREAM * hasn't been defined yet.

   Neither of these are strictly speaking certificate functions, but the
   best place (meaning least inappropriate) place to put them is with the
   cert-management code */

int iCryptImportCertIndirect( CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  const int options );
int iCryptReadSubjectPublicKey( void *streamPtr, CRYPT_CONTEXT *iCryptContext,
								const BOOLEAN deferredLoad );

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics */

int attributeCopy( RESOURCE_DATA *msgData, const void *attribute,
				   const int attributeLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#define checkBadPassword( password ) \
		( checkBadPtrRead( password, 1 ) || ( strlen( password ) < 1 ) )

/* Check whether a given algorithm is available for use.  This is performed
   frequently enough that we have a special function for it rather than
   querying the system object */

BOOLEAN algoAvailable( const CRYPT_ALGO_TYPE cryptAlgo );

/* In exceptional circumstances an attempt to read the time can fail,
   returning either a garbage value (unsigned time_t) or -1 (signed time_t).
   This can be problematic because many crypto protocols and operations use
   the time at some point.  In order to protect against this, we provide a
   safe time-read function that returns either a sane time value or zero,
   and for situations where the absolute time isn't critical an approximate
   current-time function that returns either a sane time value or an
   approximate value hardcoded in at compile time.  Finally, we provide a
   reliable time function used for operations such as signing certs and 
   timestamping that tries to get the time from a hardware time source if 
   one is available.

   The following two values define the minimum time value that's regarded as
   being a valid time (we have to allow dates slightly before the current
   time because of things like backdated cert revocations, as a rule of
   thumb we allow a date up to five years in the past) and an approximation
   of the current time, with the constraint that it's not after the current
   date */

#define MIN_TIME_VALUE			( ( 1998 - 1970 ) * 365 * 86400L )
#define CURRENT_TIME_VALUE		( MIN_TIME_VALUE + ( 86400 * 365 * 4 ) )

#include <time.h>

time_t getTime( void );
time_t getApproxTime( void );
time_t getReliableTime( const CRYPT_HANDLE cryptHandle );

/* Compare two strings in a case-insensitive manner for those systems that
   don't have this function */

#if defined( __UNIX__ ) && !defined( __CYGWIN__ )
  #define strnicmp	strncasecmp
  #define stricmp	strcasecmp
#elif defined( __xxxOS___ )
  int strnicmp( const char *src, const char *dest, const int length );
  int stricmp( const char *src, const char *dest );
#endif /* OS-specific case-insensitive string compares */

/* Hash state information.  We can either call the hash function with
   HASH_ALL to process an entire buffer at a time, or HASH_START/
   HASH_CONTINUE/HASH_END to process it in parts */

typedef enum { HASH_START, HASH_CONTINUE, HASH_END, HASH_ALL } HASH_STATE;

/* The hash functions are used quite a bit so we provide an internal API for
   them to avoid the overhead of having to set up an encryption context
   every time they're needed.  These take a block of input data and hash it,
   leaving the result in the output buffer.  If the hashState parameter is
   HASH_ALL the hashInfo parameter may be NULL, in which case the function
   will use its own memory for the hashInfo */

#ifdef _BIG_WORDS
  typedef BYTE HASHINFO[ 280 ];	/* RIPEMD160: 24 * sizeof( long64 ) + 64 */
#else
  typedef BYTE HASHINFO[ 100 ];	/* RIPEMD160: 24 * sizeof( long ) */
#endif /* _BIG_WORDS */

typedef void ( *HASHFUNCTION )( HASHINFO hashInfo, BYTE *outBuffer, \
								const BYTE *inBuffer, const int length, \
								const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashOutputSize );

/* Sometimes all we want is a quick-reject check (usually performed to
   lighten the load when we need to do a full hash check), the following
   function returns an integer checksum that can be used to weed out
   non-matches */

int checksumData( const void *data, const int dataLength );

/* Dynamic buffer management functions.  When reading variable-length
   attribute data we can usually fit the data in a small, fixed-length
   buffer, but occasionally we have to cope with larger data amounts that
   require a dynamically-allocated buffer.  The following routines manage
   this process, dynamically allocating and freeing a larger buffer if
   required */

#define DYNBUF_SIZE		1024

typedef struct {
	void *data;						/* Pointer to data */
	int length;
	BYTE dataBuffer[ DYNBUF_SIZE ];	/* Data buf.if size <= DYNBUF_SIZE */
	} DYNBUF;

int dynCreate( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
			   const CRYPT_ATTRIBUTE_TYPE attributeType );
void dynDestroy( DYNBUF *dynBuf );

#define dynLength( dynBuf )		( dynBuf ).length
#define dynData( dynBuf )		( dynBuf ).data

/* Export data to a stream without the overhead of going via a dynbuf.  The
   first parameter for this function is actually a STREAM *, but we can't
   use this here since STREAM * hasn't been defined yet */

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType );
int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTTYPE_TYPE certType );

/* In order to make it easier to add lots of arbitrary-sized random data
   values, we make the following functions available to the polling code to
   implement a clustered-write mechanism for small data quantities.  These
   add an integer, long, or (short) string value to a buffer and send it
   through to the system device when the buffer is full.  The caller
   declares a state variable of type RANDOM_STATE, calls initRandomData() to
   initialise it, calls addRandomData() for each consecutive piece of data
   to add to the buffer, and finally calls endRandomData() to flush the data
   through to the system device.  We also provide an addRandomValue() to make
   it easier to add function return values, for which we can't pass an
   address to addRandomData() unless we copy it to a temporary var first.
   Using the intermediate buffer ensures that we don't have to send a
   message to the device for every bit of data added */

typedef BYTE RANDOM_STATE[ 128 ];

#define addRandomValue( statePtr, value ) \
		addRandomLong( statePtr, ( long ) value )

void initRandomData( void *statePtr, void *buffer, const int maxSize );
int addRandomData( void *statePtr, const void *value,
				   const int valueLength );
int addRandomLong( void *statePtr, const long value );
int endRandomData( void *statePtr, const int quality );

/* MIME header-line parsing routines.  The caller declares a state variable
   of type MIME_STATE, calls initMIMEstate() to initialise it, calls
   addMIMEchar() for each consecutive char to add to the line buffer, and
   finally calls endMIMEstate() to retrive the total character count */

typedef BYTE MIME_STATE[ 128 ];

void initMIMEstate( MIME_STATE *mimeState, const int maxSize );
int addMIMEchar( MIME_STATE *mimeState, char *buffer, int ch );
int endMIMEstate( MIME_STATE *mimeState );

/* When allocating many little blocks of memory, especially in resource-
   constrained systems, it's better if we pre-allocate a small memory pool
   ourselves and grab chunks of it as required, falling back to dynamically
   allocating memory later on if we exhaust the pool.  To use a custom 
   memory pool, the caller declares a state varible of type MEMPOOL_STATE,
   calls initMemPool() to initialise the pool, and then calls getMemPool()
   and freeMemPool() to allocate and free memory blocks */

typedef BYTE MEMPOOL_STATE[ 32 ];

void initMemPool( void *statePtr, void *memPool, const int memPoolSize );
void *getMemPool( void *statePtr, const int size );
void freeMemPool( void *statePtr, void *memblock );

/* base64/SMIME-en/decode routines */

CRYPT_CERTFORMAT_TYPE base64checkHeader( const char *data,
										 const int dataLength, int *startPos );
int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType );
int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType );
int base64decodeLen( const char *data, const int dataLength );
int base64decode( void *outBuffer, const char *inBuffer, const int count,
				  const CRYPT_CERTFORMAT_TYPE format );

/* User data en/decode routines */

BOOLEAN isPKIUserValue( const char *encVal, const int encValueLength );
int adjustPKIUserValue( BYTE *value, const int noCodeGroups );
int encodePKIUserValue( char *encVal, const BYTE *value,
						const int noCodeGroups );
int decodePKIUserValue( BYTE *value, const char *encVal,
						const int encValueLength );

/* General-purpose enveloping functions, used by various high-level
   protocols */

int envelopeWrap( const void *inData, const int inDataLength, void *outData,
				  int *outDataLength, const int outDataMaxLength,
				  const CRYPT_FORMAT_TYPE formatType,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_HANDLE iCryptKey );
int envelopeUnwrap( const void *inData, const int inDataLength,
					void *outData, int *outDataLength,
					const int outDataMaxLength,
					const CRYPT_CONTEXT iDecryptKey );
int envelopeSign( const void *inData, const int inDataLength,
				  void *outData, int *outDataLength,
				  const int outDataMaxLength,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_CONTEXT iSigKey,
				  const CRYPT_CERTIFICATE iCmsAttributes );
int envelopeSigCheck( const void *inData, const int inDataLength,
					  void *outData, int *outDataLength,
					  const int outDataMaxLength,
					  const CRYPT_CONTEXT iSigCheckKey,
					  int *sigResult, CRYPT_CERTIFICATE *iSigningCert,
					  CRYPT_CERTIFICATE *iCmsAttributes );

/* Hardware timer read routine used for performance evaluation */

#if defined( __WIN32__ ) && !defined( NDEBUG )

unsigned long getTickCount( unsigned long startTime );

#endif /* __WIN32__ debug build */

/****************************************************************************
*																			*
*								Debugging Functions							*
*																			*
****************************************************************************/

/* When we encounter an internal consistency check failure, we usually want
   to display some sort of message telling the user that something has gone
   catastrophically wrong, however people probably don't want klaxons going
   off when there's a problem in production code so we only enable it in
   debug versions.  The command-line makefiles by default build release
   versions, so in practice the warn-the-user action is only taken under
   Windows unless the user explicitly enables the use of assertions */

#include <assert.h>
#define NOTREACHED	0	/* Force an assertion failure via assert( NOTREACHED ) */

/* The following macro can be used to enable dumping of PDUs to disk.  As a
   safeguard, this only works in the Win32 debug version to prevent it from
   being accidentally enabled in any release version */

#if defined( __WIN32__ ) && !defined( NDEBUG )
  #define DEBUG_DUMP( name, data, length ) \
	{ \
	FILE *filePtr; \
	char fileName[ 1024 ]; \
	\
	GetTempPath( 512, fileName ); \
	strcat( fileName, name ); \
	strcat( fileName, ".der" ); \
	\
	filePtr = fopen( fileName, "wb" ); \
	if( filePtr != NULL ) \
		{ \
		if( length > 0 ) \
			fwrite( data, 1, length, filePtr ); \
		fclose( filePtr ); \
		} \
	}
#else
  #define DEBUG_DUMP( name, data, length )
#endif /* Win32 debug */

/* In order to debug memory usage, we can define CONFIG_DEBUG_MALLOC to dump 
   memory usage diagnostics to stdout (this would usually be done in the
   makefile rather than hardcoding it in here).  Without this, the debug 
   malloc just becomes a standard malloc.  Note that crypt/osconfig.h 
   contains its own debug-malloc() handling for the OpenSSL-derived code 
   enabled via USE_BN_DEBUG_MALLOC in osconfig.h, and zlib also has its own 
   allocation code (which isn't instrumented for diagnostic purposes).
   
   In addition in order to control on-demand allocation of buffers for 
   larger-than-normal data items, we can define CONFIG_NO_DYNALLOC to 
   disable this allocation.  This is useful in memory-constrained 
   environments where we can't afford to grab chunks of memory at random */

#ifdef CONFIG_DEBUG_MALLOC
  #undef clAlloc
  #undef clFree
  #define clAlloc( string, size ) \
		  clAllocFn( __FILE__, ( string ), __LINE__, ( size ) )
  #define clFree( string, memblock ) \
		  clFreeFn( __FILE__, ( string ), __LINE__, ( memblock ) )
  void *clAllocFn( const char *fileName, const char *fnName, 
				   const int lineNo, size_t size );
  void clFreeFn( const char *fileName, const char *fnName, 
				 const int lineNo, void *memblock );
#else
  #define clAlloc( string, size )		malloc( size )
  #define clFree( string, memblock )	free( memblock )
#endif /* !CONFIG_DEBUG_MALLOC */
#ifdef CONFIG_NO_DYNALLOC
  #define clDynAlloc( string, size )	NULL
#else
  #define clDynAlloc( string, size )	clAlloc( string, size )
#endif /* CONFIG_NO_DYNALLOC */
#endif /* _CRYPT_DEFINED */
