/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-2004					*
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
  #define NONLS				/* NLS routines */
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

/* The Palm OS SDK compiler tries to make enums as small as possible (8-bit
   unsigned chars if it can, otherwise 16-bit unsigned shorts, otherwise
   ints) for backwards-compatibility with the old 68K-based Palm interface,
   which causes severe problems for code that assumes that enum == int
   (this occurs in a number of places where an integer parameter is used to
   pass a generic value to/from a function).  CodeWarrior allows this enum
   behaviour to be turned off, but pacc doesn't.

   Similarly, the MSDOS-derived (!!) Watcom C compiler used with older
   versions of QNX 4.x uses 16-bit enums (DOS 16-bit ints) if possible, and
   again there's no way to disable this behaviour (there is with newer
   versions, the pragma to fix the problem is used further down).

   To fix this, we take advantage of the fact that every typedef'd enum has
   a _LAST member as the last entry and override it to include an additional
   value that forces the enum range into the 32-bit int range */

#if ( defined( __PALMSOURCE__ ) && defined( _PACC_VER ) ) || \
	( defined( __QNX__ ) && ( OSVERSION <= 4 ) )
  #define NEED_ENUMFIX			/* Remember to undo defines later */

  /* cryptlib.h */
  #define CRYPT_ALGO_LAST		CRYPT_ALGO_LAST, CRYPT_ALGO_ENUM = -50000
  #define CRYPT_MODE_LAST		CRYPT_MODE_LAST, CRYPT_MODE_ENUM = -50000
  #define CRYPT_KEYSET_LAST		CRYPT_KEYSET_LAST, CRYPT_KEYSET_ENUM = -50000
  #define CRYPT_DEVICE_LAST		CRYPT_DEVICE_LAST, CRYPT_DEVICE_ENUM = -50000
  #define CRYPT_CERTTYPE_LAST	CRYPT_CERTTYPE_LAST, CRYPT_CERTTYPE_ENUM = -50000
  #define CRYPT_FORMAT_LAST		CRYPT_FORMAT_LAST, CRYPT_FORMAT_ENUM = -50000
  #define CRYPT_SESSION_LAST	CRYPT_SESSION_LAST, CRYPT_SESSION_ENUM = -50000
  #define CRYPT_USER_LAST		CRYPT_USER_LAST, CRYPT_USER_ENUM = -50000
  #define CRYPT_IATTRIBUTE_LAST	CRYPT_IATTRIBUTE_LAST, CRYPT_IATTRIBUTE_ENUM = -50000
  #define CRYPT_CRLEXTREASON_LAST	CRYPT_CRLEXTREASON_LAST, CRYPT_CRLEXTREASON_ENUM = -50000
  #define CRYPT_CONTENT_LAST	CRYPT_CONTENT_LAST, CRYPT_CONTENT_ENUM = -50000
  #define CRYPT_SIGNATURELEVEL_LAST	CRYPT_SIGNATURELEVEL_LAST, CRYPT_SIGNATURELEVEL_ENUM = -50000
  #define CRYPT_CERTFORMAT_LAST	CRYPT_CERTFORMAT_LAST
  #define CRYPT_REQUESTTYPE_LAST	CRYPT_REQUESTTYPE_LAST, CRYPT_REQUESTTYPE_ENUM = -50000
  #define CRYPT_KEYID_LAST		CRYPT_KEYID_LAST, CRYPT_KEYID_ENUM = -50000
  #define CRYPT_OBJECT_LAST		CRYPT_OBJECT_LAST, CRYPT_OBJECT_ENUM = -50000
  #define CRYPT_ERRTYPE_LAST	CRYPT_ERRTYPE_LAST, CRYPT_ERRTYPE_ENUM = -50000
  #define CRYPT_CERTACTION_LAST	CRYPT_CERTACTION_LAST, CRYPT_CERTACTION_ENUM = -50000
  #define CRYPT_KEYOPT_LAST		CRYPT_KEYOPT_LAST, CRYPT_KEYOPT_ENUM = -50000
  /* crypt.h */
  #define KEYFORMAT_LAST		KEYFORMAT_LAST, KEYFORMAT_ENUM = -50000
  #define CERTFORMAT_LAST		CERTFORMAT_LAST, CERTFORMAT_ENUM = -50000
  #define MANAGEMENT_ACTION_LAST	MANAGEMENT_ACTION_LAST, MANAGEMENT_ACTION_ENUM = -50000
  #define HASH_LAST				HASH_LAST, HASH_ENUM = -50000
  #define ATTR_LAST				ATTR_LAST, ATTR_ENUM = -50000
  /* cryptkrn.h */
  #define MESSAGE_COMPARE_LAST	MESSAGE_COMPARE_LAST, MESSAGE_COMPARE_ENUM = -50000
  #define MESSAGE_CHECK_LAST	MESSAGE_CHECK_LAST, MESSAGE_CHECK_ENUM = -50000
  #define MESSAGE_CHANGENOTIFY_LAST	MESSAGE_CHANGENOTIFY_LAST, MESSAGE_CHANGENOTIFY_ENUM = -50000
  #define MECHANISM_LAST		MECHANISM_LAST, MECHANISM_ENUM = -50000
  #define KEYMGMT_ITEM_LAST		KEYMGMT_ITEM_LAST, KEYMGMT_ITEM_ENUM = -50000
  #define SEMAPHORE_LAST		SEMAPHORE_LAST, SEMAPHORE_ENUM = -50000
  #define MUTEX_LAST			MUTEX_LAST, MUTEX_ENUM = -50000
  /* cert/cert.h */
  #define RTCSRESPONSE_TYPE_LAST	RTCSRESPONSE_TYPE_LAST, RTCSRESPONSE_TYPE_ENUM = -50000
  #define ATTRIBUTE_LAST		ATTRIBUTE_LAST, ATTRIBUTE_ENUM = -50000
  #define POLICY_LAST			POLICY_LAST, POLICY_ENUM = -50000
  #define SELECTION_OPTION_LAST	SELECTION_OPTION_LAST, SELECTION_OPTION_ENUM = -50000
  /* context/context.h */
  #define CONTEXT_LAST			CONTEXT_LAST, CONTEXT_ENUM = -50000
  /* device/capabil.h */
  #define CAPABILITY_INFO_LAST	CAPABILITY_INFO_LAST, CAPABILITY_INFO_ENUM = -50000
  /* envelope/envelope.h */
  #define ACTION_LAST			ACTION_LAST, ACTION_ENUM = -50000
  #define ACTION_RESULT_LAST	ACTION_RESULT_LAST, ACTION_RESULT_ENUM = -50000
  #define STATE_LAST			STATE_LAST, STATE_ENUM = -50000
  #define ENVSTATE_LAST			ENVSTATE_LAST, ENVSTATE_ENUM = -50000
  #define DEENVSTATE_LAST		DEENVSTATE_LAST, DEENVSTATE_ENUM = -50000
  #define PGP_DEENVSTATE_LAST	PGP_DEENVSTATE_LAST, PGP_DEENVSTATE_ENUM = -50000
  #define SEGHDRSTATE_LAST		SEGHDRSTATE_LAST, SEGHDRSTATE_ENUM = -50000
  /* envelope/pgp.h */
  #define PGP_ALGOCLASS_LAST	PGP_ALGOCLASS_LAST, PGP_ALGOCLASS_ENUM = -50000
  /* kernel/acl.h */
  #define RANGEVAL_LAST			RANGEVAL_LAST, RANGEVAL_ENUM = -50000
  #define ATTRIBUTE_VALUE_LAST	ATTRIBUTE_VALUE_LAST, ATTRIBUTE_VALUE_ENUM = -50000
  #define PARAM_VALUE_LAST		PARAM_VALUE_LAST, PARAM_VALUE_ENUM = -50000
  /* kernel/kernel.h */
  #define SEMAPHORE_STATE_LAST	SEMAPHORE_STATE_LAST, SEMAPHORE_STATE_ENUM = -50000
  /* keyset/dbms.h */
  #define CERTADD_LAST			CERTADD_LAST, CERTADD_ENUM = -50000
  /* keyset/keyset.h */
  #define KEYSET_SUBTYPE_LAST	KEYSET_SUBTYPE_LAST, KEYSET_SUBTYPE_ENUM = -50000
  #define DBMS_QUERY_LAST		DBMS_QUERY_LAST, DBMS_QUERY_ENUM = -50000
  #define DBMS_UPDATE_LAST		DBMS_UPDATE_LAST, DBMS_UPDATE_ENUM = -50000
  #define DBMS_CACHEDQUERY_LAST	DBMS_CACHEDQUERY_LAST, DBMS_CACHEDQUERY_ENUM = -50000
  /* keyset/pkcs15.h */
  #define PKCS15_SUBTYPE_LAST	PKCS15_SUBTYPE_LAST, PKCS15_SUBTYPE_ENUM = -50000
//  #define PKCS15_OBJECT_LAST	PKCS15_OBJECT_LAST, PKCS15_OBJECT_ENUM = -50000
  #define PKCS15_KEYID_LAST		PKCS15_KEYID_LAST, PKCS15_KEYID_ENUM = -50000
  /* misc/ber.h */
  #define BER_ID_LAST			BER_ID_LAST, BER_ID_ENUM = -50000
  /* misc/objinfo.h */
  #define KEYEX_LAST			KEYEX_LAST, KEYEX_ENUM = -50000
  #define SIGNATURE_LAST		SIGNATURE_LAST, SIGNATURE_ENUM = -50000
  /* misc/rpc.h */
  #define COMMAND_LAST			COMMAND_LAST, COMMAND_ENUM = -50000
  #define DBX_COMMAND_LAST		DBX_COMMAND_LAST, DBX_COMMAND_ENUM = -50000
  /* misc/stream.h */
  #define STREAM_TYPE_LAST		STREAM_TYPE_LAST, STREAM_TYPE_ENUM = -50000
  #define BUILDPATH_LAST		BUILDPATH_LAST, BUILDPATH_ENUM = -50000
  #define STREAM_IOCTL_LAST		STREAM_IOCTL_LAST, STREAM_IOCTL_ENUM = -50000
  #define STREAM_PROTOCOL_LAST	STREAM_PROTOCOL_LAST, STREAM_PROTOCOL_ENUM = -50000
  #define URL_TYPE_LAST			URL_TYPE_LAST, URL_TYPE_ENUM = -50000
  #define NET_OPTION_LAST		NET_OPTION_LAST, NET_OPTION_ENUM = -50000
  /* session/cmp.h */
  #define CMPBODY_LAST			CMPBODY_LAST, CMPBODY_ENUM = -50000
  /* session/session.h */
  #define READINFO_LAST			READINFO_LAST, READINFO_ENUM = -50000
  /* session/ssh.h */
  #define CHANNEL_LAST			CHANNEL_LAST, CHANNEL_ENUM = -50000
  #define MAC_LAST				MAC_LAST, MAC_ENUM = -50000
  #define SSH_ATRIBUTE_LAST		SSH_ATRIBUTE_LAST, SSH_ATRIBUTE_ENUM = -50000
  /* session/ssl.h */
  #define SSL_LAST				SSL_LAST, SSL_ENUM = -50000
  #define TLS_EXT_LAST			TLS_EXT_LAST, TLS_EXT_ENUM = -50000
#endif /* Palm SDK compiler enum fix */

/* If the global cryptlib header hasn't been included yet, include it now */

#ifndef _CRYPTLIB_DEFINED
  #include "cryptlib.h"
#endif /* _CRYPTLIB_DEFINED */

/* Since some of the _LAST types are used in the code, we have to undefine
   them again if they've been used in the enum-fix kludge */

#ifdef NEED_ENUMFIX
  #undef CRYPT_ALGO_LAST
  #undef CRYPT_MODE_LAST
  #undef CRYPT_KEYSET_LAST
  #undef CRYPT_DEVICE_LAST
  #undef CRYPT_CERTTYPE_LAST
  #undef CRYPT_FORMAT_LAST
  #undef CRYPT_SESSION_LAST
  #undef CRYPT_USER_LAST
  #undef CRYPT_IATTRIBUTE_LAST
  #undef CRYPT_CRLEXTREASON_LAST
  #undef CRYPT_CONTENT_LAST
  #undef CRYPT_SIGNATURELEVEL_LAST
  #undef CRYPT_CERTFORMAT_LAST
  #undef CRYPT_REQUESTTYPE_LAST
  #undef CRYPT_KEYID_LAST
  #undef CRYPT_OBJECT_LAST
  #undef CRYPT_ERRTYPE_LAST
  #undef CRYPT_CERTACTION_LAST
  #undef CRYPT_KEYOPT_LAST
#endif /* NEED_ENUMFIX */

/****************************************************************************
*																			*
*								OS-Specific Defines							*
*																			*
****************************************************************************/

/* To build the static .LIB under Win32, uncomment the following define (this
   it not recommended since the init/shutdown is no longer thread-safe).  In
   theory it should be possible to detect the build of a DLL vs a LIB with
   the _DLL define which is set when the /MD (multithreaded DLL) option is
   used, however VC++ only defines _DLL when /MD is used *and* it's linked
   with the MT DLL runtime.  If it's linked with the statically linked
   runtime, _DLL isn't defined, which would result in the unsafe LIB version
   being built as a DLL */

/* #define STATIC_LIB */

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

/* In some cases we're using a DOS or Windows system as a cross-development
   platform, if we are we add extra defines to turn off some Windows-
   specific features */

#ifdef _SCCTK
  #define __IBM4758__
#endif /* IBM 4758 cross-compiled under Windows */

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

/* If we're compiling under VC++ with the maximum level of warning, turn off
   some of the more irritating warnings */

#if defined( _MSC_VER )
  /* Warning level 3 */
  #pragma warning( disable: 4018 )	/* Comparing signed <-> unsigned value */
  #pragma warning( disable: 4127 )	/* Conditional is constant: while( TRUE ) */

  /* Warning level 4 */
  #pragma warning( disable: 4054 )	/* Cast from fn.ptr -> generic (data) ptr.*/
  #pragma warning( disable: 4055 )	/* Cast from generic (data) ptr. -> fn.ptr.*/
  #pragma warning( disable: 4057 )	/* char vs.unsigned char use */
  #pragma warning( disable: 4204 )	/* Struct initialised with non-const value */
  #pragma warning( disable: 4221 )	/* Struct initialised with addr.of auto.var */
  #pragma warning( disable: 4244 )	/* int <-> unsigned char/short */
  #pragma warning( disable: 4245 )	/* int <-> unsigned long */

  /* gcc -wall type warnings.  The highest warning level generates large
     numbers of spurious warnings (including ones in VC++ headers), so it's
	 best to only enable them for one-off test builds requiring manual
	 checking for real errors.  The used-before-initialised is particularly
	 common during the code generation phase, when the compiler flags all
	 values initialised in conditional code blocks as potential problems */
  #if 1
	#pragma warning( disable: 4100 )	/* Unreferenced parameter */
	#pragma warning( disable: 4131 )	/* K&R prototype (in zlib) */
	#pragma warning( disable: 4201 )	/* Nameless struct/union */
	#pragma warning( disable: 4205 )	/* Static function */
	#pragma warning( disable: 4210 )	/* Static function */
	#pragma warning( disable: 4211 )	/* Static function */
	#pragma warning( disable: 4217 )	/* Static function */
	#pragma warning( disable: 4505 )	/* Unreferenced local function */
	#pragma warning( disable: 4701 )	/* Variable used before initialised */
  #endif /* 1 */
#endif /* Visual C++ */

/* If we're using a DOS compiler and it's not a 32-bit one, record this.
   __MSDOS__ is predefined by a number of compilers, so we use __MSDOS16__
   for stuff that is 16-bit DOS specific, and __MSDOS32__ for stuff that
   is 32-bit DOS specific */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* 16-bit DOS */

/* Make the Tandem, Macintosh, and PalmOS defines look a bit more like the
   usual ANSI defines used to identify the other OS types */

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

#ifdef __PALMSOURCE__
  #define __PALMOS__
#endif /* Palm OS */

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

/* If we're compiling under QNX, make enums a fixed size rather than using
   the variable-length values that the Watcom compiler defaults to */

#if defined( __QNX__ ) && defined( __WATCOMC__ )
  #pragma enum int
#endif /* QNX and Watcom C */

/* PalmOS is a bit more picky than other OSes about what has to be in which
   header, in particular shared data segments can't be easily exported from
   libraries so the isXYZ() macros (which use lookup tables) that are
   generally available elsewhere have to be explicitly enabled via ctype.h,
   and the native strcpy()/memcpy() used by most compilers may not be
   available in some cases either so we have to explicitly pull them in via
   string.h */

#ifdef __PALMOS__
  #include <ctype.h>
  #include <string.h>
#endif /* __PALMOS__ */

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
#if defined( __WIN32__ ) || defined( __WINCE__ )
  #define BOOLEAN			int
#else
  typedef int				BOOLEAN;
#endif /* __WIN32__ || __WINCE__ */

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

#if defined( __MSDOS16__ ) || defined( __uClinux__ )
  #define CONFIG_CONSERVE_MEMORY
#endif /* Memory-starved systems */

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
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	( defined( __UNIX__ ) && defined( _MPRAS ) )
  #define STATIC_FN
  #define STATIC_DATA
#else
  #define STATIC_FN		static
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

#if ( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
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

/* The Tandem mktime() is broken and can't convert dates beyond 2023, so we
   replace it with our own version which can */

#if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
  #define mktime	my_mktime
#endif /* __TANDEM_NSK__ || __TANDEM_OSS__ */

/* Support for vsnprintf() (used for assembling the
   CRYPT_ATTRIBUTE_INT_ERRORMESSAGE value) is a bit hit-and-miss on non-Unix
   systems and also on older Unixen, if it's not available we alias it to
   vsprintf() */

#if defined( __ITRON__ ) || \
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
	  defined( __PALMOS__ ) || defined( __TANDEM_NSK__ ) || \
	  defined( __TANDEM_OSS__ ) || defined( __UNIX__ ) || \
	  defined( __VMCMS__ )
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
  #if !( ( defined( __QNX__ ) && ( OSVERSION <= 4 ) ) || \
		 ( defined( __WINCE__ ) && _WIN32_WCE < 400 ) )
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
	 defines it in wchar.c but then defines it differently in stddef.h, and
	 in any case has no wchar support present */
  #if !( defined( __APPLE__ ) || defined( __OpenBSD__ ) || \
		 defined( __PALMOS__ ) )
	typedef unsigned short int wchar_t;
  #endif /* __APPLE__ */
  #define WCSIZE	( sizeof( wchar_t ) )
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

#ifdef UNICODE_CHARS
  #define MIN_NAME_LENGTH		( 2 * sizeof( wchar_t ) )
#else
  #define MIN_NAME_LENGTH		2
#endif /* Unicode vs. ASCII environments */

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
#define MIN_RFC822_SIZE			7			/* x@yy.zz */
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
	KEYFORMAT_SSL,		/* SSL public key */
	KEYFORMAT_PGP,		/* PGP public key */
	KEYFORMAT_PRIVATE,	/* Private key */
	KEYFORMAT_PRIVATE_OLD,	/* Older format for backwards-compatibility */
	KEYFORMAT_LAST		/* Last possible key format type */
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
   covers cert chains, specifically CTLs that are used as containers for
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
	S/MIME: publicValue = y, ukm = 512-bit nonce, wrappedKey = g^x mod p
	SSH, SSL: publicValue = y, wrappedKey = x */

typedef struct {
	BYTE publicValue[ CRYPT_MAX_PKCSIZE + 8 ];
	int publicValueLen;				/* Public key value */
#ifdef USE_FORTEZZA
	BYTE ukm[ CRYPT_MAX_PKCSIZE + 8 ];
	int ukmLen;						/* User keying material */
	CRYPT_CONTEXT sessionKeyContext;/* Context for derived key */
#endif /* USE_FORTEZZA */
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
	int wrappedKeyLen;				/* Wrapped key */
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

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best that we can do is check that it's not null, but some OSes allow
   for better checking than this, for example that it points to a block of
   readable or writeable memory.  Under Windows IsBadReadPtr() will always
   succeed if the size is 0, so we have to add a separate check to make sure
   that it's non-NULL */

#if defined( __WIN32__ ) || defined( __WINCE__ )
  #define isReadPtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
  #define isWritePtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
#else
  #define isReadPtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 )
  #define isWritePtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 )
#endif /* Pointer check macros */

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

#define deleteSingleListElement( listHead, listPrev, element ) \
		{ \
		if( element == *( listHead ) ) \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
		else \
			/* Delete from middle or end of the list */ \
			listPrev->next = element->next; \
		}

#define deleteDoubleListElement( listHead, element ) \
		{ \
		if( element == *( listHead ) ) \
			{ \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
			if( element->next != NULL ) \
				element->next->prev = NULL; \
			} \
		else \
			{ \
			/* Delete from the middle or the end of the list */ \
			element->prev->next = element->next; \
			if( element->next != NULL ) \
				element->next->prev = element->prev; \
			} \
		}

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

/* Get information on encoded object data.  The first parameter for this
   function is actually a STREAM *, but we can't use this here since
   STREAM * hasn't been defined yet */

int queryAsn1Object( void *streamPtr, QUERY_INFO *queryInfo );
int queryPgpObject( void *streamPtr, QUERY_INFO *queryInfo );

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics */

int attributeCopy( RESOURCE_DATA *msgData, const void *attribute,
				   const int attributeLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#ifdef UNICODE_CHARS
  #define checkBadPassword( password ) \
		  ( !isReadPtr( password, sizeof( wchar_t ) ) || \
		    ( wcslen( password ) < 1 ) )
#else
  #define checkBadPassword( password ) \
		  ( !isReadPtr( password, 1 ) || \
		    ( strlen( password ) < 1 ) )
#endif /* Unicode vs. ASCII environments */

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
   don't have this function (PalmOS has strcasecmp()/strncasecmp(), but
   these aren't i18n-aware) */

#if defined( __UNIX__ ) && !( defined( __CYGWIN__ ) )
  #if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
	#include <strings.h>
  #endif /* Tandem */
  #define strnicmp	strncasecmp
  #define stricmp	strcasecmp
#elif defined( __WINCE__ )
  #define strnicmp	_strnicmp
  #define stricmp	_stricmp
#elif defined __PALMOS__
  #include <StringMgr.h>

  #define strnicmp	StrNCaselessCompare
  #define stricmp	StrCaselessCompare
#elif defined( __xxxOS___ )
  int strnicmp( const char *src, const char *dest, const int length );
  int stricmp( const char *src, const char *dest );
#endif /* OS-specific case-insensitive string compares */

/* Hash state information.  We can either call the hash function with
   HASH_ALL to process an entire buffer at a time, or HASH_START/
   HASH_CONTINUE/HASH_END to process it in parts */

typedef enum {
	HASH_START,					/* Begin hashing */
	HASH_CONTINUE,				/* Continue existing hashing */
	HASH_END,					/* Complete existing hashing */
	HASH_ALL,					/* One-step hash operation */
	HASH_LAST					/* Last valid hash option */
	} HASH_STATE;

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

typedef void ( *HASHFUNCTION )( HASHINFO hashInfo, BYTE *outBuffer,
								const BYTE *inBuffer, const int length,
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

/* Export/import data to/from a stream without the overhead of going via a
   dynbuf.  The first parameter for these function is actually a STREAM *,
   but we can't use this here since STREAM * hasn't been defined yet */

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType,
							 const int attributeLength );
int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTFORMAT_TYPE certFormatType );
int importCertFromStream( void *streamPtr,
						  CRYPT_CERTIFICATE *cryptCertificate,
						  const int length,
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
int base64encode( char *dest, const int destMaxLen, const void *src,
				  const int srcLen, const CRYPT_CERTTYPE_TYPE certType );
int base64decodeLen( const char *data, const int dataLength );
int base64decode( void *dest, const int destMaxLen, const char *src,
				  const int srcLen, const CRYPT_CERTFORMAT_TYPE format );

/* User data en/decode routines */

BOOLEAN isPKIUserValue( const char *encVal, const int encValueLength );
int adjustPKIUserValue( BYTE *value, const int noCodeGroups );
int encodePKIUserValue( char *encVal, const BYTE *value,
						const int noCodeGroups );
int decodePKIUserValue( BYTE *value, const char *encVal,
						const int encValueLength );

/* In order to work with attribute lists of different types, we need a
   means of accessing the type-specific previous and next pointers and the
   attribute ID information.  The following callback function is passed to
   all attribute-list manipulation functions and provides external access
   to the required internal fields */

typedef enum {
	ATTR_NONE,			/* No attribute get type */
	ATTR_CURRENT,		/* Get details for current attribute */
	ATTR_PREV,			/* Get details for previous attribute */
	ATTR_NEXT,			/* Get details for next attribute */
	ATTR_LAST			/* Last valid attribute get type */
	} ATTR_TYPE;

typedef const void * ( *GETATTRFUNCTION )( const void *attributePtr,
										   CRYPT_ATTRIBUTE_TYPE *groupID,
										   CRYPT_ATTRIBUTE_TYPE *attributeID,
										   CRYPT_ATTRIBUTE_TYPE *instanceID,
										   const ATTR_TYPE attrGetType );

void *attributeFindStart( const void *attributePtr,
						  GETATTRFUNCTION getAttrFunction );
void *attributeFindEnd( const void *attributePtr,
						GETATTRFUNCTION getAttrFunction );
void *attributeFind( const void *attributePtr,
					 GETATTRFUNCTION getAttrFunction,
					 const CRYPT_ATTRIBUTE_TYPE attributeID,
					 const CRYPT_ATTRIBUTE_TYPE instanceID );
void *attributeFindNextInstance( const void *attributePtr,
								 GETATTRFUNCTION getAttrFunction );
const void *attributeMoveCursor( const void *currentCursor,
								 GETATTRFUNCTION getAttrFunction,
								 const CRYPT_ATTRIBUTE_TYPE attributeMoveType,
								 const int cursorMoveType );

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

long getTickCount( long startTime );

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

#if defined( __WINCE__ ) && _WIN32_WCE < 400
#if 0
  /* Older WinCE environments don't support assert() because there's no
     console and no other support for it in the runtime (the documentation
	 claims there's at least an _ASSERT available, but this isn't present
	 in many systems such as PocketPC), so we use it if it's available and
	 otherwise kludge it using NKDbgPrintfW() */
  #ifndef _ASSERTE
	#ifdef NDEBUG
	  #define _ASSERTE( x )
	#else
	  #define _ASSERTE( expr )	( void )( ( expr ) || ( NKDbgPrintfW( #expr ) ) )
	#endif /* Debug vs. non-debug builds */
  #endif /* _ASSERTE available */
  #define assert( expr )	_ASSERTE( expr )
#else
  /* Older WinCE environments don't support assert() because there's no
     console and no other support for it in the runtime (the documentation
	 claims there's at least an _ASSERT available, but this isn't present
	 in many systems such as PocketPC), so we build our own assert() from
	 DEBUGMSG().  Note that (in theory) the version check isn't reliable
	 since we should be checking for the development environment version
	 rather than the target OS version, however in practice compiler/SDK
	 version == OS version unless you seriously enjoy pain, and in any case
	 it's not really possible to differentiate between eVC++ 3.0 and 4.0 -
	 the SHx, MIPS, and ARM compilers at least report 120{1|2} for 3.0 and
	 1200 for 3.0, but the x86 compiler reports 1200 for both 3.0 and 4.0
	 even though it's a different build, 0.8168 vs 0.8807 */
  #ifdef NDEBUG
	#define assert( x )
  #else
	#define assert( x )		\
			DEBUGMSG( !( x ), ( TEXT( "Assert failed in %s line %d: %s" ), TEXT( __FILE__ ), __LINE__, TEXT( #x ) ) )
  #endif /* Debug vs. non-debug builds */
#endif /* 0 */
#else
  #include <assert.h>
#endif /* Systems without assert() */
#define NOTREACHED	0	/* Force an assertion failure via assert( NOTREACHED ) */

/* The following macro outputs an I-am-here to stdout, useful when tracing
   errors in code without debug symbols available */

#define DEBUG_INFO()	printf( "%4d %s.\n", __LINE__, __FILE__ );

/* The following macros can be used to enable dumping of PDUs to disk and to
   create a hex dump of the first n bytes of a buffer, along with the length
   and a checksum of the entire buffer.  As a safeguard, these only work in
   the Win32 debug version to prevent them from being accidentally enabled in
   any release version */

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

  #define DEBUG_DUMP_CERT( name, cert ) \
	{ \
	RESOURCE_DATA msgData; \
	FILE *filePtr; \
	char fileName[ 1024 ]; \
	BYTE certData[ 2048 ]; \
	\
	GetTempPath( 512, fileName ); \
	strcat( fileName, name ); \
	strcat( fileName, ".der" ); \
	\
	filePtr = fopen( fileName, "wb" ); \
	if( filePtr != NULL ) \
		{ \
		setMessageData( &msgData, certData, 2048 ); \
		status = krnlSendMessage( cert, IMESSAGE_CRT_EXPORT, &msgData, \
								  CRYPT_CERTFORMAT_CERTIFICATE ); \
		if( cryptStatusOK( status ) ) \
			fwrite( msgData.data, 1, msgData.length, filePtr ); \
		fclose( filePtr ); \
		} \
	}

  #define DEBUG_DUMPHEX( dumpBuf, dumpLen ) \
	{ \
	const int maxLen = min( dumpLen, 19 ); \
	int i; \
	\
	printf( "%4d %04X ", dumpLen, checksumData( dumpBuf, dumpLen ) ); \
	for( i = 0; i < maxLen; i++ ) \
		printf( "%02X ", ( ( BYTE * ) dumpBuf )[ i ] ); \
	for( i = 0; i < maxLen; i++ ) \
		{ \
		const BYTE ch = ( ( BYTE * ) dumpBuf )[ i ]; \
		\
		putchar( isprint( ch ) ? ch : '.' ); \
		} \
	putchar( '\n' ); \
	}
#else
  #define DEBUG_DUMP( name, data, length )
  #define DEBUG_DUMP_CERT( name, data, length )
  #define DEBUG_DUMPHEX( dumpBuf, dumpLen )
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

/* Windows NT/2000/XP support ACL-based access control mechanisms for system
   objects, so when we create objects such as files and threads we give them
   an ACL that allows only the creator access.  The following functions
   return the security info needed when creating objects */

#ifdef __WINDOWS__
  #ifdef __WIN32__
	void *initACLInfo( const int access );
	void *getACLInfo( void *securityInfoPtr );
	void freeACLInfo( void *securityInfoPtr );
  #else
	#define initACLInfo( x )	NULL
	#define getACLInfo( x )		NULL
	#define freeACLInfo( x )
  #endif /* __WIN32__ */
#endif /* __WINDOWS__ */

#endif /* _CRYPT_DEFINED */
