/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* Various compilers handle includes in subdirectories differently.  Most
   will work with paths from a root directory.  Non-OS X Macintoshes don't
   recognise '/'s as path delimiters, but work around it by scanning all
   subdirectories and treating the files as if they were in the same
   directory (INC_ALL).  Microsoft C, in a braindamaged exception to all
   other compilers, treats the subdirectory as the root, unless explicitly
   told to use the project-file directory by setting Project | Settings |
   C/C++ | Preprocessor | Additional include directories to '.\'.  The
   Tandem NSK (Guardian) filesystem doesn't have subdirectories, and the C
   compiler zaps '.'s, truncates filenames to 7 characters, and appends a
   'h' to the name (so that asn1misc.h becomes asn1mish).  This
   unfortunately requires a bit of renaming for header files.  Tandem OSS
   (Unix services) on the other hand is just like Unix, so we explicitly
   distinguish between the two */

#if defined( SYMANTEC_C ) && !defined( INC_ALL )
  #error You need to predefine INC_ALL in your project file
#endif /* Checks for various compiler/OS-dependant include paths */

/* If we're on a new enough version of VC++ or Metrowerks, set a flag to
   only include header files once */

#if ( defined( _MSC_VER ) && ( _MSC_VER >= 1000 ) ) || defined ( __MWERKS__ )
  #pragma once
#endif /* VC++ 5.0 or higher, Metrowerks */

/* Enable use of the TR 24731 safe stdlib extensions if they're available */

#if !defined( __STDC_WANT_LIB_EXT1__ )
  #define __STDC_WANT_LIB_EXT1__	1
#endif /* TR 24731 safe stdlib extensions */

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
  #if defined( _MSC_VER ) && ( _MSC_VER > 800 )
	#define NOMSG			/* typedef MSG and associated routines */
  #endif /* !Win16 */
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
  /* misc/asn1.h */
  #define BER_ID_LAST			BER_ID_LAST, BER_ID_ENUM = -50000
  /* misc/pgp.h */
  #define PGP_ALGOCLASS_LAST	PGP_ALGOCLASS_LAST, PGP_ALGOCLASS_ENUM = -50000
  /* misc/rpc.h */
  #define COMMAND_LAST			COMMAND_LAST, COMMAND_ENUM = -50000
  #define DBX_COMMAND_LAST		DBX_COMMAND_LAST, DBX_COMMAND_ENUM = -50000
  /* io/stream.h */
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

/* Global headers used in almost every module */

#include <stdlib.h>
#include <string.h>

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
*						System- and Compiler-Specific Defines				*
*																			*
****************************************************************************/

/* Pull in the system and compiler-specific defines and values */

#if defined( INC_ALL )
  #include "os_spec.h"
#else
  #include "misc/os_spec.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Config Options								*
*																			*
****************************************************************************/

/* Pull in the cryptlib initialisation options file, which contains the
   various USE_xxx defines that enable different cryptlib features.  Note
   that this *must* be included after os_spec.h, which performs OS detection
   used by config.h to enable/disable various code features */

#if defined( INC_ALL )
  #include "config.h"
#else
  #include "misc/config.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Kernel Interface							*
*																			*
****************************************************************************/

/* Pull in the cryptlib kernel interface defines */

#include "cryptkrn.h"

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* Read/write values as 16- and 32-bit big-endian data, required for a
   variety of non-ASN.1 data formats */

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

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* Pull in the data-size and crypt-related constants */

#if defined( INC_ALL )
  #include "consts.h"
#else
  #include "misc/consts.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on exported key/signature data.  This is an extended version
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
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];/* PKC key ID */
	int keyIDlength;

	/* The IV for conventionally encrypted data */
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];/* IV */
	int ivLength;

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO_TYPE keySetupAlgo;	/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];/* Key setup salt */
	int saltLength;

	/* The hash algorithm for signatures */
	CRYPT_ALGO_TYPE hashAlgo;		/* Hash algorithm */

	/* The start and length of the payload data, either the encrypted key or
	   the signature data */
	int dataStart, dataLength;

	/* The start and length of the issuerAndSerialNumber, authenticated 
	   attributes, and unauthenticated attributes for CMS objects */
	int iAndSStart, iAndSLength;
	int attributeStart, attributeLength;
	int unauthAttributeStart, unauthAttributeLength;
	} QUERY_INFO;

/* DLP algorithms require composite parameters when en/decrypting and
   signing/sig checking, so we can't just pass in a single buffer full of
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

/* Although min() and max() aren't in the ANSI standard, most compilers have
   them in one form or another, but just enough don't that we need to define 
   them ourselves in some cases */

#if !defined( min )
  #ifdef MIN
	#define min			MIN
	#define max			MAX
  #else
	#define min( a, b )	( ( ( a ) < ( b ) ) ? ( a ) : ( b ) )
	#define max( a, b )	( ( ( a ) > ( b ) ) ? ( a ) : ( b ) )
  #endif /* Various min/max macros */
#endif /* !min/max */

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes( bits )			( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits( bytes )		( ( bytes ) << 3 )

/* Macro to round a value up to the nearest multiple of a second value,
   with the second value being a power of 2 */

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter set to 0 all the time,
   and makes it obvious where sensitive data is being erased */

#define zeroise( memory, size )		memset( memory, 0, size )

/* A macro to check that a value is a possibly valid handle.  This doesn't
   check that the handle refers to a valid object, merely that the value is
   in the range for valid handles.  The full function isValidHandle() used
   in the kernel does check that the handle refers to a valid object, being
   more than just a range check */

#define isHandleRangeValid( handle ) \
		( ( handle ) > NO_SYSTEM_OBJECTS - 1 && ( handle ) < MAX_OBJECTS )

/* A macro to check whether an encryption mode needs an IV or not */

#define needsIV( mode )	( ( mode ) == CRYPT_MODE_CBC || \
						  ( mode ) == CRYPT_MODE_CFB || \
						  ( mode ) == CRYPT_MODE_OFB )

/* A macro to check whether an algorithm is a pure stream cipher (that is,
   a real stream cipher rather than just a block cipher run in a stream
   mode) */

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
   that it's non-NULL.

   There are additional caveats with the use of the Windows memory-checking
   functions.  In theory these would be implemented via VirtualQuery(),
   however this is quite slow, requiring a kernel transition and poking
   around with the page protection mechanisms.  Instead, they try and read
   or write the memory, with an exception handler wrapped around the access.
   If the exception is thrown, they fail.  The problem with this way of
   doing things is that if the memory address is a stack guard page used to
   grow the stack (when the system-level exception handler sees an access to
   the bottom-of-stack guard page, it knows that it has to grow the stack),
   IsBadXxxPtr() will catch the exception and the system will never see it,
   so it can't grow the stack past the current limit.  In addition if it's
   the last guard page then instead of getting an "out of stack" exception,
   it's turned into a no-op.  The second time the last guard page is hit,
   the application is terminated by the system, since it's passed its first-
   chance exception.

   A lesser problem is that there's a race condition in the checking, since
   the memory can be unmapped between the IsBadXxxPtr() check and the actual
   access.

   For these reasons we use these functions mostly for debugging, wrapping
   them up in assert()s.  Under Windows Vista, they've actually been turned
   into no-ops because of the above problems, although it's probable that
   they'll be replaced by a code to check for NULL pointers, since
   Microsoft's docs indicate that this much checking will still be done */

#if defined( __WIN32__ ) || defined( __WINCE__ )
  #define isReadPtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
  #define isWritePtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
#else
  #define isReadPtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 )
  #define isWritePtr( ptr, size )	( ( ptr ) != NULL && ( size ) > 0 )
#endif /* Pointer check macros */

/* Handle internal errors.  These follow a fixed pattern of "throw an 
   exception, return an internal-error code" (with a few exceptions for
   functions that return a pointer or void) */

#define retIntError() \
		{ \
		assert( NOTREACHED ); \
		return( CRYPT_ERROR_INTERNAL ); \
		}
#define retIntError_Null() \
		{ \
		assert( NOTREACHED ); \
		return( NULL ); \
		}
#define retIntError_Boolean() \
		{ \
		assert( NOTREACHED ); \
		return( FALSE ); \
		}
#define retIntError_Void() \
		{ \
		assert( NOTREACHED ); \
		return; \
		}
#define retIntError_Ext( value ) \
		{ \
		assert( NOTREACHED ); \
		return( value ); \
		}

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

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Pull in the internal API function definitions and prototypes */

#if defined( INC_ALL )
  #include "int_api.h"
#else
  #include "misc/int_api.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Debugging Functions							*
*																			*
****************************************************************************/

/* When we encounter an internal consistency check failure, we usually want
   to display some sort of message telling the user that something has gone
   catastrophically wrong, however people probably don't want klaxons going
   off when there's a problem in production code so we only enable it in
   debug versions.  The command-line makefile by default builds release
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
	 even though it's a different build, 0.8168 vs. 0.8807 */
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
  #ifdef __STDC_LIB_EXT1__
	#define OPEN_FILE( filePtr, fileName ) \
			if( fopen_s( &filePtr, fileName, "wb" ) != 0 ) \
				filePtr = NULL
  #else
	#define OPEN_FILE( filePtr, fileName ) \
			filePtr = fopen( fileName, "wb" )
  #endif /* __STDC_LIB_EXT1__ */

  #define DEBUG_DUMP( name, data, length ) \
	{ \
	FILE *filePtr; \
	char fileName[ 1024 ]; \
	\
	GetTempPath( 512, fileName ); \
	strcat( fileName, name ); \
	strcat( fileName, ".der" ); \
	\
	OPEN_FILE( filePtr, fileName ); \
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
	OPEN_FILE( filePtr, fileName ); \
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
   makefile).  Without this, the debug malloc just becomes a standard malloc.
   Note that crypt/osconfig.h contains its own debug-malloc() handling for
   the OpenSSL-derived code enabled via USE_BN_DEBUG_MALLOC in osconfig.h,
   and zlib also has its own allocation code (which isn't instrumented for
   diagnostic purposes).

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
