/****************************************************************************
*																			*
*					  cryptlib Encryption Context Header File 				*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifndef _CRYPTCTX_DEFINED

#define _CRYPTCTX_DEFINED

/* Various include files needed by contexts */

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../io/stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */
#ifndef BN_H
  #if defined( INC_ALL )
	#include "bn.h"
  #elif defined( INC_CHILD )
	#include "../bn/bn.h"
  #else
	#include "bn/bn.h"
  #endif /* Compiler-specific includes */
#endif /* BN_H */
#ifndef _CRYPTCAP_DEFINED
  #if defined( INC_ALL )
	#include "capabil.h"
  #elif defined( INC_CHILD )
	#include "../device/capabil.h"
  #else
	#include "device/capabil.h"
  #endif /* Compiler-specific includes */
#endif /* _CRYPTCAP_DEFINED */

/* We need to include the following because the encryption context stores
   validity information for private keys */

#include <time.h>

/* Context information flags.  Most of these flags are context-type-specific,
   and are only used with some context types:

	CONTEXT_KEY_SET: The key has been initialised.

	CONTEXT_IV_SET: The IV has been set.

	CONTEXT_ISPUBLICKEY: The key is a public or private key.
	CONTEXT_ISPRIVATEKEY:

	CONTEXT_DUMMY: The context is a dummy context with actions handled 
			through an external crypto device.  When a device context is
			created, it usually isn't instantiated at the device level until 
			the key (and possibly other parameters) are available because
			most devices use an atomic created-initialised-context operation
			rather than allowing incremental parameter setting like cryptlib
			does.  To handle this, we first create a dummy context and then
			fill in the details on demand.

	CONTEXT_DUMMY_INITED: The dummy context has been initialised.  Since
			the context isn't instantiated until required, this flag is 
			needed to keep track of whether any cached parameters retained 
			from the dummy state need to be set when the context is used.

	CONTEXT_EPHEMERAL: The context is ephemeral rather than a long-term
			context backed by a keyset or crypto device.

	CONTEXT_SIDECHANNELPROTECTION: The context has side-channel protection
			(additional checking for crypto operations, blinding, and so
			on) enabled.

	CONTEXT_HASH_INITED: The hash parameters have been inited.

	CONTEXT_HASH_DONE: The hash operation is complete, no further hashing
			can be done 

	CONTEXT_ASYNC_ABORT: Asynchronous operation state management flags
	CONTEXT_ASYNC_DONE: */

#define CONTEXT_KEY_SET			0x0001	/* Key has been set */
#define CONTEXT_IV_SET			0x0002	/* IV has been set */
#define CONTEXT_ISPUBLICKEY		0x0004	/* Key is a public key */
#define CONTEXT_ISPRIVATEKEY	0x0008	/* Key is a private key */
#define CONTEXT_DUMMY			0x0010	/* Context actions handled externally */
#define CONTEXT_DUMMY_INITED	0x0020	/* Dummy context is inited */
#define CONTEXT_EPHEMERAL		0x0040	/* Context is ephemeral */
#define CONTEXT_SIDECHANNELPROTECTION \
								0x0080	/* Enabled side-channel prot.in ops */
#define CONTEXT_HASH_INITED		0x0100	/* Hash parameters have been inited */
#define CONTEXT_HASH_DONE		0x0200	/* Hash operation is complete */
#define CONTEXT_ASYNC_ABORT		0x0400	/* Whether to abort async op.*/
#define CONTEXT_ASYNC_DONE		0x0800	/* Async operation is complete */

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* The internal fields in a context that hold data for a conventional,
   public-key, hash, or MAC algorithm.  CONTEXT_CONV and CONTEXT_MAC
   should be allocated in pagelocked memory since they contain the sensitive
   userKey data */

typedef enum { 
	CONTEXT_NONE,					/* No context type */
	CONTEXT_CONV,					/* Conventional encryption context */
	CONTEXT_PKC,					/* PKC context */
	CONTEXT_HASH,					/* Hash context */
	CONTEXT_MAC,					/* MAC context */
	CONTEXT_LAST					/* Last valid context type */
	} CONTEXT_TYPE;

#define needsSecureMemory( contextType ) \
		( contextType == CONTEXT_CONV || contextType == CONTEXT_MAC )

typedef struct {
	/* General algorithm information */
	CRYPT_MODE_TYPE mode;			/* Encryption mode being used */

	/* User keying information.  The user key is the unprocessed key as
	   entered by the user (rather than the key in the form used by the
	   algorithm), the IV is the initial IV.  We keep a copy of the
	   unprocessed key because we usually need to wrap it up in a KEK
	   at some point after it's loaded */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];		/* User encryption key */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* Initial IV */
	int userKeyLength, ivLength;

	/* Conventional encryption keying information.  The key is the processed
	   encryption key stored in whatever form is required by the algorithm,
	   usually the key-scheduled user key.  The IV is the current working IV.
	   The ivCount is the number of bytes of IV that have been used, and is
	   used when a block cipher is used as a stream cipher */
	void *key;						/* Internal working key */
	BYTE currentIV[ CRYPT_MAX_IVSIZE ];	/* Internal working IV */
	int ivCount;					/* Internal IV count for chaining modes */

	/* Information required when a key suitable for use by this algorithm
	   is derived from a longer user key */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Salt */
	int saltLength;
	int keySetupIterations;			/* Number of times setup was iterated */
	CRYPT_ALGO_TYPE keySetupAlgorithm; /* Algorithm used for key setup */
	} CONV_INFO;

typedef struct {
	/* General information on the key: The nominal key size in bits, the key
	   IDs, and key-related meta-info.  Since the OpenPGP key ID can't be
	   calculated directly like the other IDs, we have to keep track of
	   whether it's been set or not with a flag */
	int keySizeBits;				/* Nominal key size in bits */
	BYTE keyID[ KEYID_SIZE ];		/* Key ID for this key */
	BYTE pgpKeyID[ PGP_KEYID_SIZE ];/* PGP key ID for this key */
	BYTE openPgpKeyID[ PGP_KEYID_SIZE ];/* OpenPGP key ID for this key */
	BOOLEAN openPgpKeyIDSet;		/* Whether the OpenPGP key ID has been set */
	time_t pgpCreationTime;			/* Key creation time (for OpenPGP ID) */

	/* Public-key encryption keying information.  Since each algorithm has
	   its own unique parameters, the bignums are given generic names here.
	   The algorithm-specific code refers to them by their actual names,
	   which are implemented as symbolic defines of the form
	   <algo>Param_<param_name>, e.g.rsaParam_e */
	BIGNUM param1;
	BIGNUM param2;
	BIGNUM param3;
	BIGNUM param4;
	BIGNUM param5;
	BIGNUM param6;
	BIGNUM param7;
	BIGNUM param8;					/* The PKC key components */
	BN_MONT_CTX montCTX1;
	BN_MONT_CTX montCTX2;
	BN_MONT_CTX montCTX3;			/* Precomputed Montgomery values */

	/* Temporary workspace values used to avoid having to allocate and
	   deallocate them on each PKC operation, and to keep better control
	   over the data in them.  DLP operations that require extensive
	   temporary vars also reuse the last three general-purpose bignums
	   above, since they're not used for keying material */
	BIGNUM tmp1, tmp2, tmp3;
	BN_CTX bnCTX;					/* Temporary workspace */
	#define CONTEXT_PBO	0x08

	/* If we're using side-channel protection, we also need to store values
	   used to perform extra operations that eliminate timing channels */
	BIGNUM blind1, blind2;

	/* If the context is tied to a device the keying info won't be available,
	   however we generally need the public key information for use in cert
	   requests and whatnot so we save a copy as SubjectPublicKeyInfo when
	   the key is loaded/generated */
	void *publicKeyInfo;			/* X.509 SubjectPublicKeyInfo */
	int publicKeyInfoSize;			/* Key info size */

#ifdef USE_KEA
	/* For key agreement keys, we also store domain parameters (which
	   identify the domain of the originator and recipient keys) and the
	   public value used in the key agreement process.  These are just
	   pointers to the encoded data in the publicKeyInfo */
	void *domainParamPtr;			/* Domain parameters within publicKeyInfo */
	int domainParamSize;
	void *publicValuePtr;			/* Public value within publicKeyInfo */
	int publicValueSize;
#endif /* USE_KEA */

	/* Pointers to functions to public-key context access methods.  The
	   functions to read and write public and private keys are kept distinct
	   to enforce red/black separation */
	int ( *readPublicKeyFunction )( STREAM *stream, struct CI *contextInfoPtr,
									const KEYFORMAT_TYPE formatType );
	int ( *readPrivateKeyFunction )( STREAM *stream, struct CI *contextInfoPtr,
									 const KEYFORMAT_TYPE formatType );
	int ( *writePublicKeyFunction )( STREAM *stream,
									 const struct CI *contextInfoPtr,
									 const KEYFORMAT_TYPE formatType,
									 const char *accessKey );
	int ( *writePrivateKeyFunction )( STREAM *stream,
									  const struct CI *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType,
									  const char *accessKey );

	/* State information needed to allow background key generation */
#ifdef USE_THREADS
	THREAD_FUNCTION_PARAMS threadParams;
#endif /* OS's with threads */
	} PKC_INFO;

typedef struct {
	/* The current state of the hashing and the result from the last
	   completed hash operation */
	void *hashInfo;					/* Current hash state */
	BYTE hash[ CRYPT_MAX_HASHSIZE ];/* Last hash result */
	} HASH_INFO;

typedef struct {
	/* User keying information.  The user key is the unprocessed key as
	   entered by the user rather than the key in the form used by the
	   algorithm.  We keep a copy of the unprocessed key because we usually 
	   need to wrap it up in a KEK at some point after it's loaded */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];	/* User MAC key */
	int userKeyLength;

	/* The current state of the MAC'ing and the result from the last
	   completed MAC operation */
	void *macInfo;					/* Current MAC state */
	BYTE mac[ CRYPT_MAX_HASHSIZE ];	/* Last MAC result */

	/* Information required when a key suitable for use by this algorithm
	   is derived from a longer user key */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Salt */
	int saltLength;
	int keySetupIterations;			/* Number of times setup was iterated */
	CRYPT_ALGO_TYPE keySetupAlgorithm; /* Algorithm used for key setup */
	} MAC_INFO;

/* Defines to make access to the union fields less messy */

#define ctxConv		keyingInfo.convInfo
#define ctxPKC		keyingInfo.pkcInfo
#define ctxHash		keyingInfo.hashInfo
#define ctxMAC		keyingInfo.macInfo

/* An encryption context */

typedef struct CI {
	/* Control and status information */
	CONTEXT_TYPE type;				/* The context type */
	const CAPABILITY_INFO *capabilityInfo;	/* Encryption capability info */
	int flags;						/* Context information flags */

	/* Context type-specific information */
	union {
		CONV_INFO *convInfo;
		PKC_INFO *pkcInfo;
		HASH_INFO *hashInfo;
		MAC_INFO *macInfo;
		} keyingInfo;

#ifdef USE_DEVICES
	/* If implemented using a crypto device, the object information is
	   usually stored inside the device.  The following value contains the
	   reference to the crypto object inside the device.  In addition some
	   objects (specifically, DH) that aren't really public- or private-key
	   objects but a mixture of both require a second handle to the other 
	   part of the object in the device */
	long deviceObject, altDeviceObject;
#endif /* USE_DEVICES */

	/* The label for this object, typically used to identify stored keys */
	char label[ CRYPT_MAX_TEXTSIZE ];/* Text string identifying key */
	int labelSize;

#ifdef USE_THREADS
	/* Whether the context is being used for an asynchronous operation such
	   as key generation, and whether to abort the asynchronous operation.
	   If the overall object status (maintained by the kernel) is set to
	   CRYPT_ERROR_TIMEOUT, any attempt to access it will return
	   CRYPT_ERROR_TIMEOUT.  In the flags field the CONTEXT_ASYNC_ABORT flag
	   is used by cryptAsyncAbort() to signal to the async operation that it
	   should finish processing and clean up.  The CONTEXT_ASYNC_DONE flag
	   is used to indicate that the async operation has completed, so that
	   further status change operations have no effect.  The asyncStatus
	   records the result of the operation, which is returned from
	   cryptAsyncQuery() */
	int asyncStatus;				/* Exit status of the async operation */
#endif /* USE_THREADS */

	/* Pointers to context access methods.  These are somewhat higher-level
	   than the capability info methods and apply to entire classes of
	   context rather than at a per-algorithm level */
	int ( *loadKeyFunction )( struct CI *contextInfoPtr, const void *key,
							  const int keyLength );
	int ( *generateKeyFunction )( struct CI *contextInfoPtr,
								  const BOOLEAN isAsync );
	int ( *encryptFunction )( struct CI *contextInfoPtr, BYTE *buffer,
							  int length );
	int ( *decryptFunction )( struct CI *contextInfoPtr, BYTE *buffer,
							  int length );

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;

	/* Variable-length storage for the type-specific data */
	DECLARE_VARSTRUCT_VARS;
	} CONTEXT_INFO;

/* Symbolic defines for the various PKC components for different PKC
   algorithms.  All of the DLP algorithms actually use the same parameters,
   so we define generic DLP names for them */

#define dlpParam_p			param1
#define dlpParam_g			param2
#define dlpParam_q			param3
#define dlpParam_y			param4
#define dlpParam_x			param5
#define dlpTmp1				param6
#define dlpTmp2				param7
#define dlpTmp3				param8		/* More temp.values for DLP PKCs */
#define dhParam_yPrime		param8		/* Special value for DH */
#define dlpParam_mont_p		montCTX1

#define rsaParam_n			param1
#define rsaParam_e			param2
#define rsaParam_d			param3
#define rsaParam_p			param4
#define rsaParam_q			param5
#define rsaParam_u			param6
#define rsaParam_exponent1	param7
#define rsaParam_exponent2	param8
#define rsaParam_blind_k	blind1
#define rsaParam_blind_kInv	blind2
#define rsaParam_mont_n		montCTX1
#define rsaParam_mont_p		montCTX2
#define rsaParam_mont_q		montCTX3

/* Because there's no really clean way to throw an exception in C and the
   bnlib routines don't carry around state information like cryptlib objects
   do, we need to perform an error check for most of the routines we call.
   To make this slightly less ugly we define the following macro that
   performs the check for us by updating a variable called `bnStatus' with
   the result of a bnlib call, which returns 1 for OK and 0 for error.
   Annoyingly, this interface isn't quite consistent and some calls return
   pointers rather than integer values, so we define a second macro that
   checks for pointer values rather than integers */

#define CK( x )				bnStatus &= x
#define CKPTR( x )			bnStatus &= ( ( x ) == NULL ? 0 : 1 )
#define BN_STATUS			1
#define bnStatusOK( x )		bnStatus
#define bnStatusError( x )	( !bnStatus )
#define getBnStatus( x )	( bnStatus ? CRYPT_OK : CRYPT_ERROR_FAILED )

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Determine whether a context needs to have a key loaded */

#define needsKey( contextInfoPtr ) \
		!( ( contextInfoPtr )->flags & CONTEXT_KEY_SET )

/* Low-level capability checking and context-creation functions used when
   creating a context in a device */

int checkCapability( const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr );
int createContextFromCapability( CRYPT_CONTEXT *cryptContext,
						const CRYPT_USER cryptOwner,
						const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr,
						const int objectFlags );

/* Shared functions.  These are used for all native contexts and also by 
   some device types */

int initKeyParams( CONTEXT_INFO *contextInfoPtr, const void *iv,
				   const int ivLength, const CRYPT_MODE_TYPE mode );

/* Key-generation and related routines */

int initDLPkey( CONTEXT_INFO *contextInfoPtr, const BOOLEAN isDH );
int checkDLPkey( const CONTEXT_INFO *contextInfoPtr, const BOOLEAN isPKCS3 );
int generateDLPkey( CONTEXT_INFO *contextInfoPtr, const int keyBits,
					const int qBits, const BOOLEAN generateDomainParameters );
int initCheckRSAkey( CONTEXT_INFO *contextInfoPtr );
int generateRSAkey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
int generateBignum( BIGNUM *bn, const int noBits, const BYTE high,
					const BYTE low );
int calculateKeyID( CONTEXT_INFO *contextInfoPtr );
int encodeDLValues( BYTE *buffer, const int bufSize, BIGNUM *value1,
					BIGNUM *value2, const CRYPT_FORMAT_TYPE formatType );
int decodeDLValues( const BYTE *buffer, const int bufSize, BIGNUM **value1,
					BIGNUM **value2, const CRYPT_FORMAT_TYPE formatType );
int keygenCallback( void *callbackArg );

/* Key read/write routines */

void initKeyRead( CONTEXT_INFO *contextInfoPtr );
void initKeyWrite( CONTEXT_INFO *contextInfoPtr );

#endif /* _CRYPTCTX_DEFINED */
