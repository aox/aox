/****************************************************************************
*																			*
*						cryptlib System Device Routines						*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "capabil.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "capabil.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "device/capabil.h"
  #include "device/device.h"
#endif /* Compiler-specific includes */

/* Mechanisms supported by the system device.  These are sorted in order of
   frequency of use in order to make lookups a bit faster */

static const FAR_BSS MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) importCMS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PKCS5, ( MECHANISM_FUNCTION ) derivePKCS5 },
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PGP, ( MECHANISM_FUNCTION ) derivePGP },
#endif /* USE_PGP || USE_PGPKEYS */
#ifdef USE_SSL
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_SSL, ( MECHANISM_FUNCTION ) deriveSSL },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_SSL, ( MECHANISM_FUNCTION ) signSSL },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_SSL, ( MECHANISM_FUNCTION ) sigcheckSSL },
#endif /* USE_SSL */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) exportPrivateKey },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) importPrivateKey },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) exportPrivateKeyPKCS8 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) importPrivateKeyPKCS8 },
#ifdef USE_PGPKEYS
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PGP, ( MECHANISM_FUNCTION ) importPrivateKeyPGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGP },
#endif /* USE_PGPKEYS */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Object creation functions supported by the system device.  These are
   sorted in order of frequency of use in order to make lookups a bit
   faster */

int createContext( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue );
int createCertificate( MESSAGE_CREATEOBJECT_INFO *createInfo,
					   const void *auxDataPtr, const int auxValue );
int createEnvelope( MESSAGE_CREATEOBJECT_INFO *createInfo,
					const void *auxDataPtr, const int auxValue );
int createSession( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue );
int createKeyset( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue );
int createDevice( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue );
int createUser( MESSAGE_CREATEOBJECT_INFO *createInfo,
				const void *auxDataPtr, const int auxValue );

static const FAR_BSS CREATEOBJECT_FUNCTION_INFO createObjectFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
	{ OBJECT_TYPE_CERTIFICATE, createCertificate },
#ifdef USE_ENVELOPES
	{ OBJECT_TYPE_ENVELOPE, createEnvelope },
#endif /* USE_ENVELOPES */
#ifdef USE_SESSIONS
	{ OBJECT_TYPE_SESSION, createSession },
#endif /* USE_SESSIONS */
#ifdef USE_KEYSETS
	{ OBJECT_TYPE_KEYSET, createKeyset },
#endif /* USE_KEYSETS */
	{ OBJECT_TYPE_DEVICE, createDevice },
	{ OBJECT_TYPE_USER, createUser },
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Prototypes for functions in random.c */

int initRandomInfo( void **randomInfoPtrPtr );
void endRandomInfo( void **randomInfoPtrPtr );
int addEntropyData( void *randomInfo, const void *buffer, 
					const int length );
int addEntropyQuality( void *randomInfo, const int quality );
int getRandomData( void *randomInfo, void *buffer, const int length );

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Initialise and shut down the system device */

static void initCapabilities( void );		/* Fwd.dec for fn.*/

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	int status;

	UNUSED( name );

	/* Set up the randomness info */
	status = initRandomInfo( &deviceInfo->randomInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the capability information for this device and mark it as
	   active */
	initCapabilities();
	deviceInfo->label = "cryptlib system device";
	deviceInfo->flags = DEVICE_ACTIVE | DEVICE_LOGGEDIN | DEVICE_TIME;
	return( CRYPT_OK );
	}

static void shutdownFunction( DEVICE_INFO *deviceInfo )
	{
	endRandomInfo( &deviceInfo->randomInfo );
	}

/* Get random data */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length )
	{
	assert( isWritePtr( buffer, length ) );

	/* Clear the return value and make sure that we fail the FIPS 140 tests
	   on the output if there's a problem */
	zeroise( buffer, length );

	return( getRandomData( deviceInfo->randomInfo, buffer, length ) );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data, const int dataLength )
	{
	assert( type == CRYPT_IATTRIBUTE_ENTROPY || \
			type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			type == CRYPT_IATTRIBUTE_RANDOM_NONCE || \
			type == CRYPT_IATTRIBUTE_SELFTEST || \
			type == CRYPT_IATTRIBUTE_TIME );

	/* Handle entropy addition */
	if( type == CRYPT_IATTRIBUTE_ENTROPY )
		return( addEntropyData( deviceInfo->randomInfo, data, dataLength ) );
	if( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY )
		return( addEntropyQuality( deviceInfo->randomInfo, dataLength ) );

	/* Handle nonces */
	if( type == CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		SYSTEMDEV_INFO *systemInfo = deviceInfo->deviceSystem;
		BYTE *noncePtr = ( BYTE * ) data;
		int nonceLength = dataLength;

		/* Get a random (but not necessarily cryptographically strong random) 
		   nonce.  Some nonces can simply be fresh (for which a monotonically 
		   increasing sequence will do), some should be random (for which a 
		   hash of the sequence is adequate), and some need to be 
		   unpredictable.  In order to avoid problems arising from the
		   inadvertent use of a nonce with the wrong properties, we use 
		   unpredictable nonces in all cases, even where it isn't strictly 
		   necessary.
   
		   This simple generator divides the nonce state into a public 
		   section of the same size as the hash output and a private section 
		   that contains 64 bits of data from the crypto RNG, which 
		   influences the public section.  The public and private sections 
		   are repeatedly hashed to produce the required amount of output.  
		   Note that this leaks a small amount of information about the 
		   crypto RNG output since an attacker knows that 
		   public_state_n = hash( public_state_n - 1, private_state ), but 
		   this isn't a major weakness.

		   If the nonce generator hasn't been initialised yet, we set up the 
		   hashing and get 64 bits of private nonce state.  What to do if 
		   the attempt to initialise the state fails is somewhat debatable.  
		   Since nonces are only ever used in protocols alongside crypto 
		   keys, and an RNG failure will be detected when the key is 
		   generated, we can generally ignore a failure at this point.
		   However, nonces are sometimes also used in non-crypto contexts 
		   (for example to generate cert serial numbers) where this 
		   detection in the RNG won't happen.  On the other hand we 
		   shouldn't really abort processing just because we can't get some 
		   no-value nonce data, so what we do is retry the fetch of nonce 
		   data (in case the system object was busy and the first attempt 
		   timed out), and if that fails too fall back to the system time.  
		   This is no longer unpredictable, but the only location where 
		   unpredictability matters is when used in combination with crypto 
		   operations, for which the absence of random data will be detected 
		   during key generation */
		if( !systemInfo->nonceDataInitialised )
			{
			RESOURCE_DATA msgData;
			int status;

			getHashParameters( CRYPT_ALGO_SHA, &systemInfo->hashFunction, 
							   &systemInfo->hashSize );
			setMessageData( &msgData, systemInfo->nonceData + \
									  systemInfo->hashSize, 8 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_RANDOM );
			if( cryptStatusError( status ) )
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
										  IMESSAGE_GETATTRIBUTE_S, &msgData, 
										  CRYPT_IATTRIBUTE_RANDOM );
			if( cryptStatusError( status ) )
				{
				const time_t theTime = getTime();

				memcpy( systemInfo->nonceData + systemInfo->hashSize, 
						&theTime, sizeof( time_t ) );
				}
			systemInfo->nonceDataInitialised = TRUE;
			}

		/* Shuffle the public state and copy it to the output buffer until 
		   it's full */
		while( nonceLength > 0 )
			{
			const int bytesToCopy = min( nonceLength, systemInfo->hashSize );

			/* Hash the state and copy the appropriate amount of data to the 
			   output buffer */
			systemInfo->hashFunction( NULL, systemInfo->nonceData, 
									  systemInfo->nonceData, 
									  systemInfo->hashSize + 8, HASH_ALL );
			memcpy( noncePtr, systemInfo->nonceData, bytesToCopy );

			/* Move on to the next block of the output buffer */
			noncePtr += bytesToCopy;
			nonceLength -= bytesToCopy;
			}

		return( CRYPT_OK );
		}

	/* Handle algorithm self-test.  This tests either the algorithm indicated 
	   by the caller, or all algorithms if CRYPT_USE_DEFAULT is given */
	if( type == CRYPT_IATTRIBUTE_SELFTEST )
		{
		const CAPABILITY_INFO_LIST *capabilityInfoListPtr = \
									deviceInfo->capabilityInfoList;
		BOOLEAN algoTested = FALSE;

		while( capabilityInfoListPtr != NULL )
			{
			const CAPABILITY_INFO *capabilityInfoPtr = capabilityInfoListPtr->info;
			const CRYPT_ALGO_TYPE cryptAlgo = capabilityInfoPtr->cryptAlgo;

			assert( capabilityInfoPtr->selfTestFunction != NULL );

			/* Perform the self-test for this algorithm type and skip to the
			   next algorithm */
			if( dataLength == CRYPT_USE_DEFAULT || \
				capabilityInfoPtr->cryptAlgo == dataLength )
				{
				const int status = capabilityInfoPtr->selfTestFunction();
				if( cryptStatusError( status ) )
					return( status );
				algoTested = TRUE;
				}
			while( capabilityInfoListPtr != NULL && \
				   capabilityInfoListPtr->info->cryptAlgo == cryptAlgo )
				capabilityInfoListPtr = capabilityInfoListPtr->next;
			}

		return( algoTested ? CRYPT_OK : CRYPT_ERROR_NOTFOUND );
		}

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		time_t *timePtr = ( time_t * ) data;

		*timePtr = getTime();
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							Device Capability Routines						*
*																			*
****************************************************************************/

/* The cryptlib intrinsic capability list */

#define MAX_NO_CAPABILITIES		32

static const GETCAPABILITY_FUNCTION getCapabilityTable[] = {
	get3DESCapability, 
#ifdef USE_AES
	getAESCapability, 
#endif /* USE_AES */
#ifdef USE_BLOWFISH
	getBlowfishCapability,
#endif /* USE_BLOWFISH */
#ifdef USE_CAST
	getCASTCapability,
#endif /* USE_CAST */
	getDESCapability,
#ifdef USE_IDEA
	getIDEACapability,
#endif /* USE_IDEA */
#ifdef USE_RC2
	getRC2Capability,
#endif /* USE_RC2 */
#ifdef USE_RC4
	getRC4Capability,
#endif /* USE_RC4 */
#ifdef USE_RC5
	getRC5Capability,
#endif /* USE_RC5 */
#ifdef USE_SKIPJACK
	getSkipjackCapability,
#endif /* USE_SKIPJACK */

#ifdef USE_MD2
	getMD2Capability,
#endif /* USE_MD2 */
#ifdef USE_MD4
	getMD4Capability,
#endif /* USE_MD4 */
	getMD5Capability,
#ifdef USE_RIPEMD160
	getRipemd160Capability,
#endif /* USE_RIPEMD160 */
	getSHA1Capability,
#ifdef USE_SHA2
	getSHA2Capability,
#endif /* USE_SHA2 */

#ifdef USE_HMAC_MD5
	getHmacMD5Capability,
#endif /* USE_HMAC_MD5 */
#ifdef USE_HMAC_RIPEMD160
	getHmacRipemd160Capability,
#endif /* USE_HMAC_RIPEMD160 */
	getHmacSHA1Capability,

	getDHCapability,
	getDSACapability,
#ifdef USE_ELGAMAL
	getElgamalCapability,
#endif /* USE_ELGAMAL */
	getRSACapability,

	/* Vendors may want to use their own algorithms, which aren't part of the
	   general cryptlib suite.  The following provides the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* End-of-list marker */
	NULL
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ MAX_NO_CAPABILITIES ];

/* Initialise the capability info */

static void initCapabilities( void )
	{
	int i;

	/* Perform a consistency check on the encryption mode values, which
	   are used to index a table of per-mode function pointers */
	assert( CRYPT_MODE_CBC == CRYPT_MODE_ECB + 1 && \
			CRYPT_MODE_CFB == CRYPT_MODE_CBC + 1 && \
			CRYPT_MODE_OFB == CRYPT_MODE_CFB + 1 && \
			CRYPT_MODE_LAST == CRYPT_MODE_OFB + 1 );

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, 
			sizeof( CAPABILITY_INFO_LIST ) * MAX_NO_CAPABILITIES );
	for( i = 0; getCapabilityTable[ i ] != NULL; i++ )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = getCapabilityTable[ i ]();

		assert( capabilityInfoOK( capabilityInfoPtr, FALSE ) );
		capabilityInfoList[ i ].info = capabilityInfoPtr;
		capabilityInfoList[ i ].next = NULL;
		if( i > 0 )
			capabilityInfoList[ i - 1 ].next = &capabilityInfoList[ i ];
		}
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceSystem( DEVICE_INFO *deviceInfo )
	{
	deviceInfo->initFunction = initFunction;
	deviceInfo->shutdownFunction = shutdownFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->capabilityInfoList = capabilityInfoList;
	deviceInfo->createObjectFunctions = createObjectFunctions;
	deviceInfo->mechanismFunctions = mechanismFunctions;

	return( CRYPT_OK );
	}
