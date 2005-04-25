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
  #include "libs.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "capabil.h"
  #include "device.h"
  #include "../context/libs.h"
#else
  #include "crypt.h"
  #include "device/capabil.h"
  #include "device/device.h"
  #include "context/libs.h"
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

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	STATIC_FN void initCapabilities( void );
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
		const CAPABILITY_INFO *capabilityInfoPtr = deviceInfo->capabilityInfo;
		BOOLEAN algoTested = FALSE;

		while( capabilityInfoPtr != NULL )
			{
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
			while( capabilityInfoPtr != NULL && \
				   capabilityInfoPtr->cryptAlgo == cryptAlgo )
				capabilityInfoPtr = capabilityInfoPtr->next;
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

static CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The DES capabilities */
	{ CRYPT_ALGO_DES, bits( 64 ), "DES",
		bits( MIN_KEYSIZE_BITS ), bits( 64 ), bits( 64 ),
		desSelfTest, desGetInfo, NULL, initKeyParams, desInitKey, NULL,
		desEncryptECB, desDecryptECB, desEncryptCBC, desDecryptCBC,
		desEncryptCFB, desDecryptCFB, desEncryptOFB, desDecryptOFB },

	/* The triple DES capabilities.  Unlike the other algorithms, the minimum
	   key size here is 64 + 8 bits (nominally 56 + 1 bits) because using a
	   key any shorter is (a) no better than single DES, and (b) will result
	   in a key load error since the second key will be an all-zero weak
	   key.  We also give the default key size as 192 bits instead of 128 to
	   make sure that anyone using a key of the default size ends up with
	   three-key 3DES rather than two-key 3DES */
	{ CRYPT_ALGO_3DES, bits( 64 ), "3DES",
		bits( 64 + 8 ), bits( 192 ), bits( 192 ),
		des3SelfTest, des3GetInfo, NULL, initKeyParams, des3InitKey, NULL,
		des3EncryptECB, des3DecryptECB, des3EncryptCBC, des3DecryptCBC,
		des3EncryptCFB, des3DecryptCFB, des3EncryptOFB, des3DecryptOFB },

#ifdef USE_IDEA
	/* The IDEA capabilities */
	{ CRYPT_ALGO_IDEA, bits( 64 ), "IDEA",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), bits( 128 ),
		ideaSelfTest, ideaGetInfo, NULL, initKeyParams, ideaInitKey, NULL,
		ideaEncryptECB, ideaDecryptECB, ideaEncryptCBC, ideaDecryptCBC,
		ideaEncryptCFB, ideaDecryptCFB, ideaEncryptOFB, ideaDecryptOFB },
#endif /* USE_IDEA */

#ifdef USE_CAST
	/* The CAST-128 capabilities */
	{ CRYPT_ALGO_CAST, bits( 64 ), "CAST-128",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), bits( 128 ),
		castSelfTest, castGetInfo, NULL, initKeyParams, castInitKey, NULL,
		castEncryptECB, castDecryptECB, castEncryptCBC, castDecryptCBC,
		castEncryptCFB, castDecryptCFB, castEncryptOFB, castDecryptOFB },
#endif /* USE_CAST */

#ifdef USE_RC2
	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, bits( 64 ), "RC2",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), bits( 1024 ),
		rc2SelfTest, rc2GetInfo, NULL, initKeyParams, rc2InitKey, NULL,
		rc2EncryptECB, rc2DecryptECB, rc2EncryptCBC, rc2DecryptCBC,
		rc2EncryptCFB, rc2DecryptCFB, rc2EncryptOFB, rc2DecryptOFB },
#endif /* USE_RC2 */

#ifdef USE_RC4
	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, bits( 8 ), "RC4",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), 256,
		rc4SelfTest, rc4GetInfo, NULL, initKeyParams, rc4InitKey, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, rc4Encrypt, rc4Encrypt },
#endif /* USE_RC4 */

#ifdef USE_RC5
	/* The RC5 capabilities */
	{ CRYPT_ALGO_RC5, bits( 64 ), "RC5",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), bits( 832 ),
		rc5SelfTest, rc5GetInfo, NULL, initKeyParams, rc5InitKey, NULL,
		rc5EncryptECB, rc5DecryptECB, rc5EncryptCBC, rc5DecryptCBC,
		rc5EncryptCFB, rc5DecryptCFB, rc5EncryptOFB, rc5DecryptOFB },
#endif /* USE_RC5 */

#ifdef USE_AES
	/* The AES capabilities */
	{ CRYPT_ALGO_AES, bits( 128 ), "AES",
		bits( 128 ), bits( 128 ), bits( 256 ),
		aesSelfTest, aesGetInfo, NULL, initKeyParams, aesInitKey, NULL,
		aesEncryptECB, aesDecryptECB, aesEncryptCBC, aesDecryptCBC,
		aesEncryptCFB, aesDecryptCFB, aesEncryptOFB, aesDecryptOFB },
#endif /* USE_AES */

#ifdef USE_BLOWFISH
	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, bits( 64 ), "Blowfish",
		bits( MIN_KEYSIZE_BITS ), bits( 128 ), bits( 448 ),
		blowfishSelfTest, blowfishGetInfo, NULL, initKeyParams, blowfishInitKey, NULL,
		blowfishEncryptECB, blowfishDecryptECB, blowfishEncryptCBC, blowfishDecryptCBC,
		blowfishEncryptCFB, blowfishDecryptCFB, blowfishEncryptOFB, blowfishDecryptOFB },
#endif /* USE_BLOWFISH */

#ifdef USE_SKIPJACK
	/* The Skipjack capabilities */
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ),
		skipjackSelfTest, skipjackGetInfo, NULL, initKeyParams, skipjackInitKey, NULL,
		skipjackEncryptECB, skipjackDecryptECB, skipjackEncryptCBC, skipjackDecryptCBC,
		skipjackEncryptCFB, skipjackDecryptCFB, skipjackEncryptOFB, skipjackDecryptOFB },
#endif /* USE_SKIPJACK */

#ifdef USE_MD2
	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, bits( 128 ), "MD2",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md2SelfTest, md2GetInfo, NULL, NULL, NULL, NULL, md2Hash, md2Hash },
#endif /* USE_MD2 */

#ifdef USE_MD4
	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, bits( 128 ), "MD4",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md4SelfTest, md4GetInfo, NULL, NULL, NULL, NULL, md4Hash, md4Hash },
#endif /* USE_MD4 */

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md5SelfTest, md5GetInfo, NULL, NULL, NULL, NULL, md5Hash, md5Hash },

	/* The SHA1 capabilities */
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ),
		shaSelfTest, shaGetInfo, NULL, NULL, NULL, NULL, shaHash, shaHash },

#ifdef USE_RIPEMD160
	/* The RIPEMD-160 capabilities */
	{ CRYPT_ALGO_RIPEMD160, bits( 160 ), "RIPEMD-160",
		bits( 0 ), bits( 0 ), bits( 0 ),
		ripemd160SelfTest, ripemd160GetInfo, NULL, NULL, NULL, NULL,
		ripemd160Hash, ripemd160Hash },
#endif /* USE_RIPEMD160 */

#ifdef USE_SHA2
	/* The SHA2 capabilities */
	{ CRYPT_ALGO_SHA2, bits( 256 ), "SHA2",
		bits( 0 ), bits( 0 ), bits( 0 ),
		sha2SelfTest, sha2GetInfo, NULL, NULL, NULL, NULL, sha2Hash, sha2Hash },
#endif /* USE_SHA2 */

#ifdef USE_HMAC_MD5
	/* The HMAC-MD5 capabilities */
	{ CRYPT_ALGO_HMAC_MD5, bits( 128 ), "HMAC-MD5",
		bits( 64 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacMD5SelfTest, hmacMD5GetInfo, NULL, NULL, hmacMD5InitKey,
		NULL, hmacMD5Hash, hmacMD5Hash },
#endif /* USE_HMAC_MD5 */

	/* The HMAC-SHA capabilities */
	{ CRYPT_ALGO_HMAC_SHA, bits( 160 ), "HMAC-SHA",
		bits( 64 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacSHASelfTest, hmacSHAGetInfo, NULL, NULL, hmacSHAInitKey,
		NULL, hmacSHAHash, hmacSHAHash },

#ifdef USE_HMAC_RIPEMD160
	/* The HMAC-RIPEMD160 capabilities */
	{ CRYPT_ALGO_HMAC_RIPEMD160, bits( 160 ), "HMAC-RIPEMD160",
		bits( 64 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacRIPEMD160SelfTest, hmacRIPEMD160GetInfo, NULL, NULL, hmacRIPEMD160InitKey,
		NULL, hmacRIPEMD160Hash, hmacRIPEMD160Hash },
#endif /* USE_HMAC_RIPEMD160 */

	/* The Diffie-Hellman capabilities */
	{ CRYPT_ALGO_DH, bits( 0 ), "Diffie-Hellman",
		bits( MIN_PKCSIZE_BITS ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		dhSelfTest, getInfo, NULL, NULL, dhInitKey, dhGenerateKey,
		dhEncrypt, dhDecrypt },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( MIN_PKCSIZE_BITS ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		rsaSelfTest, getInfo, NULL, NULL, rsaInitKey, rsaGenerateKey,
		rsaEncrypt, rsaDecrypt, NULL, NULL, NULL, NULL, NULL, NULL,
		rsaDecrypt, rsaEncrypt },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( MIN_PKCSIZE_BITS ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		dsaSelfTest, getInfo, NULL, NULL, dsaInitKey, dsaGenerateKey,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		dsaSign, dsaSigCheck },

#ifdef USE_ELGAMAL
	/* The ElGamal capabilities */
	{ CRYPT_ALGO_ELGAMAL, bits( 0 ), "Elgamal",
		bits( MIN_PKCSIZE_BITS ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		elgamalSelfTest, getInfo, NULL, NULL, elgamalInitKey, elgamalGenerateKey,
		elgamalEncrypt, elgamalDecrypt, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL },
#endif /* USE_ELGAMAL */

	/* Vendors may want to use their own algorithms, which aren't part of the
	   general cryptlib suite.  The following provides the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* The end-of-list marker.  This value isn't linked into the
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }
	};

/* Initialise the capability info */

static void initCapabilities( void )
	{
	CAPABILITY_INFO *prevCapabilityInfoPtr = NULL;
	int i;

	/* Perform a consistency check on the encryption mode values, which
	   are used to index a table of per-mode function pointers */
	assert( CRYPT_MODE_CBC == CRYPT_MODE_ECB + 1 && \
			CRYPT_MODE_CFB == CRYPT_MODE_CBC + 1 && \
			CRYPT_MODE_OFB == CRYPT_MODE_CFB + 1 && \
			CRYPT_MODE_LAST == CRYPT_MODE_OFB + 1 );

	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
		{
		assert( capabilityInfoOK( &capabilities[ i ], FALSE ) );
		if( prevCapabilityInfoPtr != NULL )
			prevCapabilityInfoPtr->next = &capabilities[ i ];
		prevCapabilityInfoPtr = &capabilities[ i ];
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
	deviceInfo->capabilityInfo = capabilities;
	deviceInfo->createObjectFunctions = createObjectFunctions;
	deviceInfo->mechanismFunctions = mechanismFunctions;

	return( CRYPT_OK );
	}
