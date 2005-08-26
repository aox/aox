/****************************************************************************
*																			*
*						cryptlib AES Encryption Routines					*
*						Copyright Peter Gutmann 2000-2005					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "aes.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "../crypt/aes.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/aes.h"
#endif /* Compiler-specific includes */

#ifdef USE_AES

/* The size of an AES key and block and a keyscheduled AES key */

#define AES_KEYSIZE				32
#define AES_BLOCKSIZE			16
#define AES_EXPANDED_KEYSIZE	sizeof( AES_CTX )

/* The scheduled AES key and key schedule control and function return 
   codes */

#define AES_EKEY				aes_encrypt_ctx
#define AES_DKEY				aes_decrypt_ctx
#define AES_2KEY				AES_CTX

/* The AES code separates encryption and decryption to make it easier to
   do encrypt-only or decrypt-only apps, however since we don't know
   what the user will choose to do we have to do both key schedules (this
   is a relatively minor overhead compared to en/decryption, so it's not a 
   big problem) */

typedef struct {
	AES_EKEY	encKey;
	AES_DKEY	decKey;
	} AES_CTX;

#define	ENC_KEY( contextInfoPtr )	&( ( AES_2KEY * ) convInfo->key )->encKey
#define	DEC_KEY( contextInfoPtr )	&( ( AES_2KEY * ) convInfo->key )->decKey

/****************************************************************************
*																			*
*								AES Self-test Routines						*
*																			*
****************************************************************************/

/* AES FIPS test vectors */

/* The data structure for the ( key, plaintext, ciphertext ) triplets */

typedef struct {
	const int keySize;
	const BYTE key[ AES_KEYSIZE ];
	const BYTE plaintext[ AES_BLOCKSIZE ];
	const BYTE ciphertext[ AES_BLOCKSIZE ];
	} AES_TEST;

static const FAR_BSS AES_TEST testAES[] = {
	{ 16,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
	  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	  { 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 
		0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A } },
	{ 24,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
	  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	  { 0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0, 
		0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91 } },
	{ 32,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	  { 0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 
		0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89 } }
	};

#if 0

/* Test the AES code against the test vectors from the AES FIPS */

static void printVector( const char *description, const BYTE *data,
						 const int length )
	{
	int i;

	printf( "%s = ", description );
	for( i = 0; i < length; i++ )
		printf( "%02x", data[ i ] );
	putchar( '\n' );
	}

static int updateKey( BYTE *key, const int keySize,
					  CONTEXT_INFO *contextInfo, 
					  const CAPABILITY_INFO *capabilityInfo,
					  const BYTE *newKey1, const BYTE *newKey2 )
	{
	BYTE keyData[ AES_KEYSIZE ];
	int i;

	switch( keySize )
		{
		case 16:
			memcpy( keyData, newKey2, keySize );
			break;

		case 24:
			memcpy( keyData, newKey1 + 8, keySize );
			memcpy( keyData + 8, newKey2, AES_BLOCKSIZE );

		case 32:
			memcpy( keyData, newKey1, AES_BLOCKSIZE );
			memcpy( keyData + 16, newKey2, AES_BLOCKSIZE );
		}

	for( i = 0; i < keySize; i++ )
		key[ i ] ^= keyData[ i ];
	return( capabilityInfo->initKeyFunction( contextInfo, key, 
											 keySize ) );
	}

static int mct( CONTEXT_INFO *contextInfo, 
			    const CAPABILITY_INFO *capabilityInfo,
				const BYTE *initialKey, const int keySize,
				const BYTE *initialIV, const BYTE *initialPT )
	{
	BYTE key[ AES_KEYSIZE ], iv[ AES_KEYSIZE ], temp[ AES_BLOCKSIZE ];
	int i;

	memcpy( key, initialKey, keySize );
	if( iv != NULL )
		memcpy( iv, initialIV, AES_BLOCKSIZE );
	memcpy( temp, initialPT, AES_BLOCKSIZE );
	for( i = 0; i < 100; i++ )
		{
		BYTE prevTemp[ AES_BLOCKSIZE ];
		int j, status;

		status = capabilityInfo->initKeyFunction( contextInfo, key, 
												  keySize );
		if( cryptStatusError( status ) )
			return( status );
		printVector( "Key", key, keySize );
		if( iv != NULL )
			printVector( "IV", iv, AES_BLOCKSIZE );
		printVector( "Plaintext", temp, AES_BLOCKSIZE );
		if( iv != NULL )
			memcpy( contextInfo->ctxConv->currentIV, iv, AES_BLOCKSIZE );
		for( j = 0; j < 1000; j++ )
			{
/*			memcpy( prevTemp, temp, AES_BLOCKSIZE ); */
			if( iv != NULL && j == 0 )
				{
				status = capabilityInfo->encryptCBCFunction( contextInfo, temp, 
															 AES_BLOCKSIZE );
				memcpy( prevTemp, temp, AES_BLOCKSIZE );
				memcpy( temp, iv, AES_BLOCKSIZE );
				}
			else
				{
				status = capabilityInfo->encryptFunction( contextInfo, temp, 
														  AES_BLOCKSIZE );
				if( iv != NULL )
					{
					BYTE tmpTemp[ AES_BLOCKSIZE ];

					memcpy( tmpTemp, temp, AES_BLOCKSIZE );
					memcpy( temp, prevTemp, AES_BLOCKSIZE );
					memcpy( prevTemp, tmpTemp, AES_BLOCKSIZE );
					}
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		printVector( "Ciphertext", temp, AES_BLOCKSIZE );
		putchar( '\n' );
		status = updateKey( key, keySize, contextInfo, capabilityInfo, 
							prevTemp, temp );
		if( cryptStatusError( status ) )
			return( status );
		}
	
	return( CRYPT_OK );
	}
#endif

static int selfTest( void )
	{
	/* ECB */
	static const BYTE mctECBKey[] = { 0x8D, 0x2E, 0x60, 0x36, 0x5F, 0x17, 0xC7, 0xDF, 0x10, 0x40, 0xD7, 0x50, 0x1B, 0x4A, 0x7B, 0x5A };
	static const BYTE mctECBPT[] = { 0x59, 0xB5, 0x08, 0x8E, 0x6D, 0xAD, 0xC3, 0xAD, 0x5F, 0x27, 0xA4, 0x60, 0x87, 0x2D, 0x59, 0x29 };
	/* CBC */
	static const BYTE mctCBCKey[] = { 0x9D, 0xC2, 0xC8, 0x4A, 0x37, 0x85, 0x0C, 0x11, 0x69, 0x98, 0x18, 0x60, 0x5F, 0x47, 0x95, 0x8C };
	static const BYTE mctCBCIV[] = { 0x25, 0x69, 0x53, 0xB2, 0xFE, 0xAB, 0x2A, 0x04, 0xAE, 0x01, 0x80, 0xD8, 0x33, 0x5B, 0xBE, 0xD6 };
	static const BYTE mctCBCPT[] = { 0x2E, 0x58, 0x66, 0x92, 0xE6, 0x47, 0xF5, 0x02, 0x8E, 0xC6, 0xFA, 0x47, 0xA5, 0x5A, 0x2A, 0xAB };
	/* OFB */
	static const BYTE mctOFBKey[] = { 0xB1, 0x1E, 0x4E, 0xCA, 0xE2, 0xE7, 0x1E, 0x14, 0x14, 0x5D, 0xD7, 0xDB, 0x26, 0x35, 0x65, 0x2F };
	static const BYTE mctOFBIV[] = { 0xAD, 0xD3, 0x2B, 0xF8, 0x20, 0x4C, 0x33, 0x33, 0x9C, 0x54, 0xCD, 0x58, 0x58, 0xEE, 0x0D, 0x13 };
	static const BYTE mctOFBPT[] = { 0x73, 0x20, 0x49, 0xE8, 0x9D, 0x74, 0xFC, 0xE7, 0xC5, 0xA4, 0x96, 0x64, 0x04, 0x86, 0x8F, 0xA6 };
	/* CFB-128 */
	static const BYTE mctCFBKey[] = { 0x71, 0x15, 0x11, 0x93, 0x1A, 0x15, 0x62, 0xEA, 0x73, 0x29, 0x0A, 0x8B, 0x0A, 0x37, 0xA3, 0xB4 };
	static const BYTE mctCFBIV[] = { 0x9D, 0xCE, 0x23, 0xFD, 0x2D, 0xF5, 0x36, 0x0F, 0x79, 0x9C, 0xF1, 0x79, 0x84, 0xE4, 0x7C, 0x8D };
	static const BYTE mctCFBPT[] = { 0xF0, 0x66, 0xBE, 0x4B, 0xD6, 0x71, 0xEB, 0xC1, 0xC4, 0xCF, 0x3C, 0x00, 0x8E, 0xF2, 0xCF, 0x18 };
	const CAPABILITY_INFO *capabilityInfo = getAESCapability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	BYTE keyData[ AES_EXPANDED_KEYSIZE ];
	int i, status;

#if 1
	for( i = 0; i < sizeof( testAES ) / sizeof( AES_TEST ); i++ )
		{
		BYTE temp[ AES_BLOCKSIZE ];

		memcpy( temp, testAES[ i ].plaintext, AES_BLOCKSIZE );
		staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
						   &contextData, sizeof( CONV_INFO ), keyData );
		status = capabilityInfo->initKeyFunction( &contextInfo, 
												  testAES[ i ].key,
												  testAES[ i ].keySize );
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, temp, 
													  AES_BLOCKSIZE );
		if( cryptStatusOK( status ) && \
			memcmp( testAES[ i ].ciphertext, temp, AES_BLOCKSIZE ) )
			status = CRYPT_ERROR;
		if( cryptStatusOK( status ) )
			status = capabilityInfo->decryptFunction( &contextInfo, temp, 
													  AES_BLOCKSIZE );
		if( cryptStatusOK( status ) && \
			memcmp( testAES[ i ].plaintext, temp, AES_BLOCKSIZE ) )
			status = CRYPT_ERROR;
		staticDestroyContext( &contextInfo );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR );
		}
#endif

#if 0	/* OK */
	staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
					   &contextData, sizeof( CONV_INFO ), keyData );
	status = mct( &contextInfo, capabilityInfo, mctECBKey, 16, 
				  NULL, mctECBPT );
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR );
#endif
#if 0	/* OK */
	staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
					   &contextData, sizeof( CONV_INFO ), keyData );
	status = mct( &contextInfo, capabilityInfo, mctCBCKey, 16, 
				  mctCBCIV, mctCBCPT );
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR );
#endif

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

static int getInfo( const CAPABILITY_INFO_TYPE type, void *varParam, 
					const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( AES_EXPANDED_KEYSIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							AES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

static int encryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Encrypt a block of data */
		aes_encrypt( buffer, buffer, aesKey );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

static int decryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_DKEY *aesKey = DEC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Decrypt a block of data */
		aes_decrypt( buffer, buffer, aesKey );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

static int encryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < AES_BLOCKSIZE; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Encrypt a block of data */
		aes_encrypt( buffer, buffer, aesKey);

		/* Shift ciphertext into IV */
		memcpy( convInfo->currentIV, buffer, AES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

static int decryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_DKEY *aesKey = DEC_KEY( convInfo );
	BYTE temp[ AES_BLOCKSIZE ];
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, AES_BLOCKSIZE );

		/* Decrypt a block of data */
		aes_decrypt( buffer, buffer, aesKey );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < AES_BLOCKSIZE; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, temp, AES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, AES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

static int encryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = AES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
		memcpy( convInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > AES_BLOCKSIZE ) ? AES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		aes_encrypt( convInfo->currentIV, convInfo->currentIV, aesKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % AES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

static int decryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	BYTE temp[ AES_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = AES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
		memcpy( convInfo->currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > AES_BLOCKSIZE ) ? AES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		aes_encrypt( convInfo->currentIV, convInfo->currentIV, aesKey );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % AES_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, AES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

static int encryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = AES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > AES_BLOCKSIZE ) ? AES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		aes_encrypt( convInfo->currentIV, convInfo->currentIV, aesKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % AES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

static int decryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = AES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > AES_BLOCKSIZE ) ? AES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		aes_encrypt( convInfo->currentIV, convInfo->currentIV, aesKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % AES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							AES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule an AES key */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	AES_2KEY *aesKey = convInfo->key;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	/* Call the AES key schedule code */
	aes_encrypt_key( convInfo->userKey, keyLength, &aesKey->encKey );
	aes_decrypt_key( convInfo->userKey, keyLength, &aesKey->decKey );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_AES, bitsToBytes( 128 ), "AES",
	bitsToBytes( 128 ), bitsToBytes( 128 ), bitsToBytes( 256 ),
	selfTest, getInfo, NULL, initKeyParams, initKey, NULL,
	encryptECB, decryptECB, encryptCBC, decryptCBC,
	encryptCFB, decryptCFB, encryptOFB, decryptOFB
	};

const CAPABILITY_INFO *getAESCapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_AES */
