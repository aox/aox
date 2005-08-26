/****************************************************************************
*																			*
*					  cryptlib CAST-128 Encryption Routines					*
*						Copyright Peter Gutmann 1997-2005					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "cast.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "../crypt/cast.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/cast.h"
#endif /* Compiler-specific includes */

#ifdef USE_CAST

/* Defines to map from EAY to native naming */

#define CAST_BLOCKSIZE			CAST_BLOCK

/* The size of the keyscheduled CAST key */

#define CAST_EXPANDED_KEYSIZE	sizeof( CAST_KEY )

/****************************************************************************
*																			*
*								CAST Self-test Routines						*
*																			*
****************************************************************************/

/* CAST test vectors from CAST specification */

static const FAR_BSS struct CAST_TEST {
	BYTE key[ CAST_KEY_LENGTH ];
	BYTE plainText[ CAST_BLOCKSIZE ];
	BYTE cipherText[ CAST_BLOCKSIZE ];
	} testCAST[] = {
	{ { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
		0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
	  { 0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2 } }
	};

/* Test the CAST code against the CAST test vectors */

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getCASTCapability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	BYTE keyData[ CAST_EXPANDED_KEYSIZE ];
	BYTE temp[ CAST_BLOCKSIZE ];
	int i, status;

	for( i = 0; i < sizeof( testCAST ) / sizeof( struct CAST_TEST ); i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
						   &contextData, sizeof( CONV_INFO ), keyData );
		memcpy( temp, testCAST[ i ].plainText, CAST_BLOCKSIZE );
		status = capabilityInfo->initKeyFunction( &contextInfo, 
												  testCAST[ i ].key,
												  CAST_KEY_LENGTH );
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, temp, 
													  CAST_BLOCKSIZE );
		staticDestroyContext( &contextInfo );
		if( cryptStatusError( status ) || \
			memcmp( testCAST[ i ].cipherText, temp, CAST_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

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
		return( CAST_EXPANDED_KEYSIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							CAST En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

static int encryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Encrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, convInfo->key, CAST_ENCRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

static int decryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Decrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, convInfo->key, CAST_DECRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

static int encryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	CAST_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					  convInfo->currentIV, CAST_ENCRYPT );

	return( CRYPT_OK );
	}

static int decryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	CAST_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					  convInfo->currentIV, CAST_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

static int encryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( convInfo->currentIV, convInfo->currentIV,
						  convInfo->key, CAST_ENCRYPT );

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
	convInfo->ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

static int decryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BYTE temp[ CAST_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( convInfo->currentIV, convInfo->currentIV,
						  convInfo->key, CAST_ENCRYPT );

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
	convInfo->ivCount = ( ivCount % CAST_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

static int encryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( convInfo->currentIV, convInfo->currentIV,
						  convInfo->key, CAST_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

static int decryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( convInfo->currentIV, convInfo->currentIV,
						  convInfo->key, CAST_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							CAST Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule an CAST key */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	CAST_set_key( convInfo->key, CAST_KEY_LENGTH, ( BYTE * ) key );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_CAST, bitsToBytes( 64 ), "CAST-128",
	bitsToBytes( MIN_KEYSIZE_BITS ), bitsToBytes( 128 ), bitsToBytes( 128 ),
	selfTest, getInfo, NULL, initKeyParams, initKey, NULL,
	encryptECB, decryptECB, encryptCBC, decryptCBC,
	encryptCFB, decryptCFB, encryptOFB, decryptOFB 
	};

const CAPABILITY_INFO *getCASTCapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_CAST */
