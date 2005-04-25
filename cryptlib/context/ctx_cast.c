/****************************************************************************
*																			*
*					  cryptlib CAST-128 Encryption Routines					*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "cast.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "../crypt/cast.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
  #include "crypt/cast.h"
#endif /* Compiler-specific includes */

#ifdef USE_CAST

/* Defines to map from EAY to native naming */

#define CAST_BLOCKSIZE		CAST_BLOCK

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

int castSelfTest( void )
	{
	BYTE temp[ CAST_BLOCKSIZE ];
	CAST_KEY castKey;
	int i;

	for( i = 0; i < sizeof( testCAST ) / sizeof( struct CAST_TEST ); i++ )
		{
		memcpy( temp, testCAST[ i ].plainText, CAST_BLOCKSIZE );
		CAST_set_key( &castKey, CAST_KEY_LENGTH, testCAST[ i ].key );
		CAST_ecb_encrypt( temp, temp, &castKey, CAST_ENCRYPT );
		if( memcmp( testCAST[ i ].cipherText, temp, CAST_BLOCKSIZE ) )
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

int castGetInfo( const CAPABILITY_INFO_TYPE type, 
				 void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( CAST_EXPANDED_KEYSIZE );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							CAST En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int castEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, convInfo->key, CAST_ENCRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int castDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, convInfo->key, CAST_DECRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int castEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	CAST_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					  convInfo->currentIV, CAST_ENCRYPT );

	return( CRYPT_OK );
	}

int castDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	CAST_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					  convInfo->currentIV, CAST_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int castEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int castDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BYTE temp[ CAST_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int castEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int castDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int castInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
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
#endif /* USE_CAST */
