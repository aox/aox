/****************************************************************************
*																			*
*						cryptlib DES Encryption Routines					*
*						Copyright Peter Gutmann 1995-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "des.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "../crypt/des.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
  #include "crypt/des.h"
#endif /* Compiler-specific includes */

/* The DES block size */

#define DES_BLOCKSIZE			8

#if defined( INC_ALL )
  #include "testdes.h"
#elif defined( INC_CHILD )
  #include "../crypt/testdes.h"
#else
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

/* The scheduled DES key and size of the keyscheduled DES key */

#define DES_KEY					Key_schedule
#define DES_KEYSIZE				sizeof( Key_schedule )

/****************************************************************************
*																			*
*							DES Self-test Routines							*
*																			*
****************************************************************************/

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 500-20, 1980 */

static int desTestLoop( const DES_TEST *testData, int iterations, 
						int operation )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key[ DES_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		/* Since the self-test uses weak keys, we have to explicitly use the
		   non-parity-checking key schedule function */
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );
		des_set_key_unchecked( ( C_Block * ) testData[ i ].key,
							   *( ( Key_schedule * ) key ) );
		des_ecb_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						 *( ( Key_schedule * ) key ), operation );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

int desSelfTest( void )
	{
	int status = CRYPT_OK;

	/* Check the DES test vectors */
	if( ( desTestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testRS, sizeof( testRS ) / sizeof( DES_TEST ),
					   DES_DECRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) )
		status = CRYPT_ERROR;

	return( status );
	}

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

int desGetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( DES_KEYSIZE );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int desEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, 
						 *( DES_KEY * ) convInfo->key, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, 
						 *( DES_KEY * ) convInfo->key, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int desEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	des_ncbc_encrypt( buffer, buffer, noBytes, *( DES_KEY * ) convInfo->key,
					  ( C_Block * ) convInfo->currentIV, DES_ENCRYPT );

	return( CRYPT_OK );
	}

int desDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	des_ncbc_encrypt( buffer, buffer, noBytes, *( DES_KEY * ) convInfo->key,
					  ( C_Block * ) convInfo->currentIV, DES_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int desEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) convInfo->currentIV,
						 ( C_Block * ) convInfo->currentIV,
						 *( DES_KEY * ) convInfo->key, DES_ENCRYPT );

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
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BYTE temp[ DES_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) convInfo->currentIV,
						 ( C_Block * ) convInfo->currentIV,
						 *( DES_KEY * ) convInfo->key, DES_ENCRYPT );

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
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int desEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) convInfo->currentIV,
						 ( C_Block * ) convInfo->currentIV,
						 *( DES_KEY * ) convInfo->key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) convInfo->currentIV,
						 ( C_Block * ) convInfo->currentIV,
						 *( DES_KEY * ) convInfo->key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule a DES key */

int desInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
				const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong (which never occurs since we force the correct parity) or -2
	   if a weak key is used */
	des_set_odd_parity( ( C_Block * ) convInfo->userKey );
	if( des_key_sched( ( C_Block * ) convInfo->userKey, 
					   *( DES_KEY * ) convInfo->key ) )
		return( CRYPT_ARGERROR_STR1 );

	return( CRYPT_OK );
	}
