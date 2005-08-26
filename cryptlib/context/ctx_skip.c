/****************************************************************************
*																			*
*					  cryptlib Skipjack Encryption Routines					*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
#else
  #include "crypt.h"
  #include "context/context.h"
#endif /* Compiler-specific includes */

#ifdef USE_SKIPJACK 

/* Size of the Skipjack block and key size */

#define SKIPJACK_KEYSIZE			10
#define SKIPJACK_BLOCKSIZE			8
#define SKIPJACK_EXPANDED_KEYSIZE	SKIPJACK_KEYSIZE * 256

/* Prototypes for functions in crypt/skipjack.c */

void skipjackMakeKey( BYTE key[ SKIPJACK_KEYSIZE ],
					  BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ]);
void skipjackEncrypt( BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ],
					  BYTE in[ SKIPJACK_BLOCKSIZE ],
					  BYTE out[ SKIPJACK_BLOCKSIZE ] );
void skipjackDecrypt( BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ],
					  BYTE in[ SKIPJACK_BLOCKSIZE ],
					  BYTE out[ SKIPJACK_BLOCKSIZE ] );

/****************************************************************************
*																			*
*							Skipjack Self-test Routines						*
*																			*
****************************************************************************/

/* Skipjack test vectors from the NSA Skipjack specification */

static const FAR_BSS struct SKIPJACK_TEST {
	const BYTE key[ 10 ];
	const BYTE plainText[ 8 ];
	const BYTE cipherText[ 8 ];
	} testSkipjack[] = {
	{ { 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 },
	  { 0x33, 0x22, 0x11, 0x00, 0xDD, 0xCC, 0xBB, 0xAA },
	  { 0x25, 0x87, 0xCA, 0xE2, 0x7A, 0x12, 0xD3, 0x00 } }
	};

/* Test the Skipjack code against the Skipjack test vectors */

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getSkipjackCapability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	BYTE keyData[ SKIPJACK_EXPANDED_KEYSIZE ];
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	int i, status;

	for( i = 0; i < sizeof( testSkipjack ) / sizeof( struct SKIPJACK_TEST ); i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
						   &contextData, sizeof( CONV_INFO ), keyData );
		memcpy( temp, testSkipjack[ i ].plainText, SKIPJACK_BLOCKSIZE );
		status = capabilityInfo->initKeyFunction( &contextInfo, 
					( BYTE * ) testSkipjack[ i ].key, SKIPJACK_KEYSIZE );
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, temp, 
													  SKIPJACK_BLOCKSIZE );
		staticDestroyContext( &contextInfo );
		if( cryptStatusError( status ) || \
			memcmp( testSkipjack[ i ].cipherText, temp, SKIPJACK_BLOCKSIZE ) )
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
		return( SKIPJACK_EXPANDED_KEYSIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							Skipjack En/Decryption Routines					*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

static int encryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Encrypt a block of data */
		skipjackEncrypt( convInfo->key, buffer, buffer );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

static int decryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		/* Decrypt a block of data */
		skipjackDecrypt( convInfo->key, buffer, buffer );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

static int encryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SKIPJACK_BLOCKSIZE; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Encrypt a block of data */
		skipjackEncrypt( convInfo->key, buffer, buffer );

		/* Shift ciphertext into IV */
		memcpy( convInfo->currentIV, buffer, SKIPJACK_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

static int decryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- > 0 )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, SKIPJACK_BLOCKSIZE );

		/* Decrypt a block of data */
		skipjackDecrypt( convInfo->key, buffer, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SKIPJACK_BLOCKSIZE; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, temp, SKIPJACK_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SKIPJACK_BLOCKSIZE );

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
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : \
													 noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( convInfo->key, convInfo->currentIV, 
						 convInfo->currentIV );

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
	convInfo->ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

static int decryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : \
													 noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( convInfo->key, convInfo->currentIV,
						 convInfo->currentIV );

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
	convInfo->ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, SKIPJACK_BLOCKSIZE );

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
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : \
													 noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( convInfo->key, convInfo->currentIV,
						 convInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

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
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : \
													 noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( convInfo->key, convInfo->currentIV,
						 convInfo->currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Skipjack Key Management Routines				*
*																			*
****************************************************************************/

/* Key schedule a Skipjack key */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	/* In theory Skipjack doesn't require a key schedule so we could just
	   copy the user key across, however the optimised version preprocesses
	   the keying data to save an XOR on each F-table access */
	skipjackMakeKey( ( BYTE * ) key, convInfo->key );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_SKIPJACK, bitsToBytes( 64 ), "Skipjack",
	bitsToBytes( 80 ), bitsToBytes( 80 ), bitsToBytes( 80 ),
	selfTest, getInfo, NULL, initKeyParams, initKey, NULL,
	encryptECB, decryptECB, encryptCBC, decryptCBC,
	encryptCFB, decryptCFB, encryptOFB, decryptOFB
	};

const CAPABILITY_INFO *getSkipjackCapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_SKIPJACK */
