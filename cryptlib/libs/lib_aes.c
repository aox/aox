/****************************************************************************
*																			*
*						cryptlib AES Encryption Routines					*
*						Copyright Peter Gutmann 2000-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "aes.h"
  #include "context.h"
  #include "libs.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../crypt/aes.h"
  #include "../misc/context.h"
  #include "libs.h"
#else
  #include "crypt.h"
  #include "crypt/aes.h"
  #include "misc/context.h"
  #include "libs/libs.h"
#endif /* Compiler-specific includes */

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

/* Test the AES code against the test vectors from the AES FIPS */

int aesSelfTest( void )
	{
	int i;

	for( i = 0; i < sizeof( testAES ) / sizeof( AES_TEST ); i++ )
		{
		AES_EKEY aesEKey;
		AES_DKEY aesDKey;
		BYTE temp[ AES_BLOCKSIZE ];

		memcpy( temp, testAES[ i ].plaintext, AES_BLOCKSIZE );
		switch(testAES[ i ].keySize)
			{
			case 16: 
				aes_encrypt_key128( testAES[ i ].key, &aesEKey ); 
				aes_decrypt_key128( testAES[ i ].key, &aesDKey ); 
				break;

			case 24: 
				aes_encrypt_key192( testAES[ i ].key, &aesEKey );
				aes_decrypt_key192( testAES[ i ].key, &aesDKey ); 
				break;

			case 32: 
				aes_encrypt_key256( testAES[ i ].key, &aesEKey );
				aes_decrypt_key256( testAES[ i ].key, &aesDKey ); 
				break;
			}
		aes_encrypt( temp, temp, &aesEKey );
		if( memcmp( testAES[ i ].ciphertext, temp, AES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		aes_decrypt( temp, temp, &aesDKey );
		if( memcmp( testAES[ i ].plaintext, temp, AES_BLOCKSIZE ) )
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

int aesGetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( AES_EXPANDED_KEYSIZE );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							AES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int aesEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		aes_encrypt( buffer, buffer, aesKey );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int aesDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_DKEY *aesKey = DEC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		aes_decrypt( buffer, buffer, aesKey );

		/* Move on to next block of data */
		buffer += AES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int aesEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- )
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

int aesDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_DKEY *aesKey = DEC_KEY( convInfo );
	BYTE temp[ AES_BLOCKSIZE ];
	int blockCount = noBytes / AES_BLOCKSIZE;

	while( blockCount-- )
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

int aesEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int aesDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	BYTE temp[ AES_BLOCKSIZE ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int aesEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int aesDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const AES_EKEY *aesKey = ENC_KEY( convInfo );
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
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

	while( noBytes )
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

int aesInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
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
