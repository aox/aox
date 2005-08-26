/****************************************************************************
*																			*
*							cryptlib SHA Hash Routines						*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "sha.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "../crypt/sha.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/sha.h"
#endif /* Compiler-specific includes */

#define HASH_STATE_SIZE		sizeof( SHA_CTX )

/****************************************************************************
*																			*
*								SHA Self-test Routines						*
*																			*
****************************************************************************/

/* Test the SHA output against the test vectors given in FIPS 180-1.  We skip 
   the third test since this takes several seconds to execute, which leads to 
   an unacceptable delay */

void shaHashBuffer( HASHINFO hashInfo, BYTE *outBuffer, const BYTE *inBuffer,
					const int length, const HASH_STATE hashState );

static const FAR_BSS struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ SHA_DIGEST_LENGTH ];	/* Digest of data */
	} digestValues[] = {
	{ "abc", 3,
	  { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
		0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
		0x9C, 0xD0, 0xD8, 0x9D } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
		0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
		0xE5, 0x46, 0x70, 0xF1 } },
/*	{ "aaaaa...", 1000000L,
	  { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4,
		0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31,
		0x65, 0x34, 0x01, 0x6F } }, */
	{ NULL, 0, { 0 } }
	};

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getSHA1Capability();
	CONTEXT_INFO contextInfo;
	HASH_INFO contextData;
	BYTE keyData[ HASH_STATE_SIZE ];
	int i, status;

	/* Test SHA-1 against values given in FIPS 180-1 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_HASH, capabilityInfo,
						   &contextData, sizeof( HASH_INFO ), keyData );
		status = capabilityInfo->encryptFunction( &contextInfo, 
							( BYTE * ) digestValues[ i ].data, 
							digestValues[ i ].length );
		contextInfo.flags |= CONTEXT_HASH_INITED;
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, NULL, 0 );
		if( cryptStatusOK( status ) && \
			memcmp( contextInfo.ctxHash->hash, digestValues[ i ].digest, 
					SHA_DIGEST_LENGTH ) )
			status = CRYPT_ERROR;
		staticDestroyContext( &contextInfo );
		if( cryptStatusError( status ) )
			return( status );
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
		return( HASH_STATE_SIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*								SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using SHA */

static int hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) contextInfoPtr->ctxHash->hashInfo;

	/* If the hash state was reset to allow another round of hashing, 
	   reinitialise things */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		SHA1_Init( shaInfo );

	if( noBytes > 0 )
		SHA1_Update( shaInfo, buffer, noBytes );
	else
		SHA1_Final( contextInfoPtr->ctxHash->hash, shaInfo );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context.  This always uses SHA1 */

void shaHashBuffer( HASHINFO hashInfo, BYTE *outBuffer, const BYTE *inBuffer,
					const int length, const HASH_STATE hashState )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) hashInfo;

	assert( hashState == HASH_ALL || hashInfo != NULL );
	assert( inBuffer == NULL || isReadPtr( inBuffer, length ) );

	switch( hashState )
		{
		case HASH_START:
			SHA1_Init( shaInfo );
			/* Drop through */

		case HASH_CONTINUE:
			SHA1_Update( shaInfo, ( BYTE * ) inBuffer, length );
			break;

		case HASH_END:
			if( inBuffer != NULL )
				SHA1_Update( shaInfo, ( BYTE * ) inBuffer, length );
			SHA1_Final( outBuffer, shaInfo );
			break;
			
		case HASH_ALL:
			{
			SHA_CTX shaInfoBuffer;

			SHA1_Init( &shaInfoBuffer );
			SHA1_Update( &shaInfoBuffer, ( BYTE * ) inBuffer, length );
			SHA1_Final( outBuffer, &shaInfoBuffer );
			zeroise( &shaInfoBuffer, sizeof( SHA_CTX ) );
			break;
			}

		default:
			assert( NOTREACHED );
		}
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_SHA, bitsToBytes( 160 ), "SHA-1",
	bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
	selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
	};

const CAPABILITY_INFO *getSHA1Capability( void )
	{
	return( &capabilityInfo );
	}
