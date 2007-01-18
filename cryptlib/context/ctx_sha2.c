/****************************************************************************
*																			*
*							cryptlib SHA2 Hash Routines						*
*						Copyright Peter Gutmann 1999-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "sha.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/sha2.h"
#endif /* Compiler-specific includes */

#ifdef USE_SHA2

#define HASH_STATE_SIZE		sizeof( sha2_ctx )

/****************************************************************************
*																			*
*							SHA2 Self-test Routines							*
*																			*
****************************************************************************/

/* Test the SHA output against the test vectors given in FIPS 180-2.  We skip
   the third test since this takes several seconds to execute, which leads
   to an unacceptable delay */

#ifndef SHA384_DIGEST_SIZE
  /* These may not be defined on non 64-bit systems */
  #define SHA384_DIGEST_SIZE			48
  #define SHA512_DIGEST_SIZE			64
  #define sha2_begin( size, ctx )		sha256_begin( ( ctx )->uu->ctx256 )
  #define sha2_hash( data, len, ctx )	sha256_hash( data, len, ( ctx )->uu->ctx256 )
  #define sha2_end( hash, ctx )			sha256_end( hash, ( ctx )->uu->ctx256 )
#endif /* SHA384_DIGEST_SIZE */

void sha2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					 const int outBufMaxLength, const BYTE *inBuffer, 
					 const int inLength, const HASH_STATE hashState );

static const struct {
	const char *data;							/* Data to hash */
	const int length;							/* Length of data */
	const BYTE dig256[ SHA256_DIGEST_SIZE ];	/* Digest of data */
	const BYTE dig384[ SHA384_DIGEST_SIZE ];	/* Digest of data */
	const BYTE dig512[ SHA512_DIGEST_SIZE ];	/* Digest of data */
	} FAR_BSS sha2Values[] = {
	{ "abc", 3,
	  { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad },
	  {	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
		0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
		0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
		0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
		0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
		0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7 },
	  {	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
		0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
		0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
		0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
		0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
		},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  {	0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
	    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 },
	  { 0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39,
		0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39,
		0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab,
		0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6,
		0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f,
		0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b },
	  {	0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a,
		0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
		0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8,
		0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
		0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9,
		0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
		0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03,
		0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45 }
		},
#if 0
	{ "aaaaa...", 1000000L,
	  {	0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
	    0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
		0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
		0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 },
	  {	0x9d, 0x0e, 0x18, 0x09, 0x71, 0x64, 0x74, 0xcb,
		0x08, 0x6e, 0x83, 0x4e, 0x31, 0x0a, 0x4a, 0x1c,
		0xed, 0x14, 0x9e, 0x9c, 0x00, 0xf2, 0x48, 0x52,
		0x79, 0x72, 0xce, 0xc5, 0x70, 0x4c, 0x2a, 0x5b,
		0x07, 0xb8, 0xb3, 0xdc, 0x38, 0xec, 0xc4, 0xeb,
		0xae, 0x97, 0xdd, 0xd8, 0x7f, 0x3d, 0x89, 0x85 },
	  {	0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
		0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
		0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
		0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
		0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
		0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
		0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
		0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b } }
#endif
	{ NULL, 0, { 0 }, { 0 }, { 0 } }
	};

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getSHA2Capability();
	CONTEXT_INFO contextInfo;
	HASH_INFO contextData;
	BYTE keyData[ HASH_STATE_SIZE + 8 ];
	int i, status;

	/* SHA-2 requires the largest amount of context state so we check to
	   make sure that the HASH_STATE_SIZE is large enough */
	assert( sizeof( HASHINFO ) <= HASH_STATE_SIZE );

	for( i = 0; sha2Values[ i ].data != NULL; i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_HASH, capabilityInfo,
						   &contextData, sizeof( HASH_INFO ), keyData );
		status = capabilityInfo->encryptFunction( &contextInfo,
							( BYTE * ) sha2Values[ i ].data,
							sha2Values[ i ].length );
		contextInfo.flags |= CONTEXT_HASH_INITED;
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, NULL, 0 );
		if( cryptStatusOK( status ) && \
			memcmp( contextInfo.ctxHash->hash, sha2Values[ i ].dig256,
					SHA256_DIGEST_SIZE ) )
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
	sha2_ctx *shaInfo = ( sha2_ctx * ) contextInfoPtr->ctxHash->hashInfo;

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		sha2_begin( SHA256_DIGEST_SIZE, shaInfo );

	if( noBytes > 0 )
		sha2_hash( buffer, noBytes, shaInfo );
	else
		sha2_end( contextInfoPtr->ctxHash->hash, shaInfo );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context.*/

void sha2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					 const int outBufMaxLength, const BYTE *inBuffer, 
					 const int inLength, const HASH_STATE hashState )
	{
	sha2_ctx *shaInfo = ( sha2_ctx * ) hashInfo;
	
	assert( ( hashState == HASH_ALL && hashInfo == NULL ) || \
			( hashState != HASH_ALL && \
			  isWritePtr( hashInfo, sizeof( HASHINFO ) ) ) );
	assert( ( ( hashState != HASH_END && hashState != HASH_ALL ) && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( ( hashState == HASH_END || hashState == HASH_ALL ) && \
			  isWritePtr( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= 32 ) );
	assert( inBuffer == NULL || isReadPtr( inBuffer, inLength ) );

	switch( hashState )
		{
		case HASH_START:
			sha2_begin( SHA256_DIGEST_SIZE, shaInfo );
			/* Drop through */

		case HASH_CONTINUE:
			sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			break;

		case HASH_END:
			if( inBuffer != NULL )
				sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			sha2_end( outBuffer, shaInfo );
			break;

		case HASH_ALL:
			{
			sha2_ctx shaInfoBuffer;

			sha2_begin( SHA256_DIGEST_SIZE, &shaInfoBuffer );
			sha2_hash( ( BYTE * ) inBuffer, inLength, &shaInfoBuffer );
			sha2_end( outBuffer, &shaInfoBuffer );
			zeroise( &shaInfoBuffer, sizeof( sha2_ctx ) );
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
	CRYPT_ALGO_SHA2, bitsToBytes( 256 ), "SHA-2",
	bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
	selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
	};

const CAPABILITY_INFO *getSHA2Capability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_SHA2 */
