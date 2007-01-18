/****************************************************************************
*																			*
*							cryptlib MD2 Hash Routines						*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "md2.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/md2.h"
#endif /* Compiler-specific includes */

#ifdef USE_MD2

#define HASH_STATE_SIZE		sizeof( MD2_CTX )

/****************************************************************************
*																			*
*								MD2 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD2 output against the test vectors given in RFC 1319 */

void md2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );

static const struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ MD2_DIGEST_LENGTH ];	/* Digest of data */
	} FAR_BSS digestValues[] = {
	{ "", 0,
	  { 0x83, 0x50, 0xE5, 0xA3, 0xE2, 0x4C, 0x15, 0x3D,
		0xF2, 0x27, 0x5C, 0x9F, 0x80, 0x69, 0x27, 0x73 } },
	{ "a", 1,
	  { 0x32, 0xEC, 0x01, 0xEC, 0x4A, 0x6D, 0xAC, 0x72,
		0xC0, 0xAB, 0x96, 0xFB, 0x34, 0xC0, 0xB5, 0xD1 } },
	{ "abc", 3,
	  { 0xDA, 0x85, 0x3B, 0x0D, 0x3F, 0x88, 0xD9, 0x9B,
		0x30, 0x28, 0x3A, 0x69, 0xE6, 0xDE, 0xD6, 0xBB } },
	{ "message digest", 14,
	  { 0xAB, 0x4F, 0x49, 0x6B, 0xFB, 0x2A, 0x53, 0x0B,
		0x21, 0x9F, 0xF3, 0x30, 0x31, 0xFE, 0x06, 0xB0 } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0x4E, 0x8D, 0xDF, 0xF3, 0x65, 0x02, 0x92, 0xAB,
		0x5A, 0x41, 0x08, 0xC3, 0xAA, 0x47, 0x94, 0x0B } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0xDA, 0x33, 0xDE, 0xF2, 0xA4, 0x2D, 0xF1, 0x39,
		0x75, 0x35, 0x28, 0x46, 0xC3, 0x03, 0x38, 0xCD } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0xD5, 0x97, 0x6F, 0x79, 0xD8, 0x3D, 0x3A, 0x0D,
		0xC9, 0x80, 0x6C, 0x3C, 0x66, 0xF3, 0xEF, 0xD8 } },
	{ NULL, 0, { 0 } }
	};

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getMD2Capability();
	CONTEXT_INFO contextInfo;
	HASH_INFO contextData;
	BYTE keyData[ HASH_STATE_SIZE + 8 ];
	int i, status;

	/* Test MD2 against the test vectors given in RFC 1319 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_HASH, capabilityInfo,
						   &contextData, sizeof( HASH_INFO ), keyData );
		status = CRYPT_OK ;
		if( digestValues[ i ].length > 0 )
			{
			status = capabilityInfo->encryptFunction( &contextInfo,
								( BYTE * ) digestValues[ i ].data,
								digestValues[ i ].length );
			contextInfo.flags |= CONTEXT_HASH_INITED;
			}
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, NULL, 0 );
		if( cryptStatusOK( status ) && \
			memcmp( contextInfo.ctxHash->hash, digestValues[ i ].digest,
					MD2_DIGEST_LENGTH ) )
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
*								MD2 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD2 */

static int hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	MD2_CTX *md2Info = ( MD2_CTX * ) contextInfoPtr->ctxHash->hashInfo;

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		MD2_Init( md2Info );

	if( noBytes > 0 )
		MD2_Update( md2Info, buffer, noBytes );
	else
		MD2_Final( contextInfoPtr->ctxHash->hash, md2Info );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context */

void md2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState )
	{
	MD2_CTX *md2Info = ( MD2_CTX * ) hashInfo;

	assert( ( hashState == HASH_ALL && hashInfo == NULL ) || \
			( hashState != HASH_ALL && \
			  isWritePtr( hashInfo, sizeof( HASHINFO ) ) ) );
	assert( ( ( hashState != HASH_END && hashState != HASH_ALL ) && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( ( hashState == HASH_END || hashState == HASH_ALL ) && \
			  isWritePtr( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= 16 ) );
	assert( inBuffer == NULL || isReadPtr( inBuffer, inLength ) );

	switch( hashState )
		{
		case HASH_START:
			MD2_Init( md2Info );
			/* Drop through */

		case HASH_CONTINUE:
			MD2_Update( md2Info, ( BYTE * ) inBuffer, inLength );
			break;

		case HASH_END:
			if( inBuffer != NULL )
				MD2_Update( md2Info, ( BYTE * ) inBuffer, inLength );
			MD2_Final( outBuffer, md2Info );
			break;

		case HASH_ALL:
			{
			MD2_CTX md2InfoBuffer;

			MD2_Init( &md2InfoBuffer );
			MD2_Update( &md2InfoBuffer, ( BYTE * ) inBuffer, inLength );
			MD2_Final( outBuffer, &md2InfoBuffer );
			zeroise( &md2InfoBuffer, sizeof( MD2_CTX ) );
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
	CRYPT_ALGO_MD2, bitsToBytes( 128 ), "MD2",
	bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
	selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
	};

const CAPABILITY_INFO *getMD2Capability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_MD2 */
