/****************************************************************************
*																			*
*							cryptlib MD4 Hash Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "md4.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "../crypt/md4.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
  #include "crypt/md4.h"
#endif /* Compiler-specific includes */

#ifdef USE_MD4

/****************************************************************************
*																			*
*								MD4 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD4 output against the test vectors given in RFC 1320 */

static const FAR_BSS struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ MD4_DIGEST_LENGTH ];	/* Digest of data */
	} digestValues[] = {
	{ "", 0,
	  { 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
		0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 } },
	{ "a", 1,
	  { 0xBD, 0xE5, 0x2C, 0xB3, 0x1D, 0xE3, 0x3E, 0x46,
		0x24, 0x5E, 0x05, 0xFB, 0xDB, 0xD6, 0xFB, 0x24 } },
	{ "abc", 3,
	  { 0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52,
		0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6, 0x72, 0x9D } },
	{ "message digest", 14,
	  { 0xD9, 0x13, 0x0A, 0x81, 0x64, 0x54, 0x9F, 0xE8,
		0x18, 0x87, 0x48, 0x06, 0xE1, 0xC7, 0x01, 0x4B } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0xD7, 0x9E, 0x1C, 0x30, 0x8A, 0xA5, 0xBB, 0xCD,
		0xEE, 0xA8, 0xED, 0x63, 0xDF, 0x41, 0x2D, 0xA9 } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0x04, 0x3F, 0x85, 0x82, 0xF2, 0x41, 0xDB, 0x35,
		0x1C, 0xE6, 0x27, 0xE1, 0x53, 0xE7, 0xF0, 0xE4 } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0xE3, 0x3B, 0x4D, 0xDC, 0x9C, 0x38, 0xF2, 0x19,
		0x9C, 0x3E, 0x7B, 0x16, 0x4F, 0xCC, 0x05, 0x36 } },
	{ NULL, 0, { 0 } }
	};

int md4SelfTest( void )
	{
	BYTE digest[ MD4_DIGEST_LENGTH ];
	int i;

	/* Test MD4 against the test vectors given in RFC 1320 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		MD4_CTX md4Info;

		MD4_Init( &md4Info );
		MD4_Update( &md4Info, ( BYTE * ) digestValues[ i ].data, 
				   digestValues[ i ].length );
		MD4_Final( digest, &md4Info );
		if( memcmp( digest, digestValues[ i ].digest, MD4_DIGEST_LENGTH ) )
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

int md4GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( sizeof( MD4_CTX ) );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*								MD4 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD4 */

int md4Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	MD4_CTX *md4Info = ( MD4_CTX * ) contextInfoPtr->ctxHash->hashInfo;

	/* If the hash state was reset to allow another round of hashing, 
	   reinitialise things */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		MD4_Init( md4Info );

	if( noBytes > 0 )
		MD4_Update( md4Info, buffer, noBytes );
	else
		MD4_Final( contextInfoPtr->ctxHash->hash, md4Info );

	return( CRYPT_OK );
	}
#endif /* USE_MD4 */
