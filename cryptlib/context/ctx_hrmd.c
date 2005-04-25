/****************************************************************************
*																			*
*					cryptlib HMAC-RIPEMD-160 Hash Routines					*
*					  Copyright Peter Gutmann 1997-2003						*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "ripemd.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "../crypt/ripemd.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
  #include "crypt/ripemd.h"
#endif /* Compiler-specific includes */

#ifdef USE_HMAC_RIPEMD160

/* A structure to hold the initial and current MAC state info.  Rather than
   redoing the key processing each time when we're calculating multiple MACs
   with the same key, we just copy the initial state into the current state */

typedef struct {
	RIPEMD160_CTX macState, initialMacState;
	} MAC_STATE;

/****************************************************************************
*																			*
*						HMAC-RIPEMD-160 Self-test Routines					*
*																			*
****************************************************************************/

/* Test the HMAC-RIPEMD-160 output against the test vectors given in ???? */

static const FAR_BSS struct {
	const char *key;							/* HMAC key */
	const int keyLength;						/* Length of key */
	const char *data;							/* Data to hash */
	const int length;							/* Length of data */
	const BYTE digest[ RIPEMD160_DIGEST_LENGTH ];	/* Digest of data */
	} hmacValues[] = {
	/* No known test vectors for this algorithm */
	{ "", 0, NULL, 0, { 0 } }
	};

int hmacRIPEMD160SelfTest( void )
	{
	CONTEXT_INFO contextInfoPtr;
	MAC_INFO macInfo;
	MAC_STATE macState;
	int i;

	/* Set up the dummy contextInfoPtr structure */
	memset( &contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	memset( &macInfo, 0, sizeof( MAC_INFO ) );
	contextInfoPtr.ctxMAC = &macInfo;
	contextInfoPtr.ctxMAC->macInfo = &macState;

	/* Test HMAC-RIPEMD-160 against the test vectors given in RFC ???? */
	for( i = 0; hmacValues[ i ].data != NULL; i++ )
		{
		/* Load the HMAC key and perform the hashing */
		hmacRIPEMD160InitKey( &contextInfoPtr, hmacValues[ i ].key,
							  hmacValues[ i ].keyLength );
		contextInfoPtr.flags |= CONTEXT_HASH_INITED;
		hmacRIPEMD160Hash( &contextInfoPtr, ( BYTE * ) hmacValues[ i ].data,
						   hmacValues[ i ].length );
		hmacRIPEMD160Hash( &contextInfoPtr, NULL, 0 );
		contextInfoPtr.flags = 0;

		/* Retrieve the hash and make sure it matches the expected value */
		if( memcmp( contextInfoPtr.ctxMAC->mac, hmacValues[ i ].digest,
					RIPEMD160_DIGEST_LENGTH ) )
			break;
		}

	return( ( hmacValues[ i ].data == NULL ) ? \
			CRYPT_OK : CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

int hmacRIPEMD160GetInfo( const CAPABILITY_INFO_TYPE type, 
						  void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( sizeof( MAC_STATE ) );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							HMAC-RIPEMD-160 Hash Routines					*
*																			*
****************************************************************************/

/* Hash data using HMAC-RIPEMD-160 */

int hmacRIPEMD160Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	RIPEMD160_CTX *ripemdInfo = &( ( MAC_STATE * ) macInfo->macInfo )->macState;

	/* If the hash state was reset to allow another round of MAC'ing, copy 
	   the initial MAC state over into the current MAC state */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		{
		MAC_STATE *macState = macInfo->macInfo;

		memcpy( &macState->macState, &macState->initialMacState, 
				sizeof( RIPEMD160_CTX ) );
		}

	if( noBytes > 0 )
		RIPEMD160_Update( ripemdInfo, buffer, noBytes );
	else
		{
		BYTE hashBuffer[ RIPEMD160_CBLOCK ], digestBuffer[ RIPEMD160_DIGEST_LENGTH ];
		int i;

		/* Complete the inner hash and extract the digest */
		RIPEMD160_Final( digestBuffer, ripemdInfo );

		/* Perform the of the outer hash using the zero-padded key XOR'd
		   with the opad value followed by the digest from the inner hash */
		memset( hashBuffer, HMAC_OPAD, RIPEMD160_CBLOCK );
		memcpy( hashBuffer, macInfo->userKey,
				macInfo->userKeyLength );
		for( i = 0; i < macInfo->userKeyLength; i++ )
			hashBuffer[ i ] ^= HMAC_OPAD;
		RIPEMD160_Init( ripemdInfo );
		RIPEMD160_Update( ripemdInfo, hashBuffer, RIPEMD160_CBLOCK );
		memset( hashBuffer, 0, RIPEMD160_CBLOCK );
		RIPEMD160_Update( ripemdInfo, digestBuffer, RIPEMD160_DIGEST_LENGTH );
		memset( digestBuffer, 0, RIPEMD160_DIGEST_LENGTH );
		RIPEMD160_Final( macInfo->mac, ripemdInfo );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						HMAC-RIPEMD-160 Key Management Routines				*
*																			*
****************************************************************************/

/* Set up an HMAC-RIPEMD-160 key */

int hmacRIPEMD160InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
						  const int keyLength )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	RIPEMD160_CTX *ripemdInfo = &( ( MAC_STATE * ) macInfo->macInfo )->macState;
	BYTE hashBuffer[ RIPEMD160_CBLOCK ];
	int i;

	RIPEMD160_Init( ripemdInfo );

	/* If the key size is larger than tha RIPEMD-160 data size, reduce it to
	   the RIPEMD-160 hash size before processing it (yuck.  You're required
	   to do this though) */
	if( keyLength > RIPEMD160_CBLOCK )
		{
		/* Hash the user key down to the hash size (RIPEMD160_Init() has
		   already been called when the context was created) */
		RIPEMD160_Update( ripemdInfo, ( BYTE * ) key, keyLength );
		RIPEMD160_Final( macInfo->userKey, ripemdInfo );
		macInfo->userKeyLength = RIPEMD160_DIGEST_LENGTH;

		/* Reset the RIPEMD-160 state */
		RIPEMD160_Init( ripemdInfo );
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( macInfo->userKey, key, keyLength );
		macInfo->userKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, RIPEMD160_CBLOCK );
	memcpy( hashBuffer, macInfo->userKey,
			macInfo->userKeyLength );
	for( i = 0; i < macInfo->userKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_IPAD;
	RIPEMD160_Update( ripemdInfo, hashBuffer, RIPEMD160_CBLOCK );
	memset( hashBuffer, 0, RIPEMD160_CBLOCK );

	/* Save a copy of the initial state in case it's needed later */
	memcpy( &( ( MAC_STATE * ) macInfo->macInfo )->initialMacState, ripemdInfo, 
			sizeof( RIPEMD160_CTX ) );

	return( CRYPT_OK );
	}
#endif /* USE_HMAC_RIPEMD160 */
