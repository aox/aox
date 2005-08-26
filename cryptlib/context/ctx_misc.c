/****************************************************************************
*																			*
*						cryptlib Context Support Routines					*
*						Copyright Peter Gutmann 1995-2005					*
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

/* Prototypes for functions in keyload.c */

int getKeysize( CONTEXT_INFO *contextInfoPtr, const int requestedKeyLength );

/****************************************************************************
*																			*
*						Capability Management Functions						*
*																			*
****************************************************************************/

/* Check that a capability info record is consistent.  This is a complex
   function which is called from an assert() macro, so we only need to define
   it when we're building the debug version of the code */

#ifndef NDEBUG

BOOLEAN capabilityInfoOK( const CAPABILITY_INFO *capabilityInfoPtr,
						  const BOOLEAN asymmetricOK )
	{
	CRYPT_ALGO_TYPE cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* Check the algorithm and mode parameters */
	if( cryptAlgo <= CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST_MAC || \
		capabilityInfoPtr->algoName == NULL )
		return( FALSE );

	/* Make sure that the minimum functions are present */
	if( isStreamCipher( cryptAlgo ) )
		{
		if( capabilityInfoPtr->encryptOFBFunction == NULL || \
			capabilityInfoPtr->decryptOFBFunction == NULL )
			return( FALSE );
		}
	else
		if( asymmetricOK )
			{
			/* If asymmetric capabilities (e.g. decrypt but not encrypt,
			   present in some tinkertoy tokens) are OK, we only check
			   that there's at least one useful capability available */
			if( capabilityInfoPtr->decryptFunction == NULL && \
				capabilityInfoPtr->signFunction == NULL )
				return( FALSE );
			}
		else
			/* We need at least one mechanism pair to be able to do anything
			   useful with the capability */
			if( ( capabilityInfoPtr->encryptFunction == NULL || \
				  capabilityInfoPtr->decryptFunction == NULL ) && \
				( capabilityInfoPtr->encryptCBCFunction == NULL || \
				  capabilityInfoPtr->decryptCBCFunction == NULL ) && \
				( capabilityInfoPtr->encryptCFBFunction == NULL || \
				  capabilityInfoPtr->decryptCFBFunction == NULL ) && \
				( capabilityInfoPtr->encryptOFBFunction == NULL || \
				  capabilityInfoPtr->decryptOFBFunction == NULL ) && \
				( capabilityInfoPtr->signFunction == NULL || \
				  capabilityInfoPtr->sigCheckFunction == NULL ) )
				return( FALSE );

	/* Make sure that the algorithm/mode names will fit inside the query
	   information structure */
	if( strlen( capabilityInfoPtr->algoName ) > CRYPT_MAX_TEXTSIZE - 1 )
		return( FALSE );

	/* Make sure that the algorithm/mode-specific parameters are
	   consistent */
	if( capabilityInfoPtr->minKeySize > capabilityInfoPtr->keySize || \
		capabilityInfoPtr->maxKeySize < capabilityInfoPtr->keySize )
		return( FALSE );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 8 ) || \
        	  capabilityInfoPtr->blockSize > CRYPT_MAX_IVSIZE ) || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( MIN_KEYSIZE_BITS ) || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyParamsFunction == NULL || \
			capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		if( !isStreamCipher( cryptAlgo ) && \
			 capabilityInfoPtr->blockSize < bitsToBytes( 64 ) )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptCBCFunction != NULL && \
			  capabilityInfoPtr->decryptCBCFunction == NULL ) || \
			( capabilityInfoPtr->encryptCBCFunction == NULL && \
			  capabilityInfoPtr->decryptCBCFunction != NULL ) )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptCFBFunction != NULL && \
			  capabilityInfoPtr->decryptCFBFunction == NULL ) || \
			( capabilityInfoPtr->encryptCFBFunction == NULL && \
			  capabilityInfoPtr->decryptCFBFunction != NULL ) )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptOFBFunction != NULL && \
			  capabilityInfoPtr->decryptOFBFunction == NULL ) || \
			( capabilityInfoPtr->encryptOFBFunction == NULL && \
			  capabilityInfoPtr->decryptOFBFunction != NULL ) )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		if( capabilityInfoPtr->blockSize || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( MIN_PKCSIZE_BITS ) || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_PKCSIZE ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		cryptAlgo <= CRYPT_ALGO_LAST_HASH )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 128 ) || \
			  capabilityInfoPtr->blockSize > CRYPT_MAX_HASHSIZE ) || \
			( capabilityInfoPtr->minKeySize || capabilityInfoPtr->keySize || \
			  capabilityInfoPtr->maxKeySize ) )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
		cryptAlgo <= CRYPT_ALGO_LAST_MAC )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 128 ) || \
			  capabilityInfoPtr->blockSize > CRYPT_MAX_HASHSIZE ) || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( MIN_KEYSIZE_BITS ) || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		}

	return( TRUE );
	}
#endif /* !NDEBUG */

/* Get information from a capability record */

void getCapabilityInfo( CRYPT_QUERY_INFO *cryptQueryInfo,
						const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr )
	{
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
	strcpy( ( char * ) cryptQueryInfo->algoName, 
			capabilityInfoPtr->algoName );
	cryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfoPtr->minKeySize;
	cryptQueryInfo->keySize = capabilityInfoPtr->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfoPtr->maxKeySize;
	}

/* Find the capability record for a given encryption algorithm */

const CAPABILITY_INFO FAR_BSS *findCapabilityInfo(
					const CAPABILITY_INFO_LIST *capabilityInfoList,
					const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const CAPABILITY_INFO_LIST *capabilityInfoListPtr;

	/* Find the capability corresponding to the requested algorithm/mode */
	for( capabilityInfoListPtr = capabilityInfoList;
		 capabilityInfoListPtr != NULL;
		 capabilityInfoListPtr = capabilityInfoListPtr->next )
		if( capabilityInfoListPtr->info->cryptAlgo == cryptAlgo )
			return( capabilityInfoListPtr->info );

	return( NULL );
	}

/****************************************************************************
*																			*
*							Shared Context Functions						*
*																			*
****************************************************************************/

/* Default handler to get object subtype-specific information.  This 
   fallback function is called if the object-specific primary get-info 
   handler doesn't want to handle the query */

int getDefaultInfo( const CAPABILITY_INFO_TYPE type, 
					void *varParam, const int constParam )
	{
	switch( type )
		{
		case CAPABILITY_INFO_KEYSIZE:
			return( getKeysize( varParam, constParam ) );

		case CAPABILITY_INFO_STATESIZE:
			return( 0 );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Misc. Functions								*
*																			*
****************************************************************************/

/* Statically initialised a context used for the internal self-test */

void staticInitContext( CONTEXT_INFO *contextInfoPtr, 
						const CONTEXT_TYPE type, 
						const CAPABILITY_INFO *capabilityInfoPtr,
						void *contextData, const int contextDataSize,
						void *keyData )
	{
	memset( contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	memset( contextData, 0, contextDataSize );
	contextInfoPtr->capabilityInfo = capabilityInfoPtr;
	switch( type )
		{
		case CONTEXT_CONV:
			contextInfoPtr->ctxConv = ( CONV_INFO * ) contextData;
			contextInfoPtr->ctxConv->key = keyData;
			break;

		case CONTEXT_HASH:
			contextInfoPtr->ctxHash = ( HASH_INFO * ) contextData;
			contextInfoPtr->ctxHash->hashInfo = keyData;
			break;

		case CONTEXT_MAC:
			contextInfoPtr->ctxMAC = ( MAC_INFO * ) contextData;
			contextInfoPtr->ctxMAC->macInfo = keyData;
			break;

		case CONTEXT_PKC:
			contextInfoPtr->ctxPKC = ( PKC_INFO * ) contextInfoPtr->storage;
			break;

		default:
			assert( NOTREACHED );
		}
	}

void staticDestroyContext( CONTEXT_INFO *contextInfoPtr )
	{
	memset( contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	}
