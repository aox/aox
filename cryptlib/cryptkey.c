/****************************************************************************
*																			*
*							cryptlib Keying Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "context.h"
#else
  #include "misc/context.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in crypt.c */

int clearTempBignums( PKC_INFO *pkcInfo );

/****************************************************************************
*																			*
*								Key Load Functions							*
*																			*
****************************************************************************/

/* Check that user-supplied supplied PKC parameters make sense (algorithm-
   parameter-specific validity checks are performed at a lower level).  
   Although the checks are somewhat specific to particular PKC algorithm 
   classes, we have to do them at this point in order to avoid duplicating 
   them in every plug-in PKC module, and because strictly speaking it's the 
   job of the higher-level code to ensure that the lower-level routines at 
   least get fed approximately valid input */

#ifndef USE_FIPS140

static int checkPKCparams( const CRYPT_ALGO_TYPE cryptAlgo, 
						   const void *keyInfo )
	{
	const CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) keyInfo;

	/* The DLP check is simpler than the RSA one because there are less
	   odd parameter combinations possible, so we get this one out of the
	   way first */
	if( isDlpAlgo( cryptAlgo ) )
		{
		const CRYPT_PKCINFO_DLP *dlpKey = ( CRYPT_PKCINFO_DLP * ) keyInfo;

		/* Check the general and public components */
		if( ( dlpKey->isPublicKey != TRUE && dlpKey->isPublicKey != FALSE ) )
			return( CRYPT_ARGERROR_STR1 );
		if( dlpKey->pLen < MIN_PKCSIZE_BITS || \
			dlpKey->pLen > MAX_PKCSIZE_BITS || \
			dlpKey->qLen < 128 || dlpKey->qLen > MAX_PKCSIZE_BITS || \
			dlpKey->gLen < 2 || dlpKey->gLen > MAX_PKCSIZE_BITS || \
			dlpKey->yLen < 0 || dlpKey->yLen > MAX_PKCSIZE_BITS )
			/* y may be 0 if only x and the public params are available */
			return( CRYPT_ARGERROR_STR1 );
		if( dlpKey->isPublicKey )
			return( CRYPT_OK );

		/* Check the private components */
		if( dlpKey->xLen < 128 || dlpKey->xLen > MAX_PKCSIZE_BITS )
			return( CRYPT_ARGERROR_STR1 );
		return( CRYPT_OK );
		}

	/* Check the general and public components */
	if( rsaKey->isPublicKey != TRUE && rsaKey->isPublicKey != FALSE )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->nLen < MIN_PKCSIZE_BITS || \
		rsaKey->nLen > MAX_PKCSIZE_BITS || \
		rsaKey->eLen < 2 || rsaKey->eLen > MAX_PKCSIZE_BITS )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->isPublicKey )
		return( CRYPT_OK );

	/* Check the private components.  This can get somewhat complex, possible
	   combinations are:

		d, p, q
		d, p, q, u
		d, p, q, e1, e2, u
		   p, q, e1, e2, u

	   The reason for some of the odder combinations is because some 
	   implementations don't use all the values (for example d isn't needed at
	   all for the CRT shortcut) or recreate them when the key is loaded.  If 
	   only d, p, and q are present we recreate e1 and e2 from them, we also 
	   create u if necessary */
	if( rsaKey->pLen < ( MIN_PKCSIZE_BITS / 2 ) - 8 || \
		rsaKey->pLen > MAX_PKCSIZE_BITS || \
		rsaKey->qLen < ( MIN_PKCSIZE_BITS / 2 ) - 8 || \
		rsaKey->qLen > MAX_PKCSIZE_BITS )
		return( CRYPT_ARGERROR_STR1 );
	if( !rsaKey->dLen && !rsaKey->e1Len )
		/* Must have either d or e1 et al */
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->dLen && \
		( rsaKey->dLen < MIN_PKCSIZE_BITS || \
		  rsaKey->dLen > MAX_PKCSIZE_BITS ) )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->e1Len && \
		( rsaKey->e1Len < ( MIN_PKCSIZE_BITS / 2 ) - 8 || \
		  rsaKey->e1Len > MAX_PKCSIZE_BITS || \
		  rsaKey->e2Len < ( MIN_PKCSIZE_BITS / 2 ) - 8 || \
		  rsaKey->e2Len > MAX_PKCSIZE_BITS ) )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->uLen && \
		( rsaKey->uLen < ( MIN_PKCSIZE_BITS / 2 ) - 8 || \
		  rsaKey->uLen > MAX_PKCSIZE_BITS ) )
		return( CRYPT_ARGERROR_STR1 );
	return( CRYPT_OK );
	}
#endif /* USE_FIPS140 */

/* Load a key into a CONTEXT_INFO structure.  These functions are called by 
   the various higher-level functions that move a key into a context */

static int loadKeyConvFunction( CONTEXT_INFO *contextInfoPtr, BYTE *key, 
								const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;

	assert( contextInfoPtr->type == CONTEXT_CONV );

	/* If we don't need an IV, record it as being set */
	if( !needsIV( contextInfoPtr->ctxConv->mode ) || \
		isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
		contextInfoPtr->flags |= CONTEXT_IV_SET;

	/* Perform the key setup */
	return( capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, 
												keyLength ) );
	}

static int loadKeyPKCFunction( CONTEXT_INFO *contextInfoPtr, BYTE *key, 
							   const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	int status;

	assert( contextInfoPtr->type == CONTEXT_PKC );

#ifndef USE_FIPS140
	/* If we're loading from externally-supplied parameters, make sure that 
	   the parameters make sense */
	if( key != NULL )
		{
		status = checkPKCparams( capabilityInfoPtr->cryptAlgo, key );
		if( cryptStatusError( status ) )
			return( status );
		contextInfoPtr->flags |= 0x10;	/* Tell lib_kg to check params too */
		}
#endif /* USE_FIPS140 */

	/* Load the keying info */
	status = capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, 
												 keyLength );
	clearTempBignums( contextInfoPtr->ctxPKC );
	return( status );
	}

static int loadKeyMacFunction( CONTEXT_INFO *contextInfoPtr, BYTE *key, 
							   const int keyLength )
	{
	assert( contextInfoPtr->type == CONTEXT_MAC );

	return( contextInfoPtr->capabilityInfo->initKeyFunction( contextInfoPtr, 
															 key, keyLength ) );
	}

/****************************************************************************
*																			*
*							Key Generation Functions						*
*																			*
****************************************************************************/

/* Threaded key generation for those OSes that support threads.  The
   following function *must* be called as a thread */

#ifdef USE_THREADS

THREADFUNC_DEFINE( threadKeygen, ptr )
	{
	CONTEXT_INFO *contextInfoPtr = ( CONTEXT_INFO * ) ptr;
	int busyStatus = CRYPT_ERROR_TIMEOUT;

	/* Mark the object as busy, perform the keygen, and set it back to non-
	   busy */
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
					 &busyStatus, CRYPT_IATTRIBUTE_STATUS );
	contextInfoPtr->asyncStatus = \
		contextInfoPtr->capabilityInfo->generateKeyFunction( contextInfoPtr,
										contextInfoPtr->ctxPKC->keySizeBits );
	if( cryptStatusOK( contextInfoPtr->asyncStatus ) )
		contextInfoPtr->flags |= CONTEXT_KEY_SET;	/* There's now a key loaded */
	contextInfoPtr->flags &= ~CONTEXT_ASYNC_ABORT;
	contextInfoPtr->flags |= CONTEXT_ASYNC_DONE;
	clearTempBignums( contextInfoPtr->ctxPKC );
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	THREAD_EXIT();
	}
#endif /* Threaded keygen function */

/* Generate a key into a CONTEXT_INFO structure.  This low-level function is
   called by both the normal and async keygen functions, which set the keygen
   up as required (the only time there's any real difference is for PKC
   keygen) */

static int generateKeyConvFunction( CONTEXT_INFO *contextInfoPtr, 
									const BOOLEAN isAsync )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	RESOURCE_DATA msgData;
	int keyLength, status;

	assert( contextInfoPtr->type == CONTEXT_CONV );

	/* Determine the best keysize for this algorithm */
	keyLength = capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE, 
									contextInfoPtr,
									contextInfoPtr->ctxConv->userKeyLength );
	if( cryptStatusError( keyLength ) )
		return( keyLength );

	/* If the context is implemented in a crypto device, it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );

	/* Generate a random session key into the context.  We always use
	   synchronous key generation even if the user has called the async
	   function because it's quick enough that it doesn't make any
	   difference.  In addition we load the random data directly into the
	   pagelocked encryption context and pass that in as the key buffer -
	   loadKey() won't copy the data if src == dest */
	setMessageData( &msgData, contextInfoPtr->ctxConv->userKey, keyLength );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	return( contextInfoPtr->loadKeyFunction( contextInfoPtr, 
								contextInfoPtr->ctxConv->userKey, keyLength ) );
	}

static int generateKeyPKCFunction( CONTEXT_INFO *contextInfoPtr, 
								   const BOOLEAN isAsync )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	int keyLength, status;
#ifdef USE_THREADS
	THREAD_HANDLE thread;
	THREAD_CREATE_VARS;
#endif /* OS's with threads */

	assert( contextInfoPtr->type == CONTEXT_PKC );

	/* Set up supplementary key information */
	contextInfoPtr->ctxPKC->pgpCreationTime = getApproxTime();

	/* Determine the best keysize for this algorithm */
	keyLength = capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE, 
						contextInfoPtr,
						bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits ) );
	if( cryptStatusError( keyLength ) )
		return( keyLength );

	/* Generate the key into the context if it's a synchronous operation or
	   if the OS doesn't support threads */
#ifdef USE_THREADS
	if( !isAsync )
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );

	/* It's an async keygen, set the context state for the async keygen and 
	   spawn the thread/process */
	contextInfoPtr->flags &= ~( CONTEXT_ASYNC_ABORT | CONTEXT_ASYNC_DONE );
	contextInfoPtr->asyncStatus = CRYPT_OK;
	contextInfoPtr->ctxPKC->keySizeBits = bytesToBits( keyLength );
	status = THREAD_CREATE( threadKeygen, contextInfoPtr, thread );
	return( cryptStatusOK( status ) ? OK_SPECIAL : status );
#else
	status = capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) );
	clearTempBignums( &contextInfoPtr->ctxPKC );
	return( status );
#endif /* OS's with threads */
	}

static int generateKeyMacFunction( CONTEXT_INFO *contextInfoPtr, 
								   const BOOLEAN isAsync )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = contextInfoPtr->capabilityInfo;
	RESOURCE_DATA msgData;
	int keyLength, status;

	assert( contextInfoPtr->type == CONTEXT_MAC );

	/* Determine the best keysize for this algorithm */
	keyLength = capabilityInfoPtr->getInfoFunction( CAPABILITY_INFO_KEYSIZE, 
									contextInfoPtr,
									contextInfoPtr->ctxMAC->userKeyLength );
	if( cryptStatusError( keyLength ) )
		return( keyLength );

	/* If the context is implemented in a crypto device, it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );

	/* Generate a random session key into the context.  We always use
	   synchronous key generation even if the user has called the async
	   function because it's quick enough that it doesn't make any
	   difference.  In addition we load the random data directly into the
	   pagelocked encryption context and pass that in as the key buffer -
	   loadKey() won't copy the data if src == dest */
	setMessageData( &msgData, contextInfoPtr->ctxMAC->userKey, keyLength );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	return( contextInfoPtr->loadKeyFunction( contextInfoPtr, 
								contextInfoPtr->ctxMAC->userKey, keyLength ) );
	}

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

void initKeyHandling( CONTEXT_INFO *contextInfoPtr )
	{
	/* Set the access method pointers */
	switch( contextInfoPtr->type )
		{
		case CONTEXT_CONV:
			contextInfoPtr->loadKeyFunction = loadKeyConvFunction;
			contextInfoPtr->generateKeyFunction = generateKeyConvFunction;
			break;

		case CONTEXT_PKC:
			contextInfoPtr->loadKeyFunction = loadKeyPKCFunction;
			contextInfoPtr->generateKeyFunction = generateKeyPKCFunction;
			break;

		case CONTEXT_MAC:
			contextInfoPtr->loadKeyFunction = loadKeyMacFunction;
			contextInfoPtr->generateKeyFunction = generateKeyMacFunction;
			break;

		default:
			assert( NOTREACHED );
		}
	}
