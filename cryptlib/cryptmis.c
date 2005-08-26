/****************************************************************************
*																			*
*							cryptlib Misc Routines							*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "md2.h"
  #include "md5.h"
  #include "ripemd.h"
  #include "sha.h"
  #ifdef USE_SHA2
	#include "sha2.h"
  #endif /* USE_SHA2 */
  #include "stream.h"
#else
  #include "crypt/md2.h"
  #include "crypt/md5.h"
  #include "crypt/ripemd.h"
  #include "crypt/sha.h"
  #ifdef USE_SHA2
	#include "crypt/sha2.h"
  #endif /* USE_SHA2 */
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Get the system time safely.  The first function implements hard failures,
   converting invalid time values to zero, which yield a warning date of
   1/1/1970 rather than an out-of-bounds value or garbage value.  The second
   function implements soft failures, returning an estimate of the
   approximate current date.  The third function is used for operations such 
   as signing certs and timestamping and tries to get the time from a 
   hardware time source if one is available */

time_t getTime( void )
	{
	const time_t theTime = time( NULL );

	return( ( theTime < MIN_TIME_VALUE ) ? 0 : theTime );
	}

time_t getApproxTime( void )
	{
	const time_t theTime = time( NULL );

	return( ( theTime < MIN_TIME_VALUE ) ? CURRENT_TIME_VALUE : theTime );
	}

time_t getReliableTime( const CRYPT_HANDLE cryptHandle )
	{
	CRYPT_DEVICE cryptDevice;
	RESOURCE_DATA msgData;
	time_t theTime;
	int status;

	/* Get the dependent device for the object that needs the time */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT, 
							  &cryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		cryptDevice = SYSTEM_OBJECT_HANDLE;

	/* Try and get the time from the device */
	setMessageData( &msgData, &theTime, sizeof( time_t ) );
	status = krnlSendMessage( cryptDevice, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TIME );
	if( cryptStatusError( status ) && cryptDevice != SYSTEM_OBJECT_HANDLE )
		/* We couldn't get the time from a crypto token, fall back to the
		   system device */
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_TIME );
	if( cryptStatusError( status ) )
		return( 0 );
	return( ( theTime < MIN_TIME_VALUE ) ? 0 : theTime );
	}

/* Calculate a 16-bit Fletcher-like checksum of a block of data.  This isn't 
   quite a pure Fletcher checksum because we don't bother keeping the 
   accumulators at 8 bits, and also don't need to set the initial value to 
   nonzero since we'll never see a sequence of zero bytes.  This isn't a big
   deal since all we need is a consistent result.  In addition we don't 
   bother with masking to 16 bits during the calculation since it's not 
   being used as a true checksum */

int checksumData( const void *data, const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	assert( isReadPtr( data, dataLength ) );

	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

/* Determine the parameters for a particular hash algorithm */

void md2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer,
					const BYTE *inBuffer, const int length,
					const HASH_STATE hashState );
void md5HashBuffer( HASHINFO hashInfo, BYTE *outBuffer,
					const BYTE *inBuffer, const int length,
					const HASH_STATE hashState );
void ripemd160HashBuffer( HASHINFO hashInfo, BYTE *outBuffer,
						  const BYTE *inBuffer, const int length,
						  const HASH_STATE hashState );
void shaHashBuffer( HASHINFO hashInfo, BYTE *outBuffer,
					const BYTE *inBuffer, const int length,
					const HASH_STATE hashState );
void sha2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer,
					 const BYTE *inBuffer, const int length,
					 const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashSize )
	{
	assert( isWritePtr( hashFunction, sizeof( HASHFUNCTION ) ) );
	assert( ( hashSize == NULL ) || isWritePtr( hashSize, sizeof( int ) ) );

	switch( hashAlgorithm )
		{
#ifdef USE_MD2
		case CRYPT_ALGO_MD2:
			*hashFunction = md2HashBuffer;
			if( hashSize != NULL )
				*hashSize = MD2_DIGEST_LENGTH;
			return;
#endif /* USE_MD2 */

		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			if( hashSize != NULL )
				*hashSize = MD5_DIGEST_LENGTH;
			return;

#ifdef USE_RIPEMD160
		case CRYPT_ALGO_RIPEMD160:
			*hashFunction = ripemd160HashBuffer;
			if( hashSize != NULL )
				*hashSize = RIPEMD160_DIGEST_LENGTH;
			return;
#endif /* USE_RIPEMD160 */

		case CRYPT_ALGO_SHA:
			*hashFunction = shaHashBuffer;
			if( hashSize != NULL )
				*hashSize = SHA_DIGEST_LENGTH;
			return;

#ifdef USE_SHA2
		case CRYPT_ALGO_SHA2:
			*hashFunction = sha2HashBuffer;
			if( hashSize != NULL )
				*hashSize = SHA256_DIGEST_SIZE;
			return;
#endif /* USE_SHA2 */
		}

	/* Make sure that we always get some sort of hash function rather than
	   just dying.  This code always works because the internal self-test
	   has confirmed the availability and functioning of SHA-1 on startup */
	*hashFunction = shaHashBuffer;
	if( hashSize != NULL )
		*hashSize = SHA_DIGEST_LENGTH;
	assert( NOTREACHED );
	}

/* Perform the FIPS-140 statistical checks that are feasible on a byte
   string.  The full suite of tests assumes that an infinite source of 
   values (and time) is available, the following is a scaled-down version 
   used to sanity-check keys and other short random data blocks.  Note that 
   this check requires at least 64 bits of data in order to produce useful 
   results */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength )
	{
	const int delta = ( dataLength < 16 ) ? 1 : 0;
	int bitCount[ 4 ] = { 0 }, noOnes, i;

	assert( isReadPtr( data, dataLength ) );
	assert( dataLength >= 8 );

	for( i = 0; i < dataLength; i++ )
		{
		const int value = data[ i ];

		bitCount[ value & 3 ]++;
		bitCount[ ( value >> 2 ) & 3 ]++;
		bitCount[ ( value >> 4 ) & 3 ]++;
		bitCount[ value >> 6 ]++;
		}

	/* Monobit test: Make sure that at least 1/4 of the bits are ones and 1/4
	   are zeroes */
	noOnes = bitCount[ 1 ] + bitCount[ 2 ] + ( 2 * bitCount[ 3 ] );
	if( noOnes < dataLength * 2 || noOnes > dataLength * 6 )
		return( FALSE );

	/* Poker test (almost): Make sure that each bit pair is present at least
	   1/16 of the time.  The FIPS 140 version uses 4-bit values, but the
	   numer of samples available from the keys is far too small for this.

	   This isn't precisely 1/16, for short samples (< 128 bits) we adjust
	   the count by one because of the small sample size, and for odd-length
	   data we're getting four more samples so the actual figure is slightly
	   less than 1/16 */
	if( ( bitCount[ 0 ] + delta < dataLength / 2 ) || \
		( bitCount[ 1 ] + delta < dataLength / 2 ) || \
		( bitCount[ 2 ] + delta < dataLength / 2 ) || \
		( bitCount[ 3 ] + delta < dataLength / 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics (these will already have been done by
   the caller, this is just a backup check) */

int attributeCopy( RESOURCE_DATA *msgData, const void *attribute,
				   const int attributeLength )
	{
	assert( isWritePtr( msgData, sizeof( RESOURCE_DATA ) ) );

	if( attributeLength <= 0 )
		{
		msgData->length = 0;
		return( CRYPT_ERROR_NOTFOUND );
		}
	if( msgData->data != NULL )
		{
		assert( isReadPtr( attribute, attributeLength ) );

		if( attributeLength > msgData->length || \
			!isWritePtr( msgData->data, attributeLength ) )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( msgData->data, attribute, attributeLength );
		}
	msgData->length = attributeLength;

	return( CRYPT_OK );
	}

/* Check whether a given algorithm is available */

BOOLEAN algoAvailable( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO queryInfo;

	return( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
									cryptAlgo ) ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*						Dynamic Buffer Management Routines					*
*																			*
****************************************************************************/

/* Dynamic buffer management functions.  When reading variable-length
   attribute data we can usually fit the data in a small, fixed-length
   buffer, but occasionally we have to cope with larger data amounts that
   require a dynamically-allocated buffer.  The following routines manage
   this process, dynamically allocating and freeing a larger buffer if
   required */

int dynCreate( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
			   const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	RESOURCE_DATA msgData;
	const MESSAGE_TYPE message = \
						( attributeType == CRYPT_CERTFORMAT_CERTIFICATE ) ? \
						IMESSAGE_CRT_EXPORT : IMESSAGE_GETATTRIBUTE_S;
	void *dataPtr = NULL;
	int status;

	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( ( cryptHandle == CRYPT_UNUSED && \
			  attributeType == CRYPT_UNUSED ) || \
			( isHandleRangeValid( cryptHandle ) && \
			  ( isAttribute( attributeType ) || \
				isInternalAttribute( attributeType ) ) ) );

	/* Clear return value */
	dynBuf->data = dynBuf->dataBuffer;
	dynBuf->length = 0;

	/* If we're just creating a placeholder buffer, return now */
	if( cryptHandle == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Get the data from the object */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, message, &msgData,
							  attributeType );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > DYNBUF_SIZE )
		{
		/* The data is larger than the built-in buffer size, dynamically
		   allocate a larger buffer */
		if( ( dataPtr = clDynAlloc( "dynCreate", msgData.length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		msgData.data = dataPtr;
		status = krnlSendMessage( cryptHandle, message, &msgData, 
								  attributeType );
		if( cryptStatusError( status ) )
			{
			clFree( "dynCreate", dataPtr );
			return( status );
			}
		dynBuf->data = dataPtr;
		}
	else
		{
		/* The data will fit into the built-in buffer, read it directly into
		   the buffer */
		msgData.data = dynBuf->data;
		status = krnlSendMessage( cryptHandle, message, &msgData,
								  attributeType );
		if( cryptStatusError( status ) )
			return( status );
		}
	dynBuf->length = msgData.length;
	return( CRYPT_OK );
	}

void dynDestroy( DYNBUF *dynBuf )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( dynBuf->length == 0 || \
			isWritePtr( dynBuf->data, dynBuf->length ) );

	if( dynBuf->length <= 0 )
		return;
	zeroise( dynBuf->data, dynBuf->length );
	if( dynBuf->data != dynBuf->dataBuffer )
		clFree( "dynDestroy", dynBuf->data );
	}

/****************************************************************************
*																			*
*								Memory Management Routines					*
*																			*
****************************************************************************/

/* Memory pool management functions.  When allocating many little blocks of 
   memory, especially in resource-constrained systems, it's better if we pre-
   allocate a small memory pool ourselves and grab chunks of it as required, 
   falling back to dynamically allocating memory later on if we exhaust the 
   pool.  The following functions implement the custom memory pool 
   management */

typedef struct {
	void *storage;					/* Memory pool */
	int storagePos, storageSize;	/* Current usage and total size of pool */
	} MEMPOOL_INFO;

void initMemPool( void *statePtr, void *memPool, const int memPoolSize )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( memPool, memPoolSize ) );

	memset( state, 0, sizeof( MEMPOOL_INFO ) );
	state->storage = memPool;
	state->storageSize = memPoolSize;
	}

void *getMemPool( void *statePtr, const int size )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;
	BYTE *allocPtr = state->storage;
	const int allocSize = roundUp( size, sizeof( int ) );

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	/* If we can't satisfy the request from the memory pool, we have to 
	   allocate it dynamically */
	if( state->storagePos + allocSize > state->storageSize )
		return( clDynAlloc( "getMemPool", size ) );
	
	/* We can satisfy the request from the pool */
	allocPtr += state->storagePos;
	state->storagePos += allocSize;
	return( allocPtr );
	}

void freeMemPool( void *statePtr, void *memblock )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	/* If the memory block is within the pool, there's nothing to do */
	if( memblock >= state->storage && \
		memblock < ( void * ) ( ( BYTE * ) state->storage + \
										   state->storageSize ) )
		return;

	/* It's outside the pool and therefore dynamically allocated, free it */
	clFree( "freeMemPool", memblock );
	}

/* Debugging malloc() that dumps memory usage diagnostics to stdout */

#ifdef CONFIG_DEBUG_MALLOC

#ifdef __WIN32__
  #include <direct.h>
#endif /* __WIN32__ */

static int clAllocIndex = 0;

void *clAllocFn( const char *fileName, const char *fnName, 
				 const int lineNo, size_t size )
	{
	char buffer[ 512 ];
	BYTE *memPtr;
	int length;

	/* Strip off the leading path components if we can to reduce the amount 
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		fileName += strlen( buffer ) + 1;	/* Skip leading path + '/' */
#endif /* __WIN32__ || __UNIX__ */

	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d - %d bytes.\n", clAllocIndex, size );
	if( ( memPtr = malloc( size + 4 ) ) == NULL )
		return( NULL );
	mputLong( memPtr, clAllocIndex );	/* Implicit memPtr += 4 */
	clAllocIndex++;
	return( memPtr );
	}

void clFreeFn( const char *fileName, const char *fnName, 
			   const int lineNo, void *memblock )
	{
	char buffer[ 512 ];
	BYTE *memPtr = ( BYTE * ) memblock - 4;
	int length, index;

	/* Strip off the leading path components if we can to reduce the amount 
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		fileName += strlen( buffer ) + 1;	/* Skip leading path + '/' */
#endif /* __WIN32__ || __UNIX__ */

	index = mgetLong( memPtr );
	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d.\n", index );
	free( memPtr - 4 );
	}
#endif /* CONFIG_DEBUG_MALLOC */

/****************************************************************************
*																			*
*							Stream Export/Import Routines					*
*																			*
****************************************************************************/

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream, however
   we can save some overhead by writing it directly to the stream's buffer */

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType,
							 const int attributeLength )
	{
	RESOURCE_DATA msgData;
	STREAM *stream = streamPtr;
	const int length = ( attributeLength == CRYPT_USE_DEFAULT ) ? \
					   sMemDataLeft( stream ) : attributeLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );
	assert( attributeLength == CRYPT_USE_DEFAULT || \
			( attributeLength >= 8 && attributeLength <= 16384 ) );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( sMemDataLeft( stream ) < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the attribute to the stream */
	setMessageData( &msgData, sMemBufPtr( stream ), length );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	RESOURCE_DATA msgData;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isHandleRangeValid( cryptCertificate ) );
	assert( certFormatType > CRYPT_CERTFORMAT_NONE && \
			certFormatType < CRYPT_CERTFORMAT_LAST );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( !sIsNullStream( stream ) && \
		sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the cert to the stream */
	setMessageData( &msgData, sMemBufPtr( stream ), sMemDataLeft( stream ) );
	status = krnlSendMessage( cryptCertificate, IMESSAGE_CRT_EXPORT,
							  &msgData, certFormatType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int importCertFromStream( void *streamPtr,
						  CRYPT_CERTIFICATE *cryptCertificate,
						  const int length,
						  const CRYPT_CERTTYPE_TYPE certType )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isWritePtr( cryptCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( length > 0 && length < INT_MAX );
	assert( ( certType > CRYPT_CERTTYPE_NONE && \
			  certType < CRYPT_CERTTYPE_LAST ) || \
			( certType == CERTFORMAT_CTL ) );

	/* Clear return value */
	*cryptCertificate = CRYPT_ERROR;

	/* Before we try the import, make sure that everything is OK with the
	   stream and parameters */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( length > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Import the cert from the stream */
	setMessageCreateObjectIndirectInfo( &createInfo, sMemBufPtr( stream ), 
										length, certType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = sSkip( stream, length );
		if( cryptStatusOK( status ) )
			*cryptCertificate = createInfo.cryptHandle;
		else
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	return( status );
	}

/****************************************************************************
*																			*
*					Attribute Location/Cursor Movement Routines				*
*																			*
****************************************************************************/

/* Find the start and end of an attribute group from an attribute within 
   the group */

void *attributeFindStart( const void *attributePtr, 
						  GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID;

	if( attributePtr == NULL )
		return( NULL );

	/* Move backwards until we find the start of the attribute */
	getAttrFunction( attributePtr, &groupID, NULL, NULL, ATTR_CURRENT );
	while( TRUE )
		{
		CRYPT_ATTRIBUTE_TYPE prevGroupID;
		const void *prevPtr;

		prevPtr = getAttrFunction( attributePtr, &prevGroupID, NULL, NULL, 
								   ATTR_PREV );
		if( prevPtr == NULL || prevGroupID != groupID )
			/* We've reached the start of the list or a different attribute 
			   group, this is the start of the current group */
			break;
		attributePtr = prevPtr;
		}

	return( ( void * ) attributePtr );
	}

void *attributeFindEnd( const void *attributePtr, 
						GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID;

	if( attributePtr == NULL )
		return( NULL );

	/* Move forwards until we're just before the start of the next 
	   attribute */
	getAttrFunction( attributePtr, &groupID, NULL, NULL, ATTR_CURRENT );
	while( TRUE )
		{
		CRYPT_ATTRIBUTE_TYPE nextGroupID;
		const void *nextPtr;

		nextPtr = getAttrFunction( attributePtr, &nextGroupID, NULL, NULL, 
								   ATTR_NEXT );
		if( nextPtr == NULL || nextGroupID != groupID )
			/* We've reached the end of the list or a different attribute 
			   group, this is the end of the current group */
			break;
		attributePtr = nextPtr;
		}

	return( ( void * ) attributePtr );
	}

/* Find an attribute in a list of attributes */

void *attributeFind( const void *attributePtr, 
					 GETATTRFUNCTION getAttrFunction,
					 const CRYPT_ATTRIBUTE_TYPE attributeID,
					 const CRYPT_ATTRIBUTE_TYPE instanceID )
	{
	CRYPT_ATTRIBUTE_TYPE currAttributeID, currInstanceID;

	if( attributePtr == NULL )
		return( NULL );

	/* Find the attribute in the list */
	getAttrFunction( attributePtr, NULL, &currAttributeID, NULL, 
					 ATTR_CURRENT );
	while( attributePtr != NULL && currAttributeID != attributeID )
		attributePtr = getAttrFunction( attributePtr, NULL, 
										&currAttributeID, NULL, 
										ATTR_NEXT );
	if( instanceID == CRYPT_ATTRIBUTE_NONE )
		/* We're not looking for a particular instance, we're done */
		return( ( void * ) attributePtr );

	/* Find the attribute instance */
	getAttrFunction( attributePtr, NULL, &currAttributeID, &currInstanceID, 
					 ATTR_CURRENT );
	while( attributePtr != NULL && currAttributeID == attributeID )
		{
		if( currInstanceID == instanceID )
			return( ( void * ) attributePtr );
		attributePtr = getAttrFunction( attributePtr, NULL, 
										&currAttributeID, &currInstanceID, 
										ATTR_NEXT );
		}
	return( NULL );
	}

/* Find the next instance of an attribute in an attribute group.  This is 
   used to step through multiple instances of an attribute, for example in
   a cert extension containing a SEQUENCE OF <attribute> */

void *attributeFindNextInstance( const void *attributePtr, 
								 GETATTRFUNCTION getAttrFunction )
	{
	CRYPT_ATTRIBUTE_TYPE groupID, attributeID;
	CRYPT_ATTRIBUTE_TYPE currGroupID, currAttributeID;

	if( attributePtr == NULL )
		return( NULL );

	/* Skip the current field */
	getAttrFunction( attributePtr, &groupID, &attributeID, NULL, 
					 ATTR_CURRENT );
	attributePtr = getAttrFunction( attributePtr, &currGroupID, 
									&currAttributeID, NULL, 
									ATTR_NEXT );

	/* Step through the remaining attributes in the group looking for
	   another occurrence of the current attribute */
	while( attributePtr != NULL && currGroupID == groupID )
		{
		if( currAttributeID == attributeID )
			return( ( void * ) attributePtr );
		attributePtr = getAttrFunction( attributePtr, &currGroupID, 
										&currAttributeID, NULL, 
										ATTR_NEXT );
		}

	/* We couldn't find another instance of the attribute in this group */
	return( NULL );
	}

/* Move the attribute cursor relative to the current cursor position */

const void *attributeMoveCursor( const void *currentCursor,
								 GETATTRFUNCTION getAttrFunction,
								 const CRYPT_ATTRIBUTE_TYPE attributeMoveType, 
								 const int cursorMoveType )
	{
	const void *newCursor = currentCursor, *lastCursor = NULL;
	const BOOLEAN absMove = ( cursorMoveType == CRYPT_CURSOR_FIRST || \
							  cursorMoveType == CRYPT_CURSOR_LAST ) ? \
							TRUE : FALSE;
	int count;

	assert( attributeMoveType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			attributeMoveType == CRYPT_ATTRIBUTE_CURRENT || \
			attributeMoveType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	assert( cursorMoveType <= CRYPT_CURSOR_FIRST && \
			cursorMoveType >= CRYPT_CURSOR_LAST );

	/* Positioning in null attribute lists is always unsuccessful */
	if( currentCursor == NULL )
		return( NULL );

	/* Set the amount that we want to move by based on the position code.  
	   This means that we can handle the movement in a simple while loop 
	   instead of having to special-case it for moves by one item */
	count = absMove ? INT_MAX : 1;

	/* Moving by attribute or attribute instance is relatively simple.  For 
	   attributes we move backwards or forwards until we either run out of 
	   attributes or the next attribute belongs to a different group.  For 
	   attribute instances we move similarly, except that we stop when we 
	   reach an attribute whose group type, attribute type, and instance 
	   type don't match the current one.  We have to explicitly keep track
	   of whether the cursor was successfully moved rather than checking
	   that it's value has changed because some object types maintain an
	   attribute-internal virtual cursor that can return the same attribute
	   pointer multiple times */
	if( attributeMoveType == CRYPT_ATTRIBUTE_CURRENT )
		{
		CRYPT_ATTRIBUTE_TYPE groupID;
		BOOLEAN cursorMoved = FALSE;

		getAttrFunction( currentCursor, &groupID, NULL, NULL, 
						 ATTR_CURRENT );
		if( cursorMoveType == CRYPT_CURSOR_FIRST || \
			cursorMoveType == CRYPT_CURSOR_PREVIOUS )
			{
			CRYPT_ATTRIBUTE_TYPE prevGroupID;
			const void *prevCursor;
			
			prevCursor = getAttrFunction( newCursor, &prevGroupID, NULL, 
										  NULL, ATTR_PREV );
			while( count-- > 0 && prevCursor != NULL && \
				   prevGroupID == groupID )
				{
				newCursor = prevCursor;
				prevCursor = getAttrFunction( newCursor, &prevGroupID, NULL, 
											  NULL, ATTR_PREV );
				cursorMoved = TRUE;
				}
			}
		else
			{
			CRYPT_ATTRIBUTE_TYPE nextGroupID;
			const void *nextCursor;

			nextCursor = getAttrFunction( newCursor, &nextGroupID, NULL, 
										  NULL, ATTR_NEXT );
			while( count-- > 0 && nextCursor != NULL && \
				   nextGroupID == groupID )
				{
				newCursor = nextCursor;
				nextCursor = getAttrFunction( newCursor, &nextGroupID, NULL, 
											  NULL, ATTR_NEXT );
				cursorMoved = TRUE;
				}
			}

		if( !absMove && !cursorMoved )
			return( NULL );
		return( newCursor );
		}
	if( attributeMoveType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE )
		{
		CRYPT_ATTRIBUTE_TYPE groupID, attributeID, instanceID;
		BOOLEAN cursorMoved = FALSE;

		getAttrFunction( currentCursor, &groupID, &attributeID, &instanceID, 
						 ATTR_CURRENT );
		if( cursorMoveType == CRYPT_CURSOR_FIRST || \
			cursorMoveType == CRYPT_CURSOR_PREVIOUS )
			{
			CRYPT_ATTRIBUTE_TYPE prevGroupID, prevAttrID, prevInstID;
			const void *prevCursor;

			prevCursor = getAttrFunction( newCursor, &prevGroupID, 
										  &prevAttrID, &prevInstID, 
										  ATTR_PREV );
			while( count-- > 0 && prevCursor != NULL && \
				   prevGroupID == groupID && prevAttrID == attributeID && \
				   prevInstID == instanceID )
				{
				newCursor = prevCursor;
				prevCursor = getAttrFunction( newCursor, &prevGroupID, 
											  &prevAttrID, &prevInstID, 
											  ATTR_PREV );
				cursorMoved = TRUE;
				}
			}
		else
			{
			CRYPT_ATTRIBUTE_TYPE nextGroupID, nextAttrID, nextInstID;
			const void *nextCursor;

			nextCursor = getAttrFunction( newCursor, &nextGroupID, 
										  &nextAttrID, &nextInstID, 
										  ATTR_NEXT );
			while( count-- > 0 && nextCursor != NULL && \
				   nextGroupID == groupID && nextAttrID == attributeID && \
				   nextInstID == instanceID )
				{
				newCursor = nextCursor;
				nextCursor = getAttrFunction( newCursor, &nextGroupID, 
											  &nextAttrID, &nextInstID, 
											  ATTR_NEXT );
				cursorMoved = TRUE;
				}
			}

		if( !absMove && !cursorMoved )
			return( NULL );
		return( newCursor );
		}

	/* Moving by attribute group is a bit more complex.  First we find the 
	   start or end of the current group.  Then we move to the start of the 
	   previous (via ATTR_PREV and attributeFindStart()), or start of the 
	   next (via ATTR_NEXT) group beyond that.  This has the effect of 
	   moving us from anywhere in the current group to the start of the 
	   preceding or following group.  Finally, we repeat this as required */
	while( count-- > 0 && newCursor != NULL )
		{
		lastCursor = newCursor;
		if( cursorMoveType == CRYPT_CURSOR_FIRST || \
			cursorMoveType == CRYPT_CURSOR_PREVIOUS )
			{
			/* Move from the start of the current group to the start of the
			   preceding group */
			newCursor = attributeFindStart( newCursor, getAttrFunction );
			newCursor = getAttrFunction( newCursor, NULL, NULL, NULL, 
										 ATTR_PREV );
			if( newCursor != NULL )
				newCursor = attributeFindStart( newCursor, getAttrFunction );
			}
		else
			{
			/* Move from the end of the current group to the start of the
			   next group */
			newCursor = attributeFindEnd( newCursor, getAttrFunction );
			newCursor = getAttrFunction( newCursor, NULL, NULL, NULL, 
										 ATTR_NEXT );
			}
		}
	assert( lastCursor != NULL );	/* We went through loop at least once */

	/* If the new cursor is NULL, we've reached the start or end of the 
	   attribute list */
	if( newCursor == NULL )
		/* If it's an absolute move we've reached our destination, otherwise
		   there's nowhere left to move to.  We move to the start of the 
		   first or last attribute that we got to before we ran out of 
		   attributes to make sure that we don't fall off the start/end of 
		   the list */
		return( absMove ? \
				attributeFindStart( lastCursor, getAttrFunction ) : NULL );

	/* We've found what we were looking for */
	return( newCursor );
	}

/****************************************************************************
*																			*
*							Enveloping Functions							*
*																			*
****************************************************************************/

/* General-purpose enveloping functions, used by various high-level
   protocols */

int envelopeWrap( const void *inData, const int inDataLength, void *outData,
				  int *outDataLength, const int outDataMaxLength,
				  const CRYPT_FORMAT_TYPE formatType,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_HANDLE iCryptKey )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength + 512 );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( contentType == CRYPT_CONTENT_NONE || \
			( contentType > CRYPT_CONTENT_NONE && \
			  contentType < CRYPT_CONTENT_LAST ) );
	assert( ( iCryptKey == CRYPT_UNUSED ) || \
			isHandleRangeValid( iCryptKey ) );

	*outDataLength = 0;

	/* Create an envelope to wrap the data, add the encryption key if
	   necessary, and pop the wrapped result */
	setMessageCreateObjectInfo( &createInfo, formatType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &inDataLength,
							  CRYPT_ENVINFO_DATASIZE );
	if( cryptStatusOK( status ) && contentType != CRYPT_CONTENT_NONE )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &contentType,
								  CRYPT_ENVINFO_CONTENTTYPE );
	if( cryptStatusOK( status ) && iCryptKey != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iCryptKey,
								  CRYPT_ENVINFO_PUBLICKEY );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) inData, inDataLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

int envelopeUnwrap( const void *inData, const int inDataLength,
					void *outData, int *outDataLength,
					const int outDataMaxLength,
					const CRYPT_CONTEXT iDecryptKey )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( ( iDecryptKey == CRYPT_UNUSED ) || \
			isHandleRangeValid( iDecryptKey ) );

	*outDataLength = 0;

	/* Create an envelope to unwrap the data, add the decryption key if
	   necessary, and pop the unwrapped result */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	setMessageData( &msgData, ( void * ) inData, inDataLength );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( status == CRYPT_ENVELOPE_RESOURCE )
		{
		/* If the caller wasn't expecting encrypted data, let them know */
		if( iDecryptKey == CRYPT_UNUSED )
			status = CRYPT_ERROR_WRONGKEY;
		else
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
									  ( void * ) &iDecryptKey,
									  CRYPT_ENVINFO_PRIVATEKEY );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		}

	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

int envelopeSign( const void *inData, const int inDataLength,
				  void *outData, int *outDataLength,
				  const int outDataMaxLength,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_CONTEXT iSigKey,
				  const CRYPT_CERTIFICATE iCmsAttributes )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength + 1024 );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 || \
			( contentType == CRYPT_CONTENT_NONE && \
			  isHandleRangeValid( iCmsAttributes ) && \
			  inDataLength == 0 ) );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( contentType >= CRYPT_CONTENT_NONE && \
			contentType < CRYPT_CONTENT_LAST );
	assert( isHandleRangeValid( iSigKey ) );
	assert( iCmsAttributes == CRYPT_UNUSED || \
			isHandleRangeValid( iCmsAttributes ) );

	*outDataLength = 0;

	/* Create an envelope to sign the data, add the signature key and
	   optional signing attributes, and pop the signed result */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_CMS );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &inDataLength,
							  CRYPT_ENVINFO_DATASIZE );
	if( cryptStatusOK( status ) && contentType != CRYPT_CONTENT_NONE )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &contentType,
								  CRYPT_ENVINFO_CONTENTTYPE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iSigKey,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) && iCmsAttributes != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iCmsAttributes,
								  CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
	if( cryptStatusOK( status ) )
		{
		/* If there's no data supplied, it's an attributes-only message
		   containing only authenticated attributes */
		if( inDataLength <= 0 )
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE,
									  CRYPT_IATTRIBUTE_ATTRONLY );
		else
			{
			setMessageData( &msgData, ( void * ) inData, inDataLength );
			status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
									  &msgData, 0 );
			}
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

int envelopeSigCheck( const void *inData, const int inDataLength,
					  void *outData, int *outDataLength,
					  const int outDataMaxLength,
					  const CRYPT_CONTEXT iSigCheckKey,
					  int *sigResult, CRYPT_CERTIFICATE *iSigningCert,
					  CRYPT_CERTIFICATE *iCmsAttributes )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	const int minBufferSize = max( MIN_BUFFER_SIZE, inDataLength );
	int status;

	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 16 );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( iSigCheckKey == CRYPT_UNUSED || \
			isHandleRangeValid( iSigCheckKey ) );
	assert( isWritePtr( sigResult, sizeof( int ) ) );

	/* Clear return values */
	*outDataLength = 0;
	*sigResult = CRYPT_ERROR;
	if( iSigningCert != NULL )
		*iSigningCert = CRYPT_ERROR;
	if( iCmsAttributes != NULL )
		*iCmsAttributes = CRYPT_ERROR;

	/* Create an envelope to sig.check the data, push in the signed data and
	   sig.check key, and pop the result.  We also speculatively set the
	   attributes-only flag to let the enveloping code know that a signed
	   message with no content is a zero-data-length message rather than a
	   detached signature, which is what this type of message would normally
	   be */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEnvelope = createInfo.cryptHandle;
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_ATTRONLY );
	setMessageData( &msgData, ( void * ) inData, inDataLength );
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) && iSigCheckKey != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &iSigCheckKey,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
								  sigResult, CRYPT_ENVINFO_SIGNATURE_RESULT );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, outData, outDataMaxLength );
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_ENV_POPDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) && iSigningCert != NULL )
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
								  iSigningCert,
								  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusOK( status ) && iCmsAttributes != NULL )
		{
		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_GETATTRIBUTE,
								  iCmsAttributes,
								  CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
		if( cryptStatusError( status ) && iSigningCert != NULL )
			{
			krnlSendNotifier( *iSigningCert, IMESSAGE_DECREFCOUNT );
			*iSigningCert = CRYPT_ERROR;
			}
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

/****************************************************************************
*																			*
*							Safe Text-line Read Functions					*
*																			*
****************************************************************************/

/* Process a MIME header line.  When we read data we're mostly looking for
   the EOL marker.  If we find more data than will fit in the input buffer,
   we discard it until we find an EOL.  As a secondary concern, we want to
   strip leading, trailing, and repeated whitespace.  We handle the former
   by setting the seen-whitespace flag to true initially, this treats any
   whitespace at the start of the line as superfluous and strips it.  We 
   also handle continued lines, denoted by a semicolon or occasionally a 
   backslash as the last non-whitespace character.  Stripping of repeated 
   whitespace is also handled by the seenWhitespace flag, stripping of 
   trailing whitespace is handled by walking back through any final 
   whitespace once we see the EOL, and continued lines are handled by 
   setting the seenContinuation flag if we see a semicolon or backslash as 
   the last non-whitespace character.

   Finally, we also need to handle generic DoS attacks.  If we see more than
   10K chars in a line, we bail out */

typedef struct {
	BOOLEAN seenWhitespace, seenContinuation;
	int totalChars, maxSize, bufPos;
	} MIME_STATE_INFO;

/* Initialise the MIME line buffer state.  We set the seen-whitespace flag
   initially to strip leading whitespace */

void initMIMEstate( MIME_STATE *mimeState, const int maxSize )
	{
	MIME_STATE_INFO *state = ( MIME_STATE_INFO * ) mimeState;

	assert( isWritePtr( state, sizeof( MIME_STATE_INFO ) ) );
	assert( sizeof( MIME_STATE_INFO ) <= sizeof( MIME_STATE ) );

	memset( state, 0, sizeof( MIME_STATE_INFO ) );
	state->seenWhitespace = TRUE;	/* Catch leading whitespace */
	state->maxSize = maxSize;
	}

/* Add a character to the line buffer with special-case MIME-specific
   processing */

int addMIMEchar( MIME_STATE *mimeState, char *buffer, int ch )
	{
	MIME_STATE_INFO *state = ( MIME_STATE_INFO * ) mimeState;

	assert( isWritePtr( state, sizeof( MIME_STATE_INFO ) ) );
	assert( buffer != NULL );

	/* Don't try and process excessively long inputs, which are probably
	   DoSes */
	if( state->totalChars++ > 10000 )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we're over the maximum buffer size, the only character we recognise
	   is EOL */
	if( ( state->bufPos > state->maxSize - 8 ) && ( ch != '\n' ) )
		return( CRYPT_OK );

	/* Process EOL */
	if( ch == '\n' )
		{
		/* Strip trailing whitespace.  At this point it's all been
		   canonicalised so we don't need to check for anything other than
		   spaces */
		while( state->bufPos > 0 && buffer[ state->bufPos - 1 ] == ' ' )
			state->bufPos--;

		/* If we've seen a continuation market as the last non-whitespace 
		   char, the line continues on the next one */
		if( state->seenContinuation )
			{
			state->seenContinuation = FALSE;
			return( CRYPT_OK );
			}

		/* We're done */
		buffer[ state->bufPos ] = '\0';
		return( OK_SPECIAL );
		}

	/* Process whitespace.  We can't use isspace() for this because it
	   includes all sorts of extra control characters */
	if( ch == ' ' || ch == '\t' )
		{
		if( state->seenWhitespace )
			/* Ignore leading and repeated whitespace */
			return( CRYPT_OK );
		ch = ' ';	/* Canonicalise whitespace */
		}

	/* Process any remaining chars */
	if( ch != '\r' )
		{
		if( !( isPrint( ch ) ) )
			return( CRYPT_ERROR_BADDATA );
		buffer[ state->bufPos++ ] = ch;
		state->seenWhitespace = ( ch == ' ' ) ? TRUE : FALSE;
		state->seenContinuation = ( ch == ';' || ch == '\\' || \
									( state->seenContinuation && \
									  state->seenWhitespace ) ) ? \
								  TRUE : FALSE;
		}

	return( CRYPT_OK );
	}

/* Wrap up the MIME line processing */

int endMIMEstate( MIME_STATE *mimeState )
	{
	MIME_STATE_INFO *state = ( MIME_STATE_INFO * ) mimeState;

	assert( isWritePtr( state, sizeof( MIME_STATE_INFO ) ) );

	return( state->bufPos );
	}
