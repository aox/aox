/****************************************************************************
*																			*
*							cryptlib Misc Routines							*
*						Copyright Peter Gutmann 1992-2003					*
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
  #include "misc/stream.h"
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

/* Calculate a 16-bit Fletcher-like checksum of a block of data.  We don't
   bother with masking to 16 bits since it's not being used as a true
   checksum */

int checksumData( const void *data, const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

/* Determine the parameters for a particular hash algorithm */

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashSize )
	{
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
   string.  The full suite of tests assumes an infinite source of values (and
   time) is available, the following is a scaled-down version used to sanity-
   check keys and other short random data blocks.  Note that this check
   requires at least 64 bits of data in order to produce useful results */

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

	if( attributeLength == 0 )
		{
		msgData->length = 0;
		return( CRYPT_ERROR_NOTFOUND );
		}
	if( msgData->data != NULL )
		{
		assert( attribute != NULL );
		assert( attributeLength > 0 );

		if( attributeLength > msgData->length || \
			checkBadPtrWrite( msgData->data, attributeLength ) )
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

	assert( isWritePtr( dynBuf, DYNBUF ) );
	assert( ( cryptHandle == CRYPT_UNUSED && \
			  attributeType == CRYPT_UNUSED ) || \
			( checkHandleRange( cryptHandle ) && \
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
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, attributeType );
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
	assert( isWritePtr( dynBuf, DYNBUF ) );
	assert( dynBuf->length == 0 || \
			isWritePtr( dynBuf->data, dynBuf->length ) );

	if( dynBuf->length <= 0 )
		return;
	zeroise( dynBuf->data, dynBuf->length );
	if( dynBuf->data != dynBuf->dataBuffer )
		clFree( "dynDestroy", dynBuf->data );
	}

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
	if( state->storageSize - state->storagePos < allocSize )
		return( clDynAlloc( "getMemPool", size ) );
	
	/* We can satisfy the request from the pool */
	allocPtr += state->storagePos;
	state->storagePos += size;
	return( allocPtr );
	}

void freeMemPool( void *statePtr, void *memblock )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	/* If the memory block is within the pool, there's nothing to do */
	if( memblock >= state->storage && \
		memblock <= ( void * ) ( ( BYTE * ) state->storage + \
											state->storageSize ) )
		return;

	/* It's outside the pool and therefore dynamically allocated, free it */
	clFree( "freeMemPool", memblock );
	}

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream, however
   we can save some overhead by writing it directly to the stream's buffer */

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	RESOURCE_DATA msgData;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( checkHandleRange( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( sMemDataLeft( stream ) < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the attribute to the stream */
	setMessageData( &msgData, sMemBufPtr( stream ), sMemDataLeft( stream ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTTYPE_TYPE certType )
	{
	RESOURCE_DATA msgData;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( checkHandleRange( cryptCertificate ) );
	assert( certType > CRYPT_CERTTYPE_NONE && \
			certType < CRYPT_CERTTYPE_LAST );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the cert to the stream */
	setMessageData( &msgData, sMemBufPtr( stream ), sMemDataLeft( stream ) );
	status = krnlSendMessage( cryptCertificate, IMESSAGE_CRT_EXPORT,
							  &msgData, certType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
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
	assert( contentType == CRYPT_UNUSED || \
			( contentType > CRYPT_CONTENT_NONE && \
			  contentType < CRYPT_CONTENT_LAST ) );
	assert( ( iCryptKey == CRYPT_UNUSED ) || \
			checkHandleRange( iCryptKey ) );

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
	if( cryptStatusOK( status ) && contentType != CRYPT_UNUSED )
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
			checkHandleRange( iDecryptKey ) );

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
			  checkHandleRange( iCmsAttributes ) && \
			  inDataLength == 0 ) );
	assert( isWritePtr( outData, outDataMaxLength ) );
	assert( outDataMaxLength > 16 );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( contentType >= CRYPT_CONTENT_NONE && \
			contentType < CRYPT_CONTENT_LAST );
	assert( checkHandleRange( iSigKey ) );
	assert( iCmsAttributes == CRYPT_UNUSED || \
			checkHandleRange( iCmsAttributes ) );

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
			checkHandleRange( iSigCheckKey ) );
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
			krnlSendNotifier( *iSigningCert, IMESSAGE_DECREFCOUNT );
		}
	krnlSendNotifier( iCryptEnvelope, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		*outDataLength = msgData.length;
	return( status );
	}

/****************************************************************************
*																			*
*								Extended libc Functions						*
*																			*
****************************************************************************/

/* Match a given substring against a string in a case-insensitive manner.
   If possible we use native calls to handle this since they deal with
   charset-specific issues such as collating sequences, however a few OSes
   don't provide this functionality so we have to do it ourselves */

#if defined( __SYMBIAN32__ ) || defined( __BEOS__ )

int strnicmp( const char *src, const char *dest, int length )
	{
	while( length-- )
		{
		char srcCh = *src++, destCh = *dest++;

		/* Need to be careful with toupper() side-effects */
		srcCh = toUpper( srcCh );
		destCh = toUpper( destCh );

		if( srcCh != destCh )
			return( srcCh - destCh );
		}

	return( 0 );
	}

int stricmp( const char *src, const char *dest )
	{
	const int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strnicmp( src, dest, length ) );
	}
#endif /* OSes without case-insensitive string compares */

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
	mputLong( memPtr, clAllocIndex );
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
*							OS-specific Helper Functions					*
*																			*
****************************************************************************/

/* For performance evaluation purposes we provide the following function,
   which returns ticks of the 3.579545 MHz hardware timer (see the long
   comment in rndwin32.c for more details on Win32 timing issues) */

#if defined( __WIN32__ ) && !defined( NDEBUG )

unsigned long getTickCount( unsigned long startTime )
	{
	LARGE_INTEGER performanceCount;
	unsigned long timeLSB;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeLSB = performanceCount.LowPart;

	if( !startTime )
		return( timeLSB );
	if( startTime < timeLSB )
		return( timeLSB - startTime );
	return( ( 0xFFFFFFFF - startTime ) + 1 + timeLSB );
	}
#endif /* __WIN32__ debug build */

/* WinNT and its derivatives support ACL-based access control mechanisms for
   system objects (modulo a great many holes), so when we create objects such
   as files and threads we give them an ACL that allows only the creator
   access.  The following functions return the security info needed when
   creating objects.  The interface for this has changed in every major NT
   release, although it never got any better, just differently ugly.  The
   following code uses the original NT 3.1 interface, which works for all OS
   versions */

#if defined( __WIN32__ )

/* The size of the buffer for ACLs and the user token */

#define ACL_BUFFER_SIZE		1024
#define TOKEN_BUFFER_SIZE	256

/* A composite structure to contain the various ACL structures.  This is
   required because ACL handling is a complex, multistage operation that
   requires first creating an ACL and security descriptor to contain it,
   adding an access control entry (ACE) to the ACL, adding the ACL as the
   DACL of the security descriptor, and finally, wrapping the security
   descriptor up in a security attributes structure that can be passed to
   an object-creation function.

   The handling of the TOKEN_INFO is extraordinarily ugly because although
   the TOKEN_USER struct as defined is only 8 bytes long, Windoze allocates
   an extra 24 bytes after the end of the struct into which it stuffs data
   that the SID pointer in the TOKEN_USER struct points to.  This means we
   can't statically allocate memory of the size of the TOKEN_USER struct but
   have to make it a pointer into a larger buffer that can contain the
   additional invisible data tacked onto the end */

typedef struct {
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR pSecurityDescriptor;
	PACL pAcl;
	PTOKEN_USER pTokenUser;
	BYTE aclBuffer[ ACL_BUFFER_SIZE ];
	BYTE tokenBuffer[ TOKEN_BUFFER_SIZE ];
	} SECURITY_INFO;

/* Initialise an ACL allowing only the creator access and return it to the
   caller as an opaque value */

void *initACLInfo( const int access )
	{
	SECURITY_INFO *securityInfo;
	HANDLE hToken = INVALID_HANDLE_VALUE;	/* See comment below */
	BOOLEAN tokenOK = FALSE;

	/* Win95 doesn't have any security, return null security info */
	if( isWin95 )
		return( NULL );

	/* Allocate and initialise the composite security info structure */
	if( ( securityInfo = \
				clAlloc( "initACLInfo", sizeof( SECURITY_INFO ) ) ) == NULL )
		return( NULL );
	memset( securityInfo, 0, sizeof( SECURITY_INFO ) );
	securityInfo->pAcl = ( PACL ) securityInfo->aclBuffer;
	securityInfo->pTokenUser = ( PTOKEN_USER ) securityInfo->tokenBuffer;

	/* Get the security token for this thread.  First we try for the thread
	   token (which it typically only has when impersonating), if we don't
	   get that we use the token associated with the process.  We also
	   initialise the hToken even though it shouldn't be necessary because
	   Windows tries to read its contents, which indicates there might be
	   problems if it happens to start out with the wrong value */
	if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) || \
		OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
		DWORD cbTokenUser;

		tokenOK = GetTokenInformation( hToken, TokenUser,
									   securityInfo->pTokenUser,
									   TOKEN_BUFFER_SIZE, &cbTokenUser );
		CloseHandle( hToken );
		}
	if( !tokenOK )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set a security descriptor owned by the current user */
	if( !InitializeSecurityDescriptor( &securityInfo->pSecurityDescriptor,
									   SECURITY_DESCRIPTOR_REVISION ) || \
		!SetSecurityDescriptorOwner( &securityInfo->pSecurityDescriptor,
									 securityInfo->pTokenUser->User.Sid,
									 FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set up the discretionary access control list (DACL) with one access
	   control entry (ACE) for the current user */
	if( !InitializeAcl( securityInfo->pAcl, ACL_BUFFER_SIZE,
						ACL_REVISION ) || \
		!AddAccessAllowedAce( securityInfo->pAcl, ACL_REVISION, access,
							  securityInfo->pTokenUser->User.Sid ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Bind the DACL to the security descriptor */
	if( !SetSecurityDescriptorDacl( &securityInfo->pSecurityDescriptor, TRUE,
									securityInfo->pAcl, FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	assert( IsValidSecurityDescriptor( &securityInfo->pSecurityDescriptor ) );

	/* Finally, set up the security attributes structure */
	securityInfo->sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	securityInfo->sa.bInheritHandle = FALSE;
	securityInfo->sa.lpSecurityDescriptor = &securityInfo->pSecurityDescriptor;

	return( securityInfo );
	}

void freeACLInfo( void *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	if( securityInfo == NULL )
		return;
	clFree( "freeACLInfo", securityInfo );
	}

/* Extract the security info needed in Win32 API calls from the collection of
   security data we set up earlier */

void *getACLInfo( void *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	return( ( securityInfo == NULL ) ? NULL : &securityInfo->sa );
	}
#endif /* __WIN32__ */

/* SCO creates threads with a ridiculously small default stack size of a few
   KB or so, which means the thread can't even start.  To work around this we
   use a wrapper that sets a slightly larger thread stack size */

#if defined( __SCO_VERSION__ ) && defined( USE_THREADS )

int int createThread( void *( *function )( void * ), void *arg,
					  pthread_t *handle )
	{
	pthread_attr_t attr;
	pthread_t dummy;
	int status;

	/* Create the thread, setting the stack size to a sensible value
	   rather than the default used by SCO */
	pthread_attr_init( &attr );
	pthread_attr_setstacksize( &attr, 32768 );
	status = pthread_create( &handle, &attr, function, arg );
	pthread_attr_destroy( &attr );

	return( status ? CRYPT_ERROR : CRYPT_OK );
	}
#endif /* UnixWare/SCO with threading */

/* VM/CMS, MVS, and AS/400 systems need to convert characters from ASCII <->
   EBCDIC before/after they're read/written to external formats, the
   following functions perform the necessary conversion using the latin-1
   code tables for systems that don't have etoa/atoe */

#ifdef EBCDIC_CHARS

#include <stdarg.h>

#ifndef USE_ETOA

/* ISO 8859-1 to IBM Latin-1 Code Page 01047 (EBCDIC). */

static const BYTE asciiToEbcdicTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F,	/* 00 - 07 */
	0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26,	/* 10 - 17 */
	0x18, 0x19, 0x3F, 0x27, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D,	/* 20 - 27 */
	0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,	/* 28 - 2F */
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,	/* 30 - 37 */
	0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,	/* 38 - 3F */
	0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,	/* 40 - 47 */
	0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,	/* 48 - 4F */
	0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,	/* 50 - 57 */
	0xE7, 0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,	/* 58 - 5F */
	0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,	/* 60 - 67 */
	0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,	/* 68 - 6F */
	0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,	/* 70 - 77 */
	0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,	/* 78 - 7F */
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x06, 0x17,	/* 80 - 87 */
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x09, 0x0A, 0x1B,	/* 88 - 8F */
	0x30, 0x31, 0x1A, 0x33, 0x34, 0x35, 0x36, 0x08,	/* 90 - 97 */
	0x38, 0x39, 0x3A, 0x3B, 0x04, 0x14, 0x3E, 0xFF,	/* 98 - 9F */
	0x41, 0xAA, 0x4A, 0xB1, 0x9F, 0xB2, 0x6A, 0xB5,	/* A0 - A7 */
	0xBB, 0xB4, 0x9A, 0x8A, 0xB0, 0xCA, 0xAF, 0xBC,	/* A8 - AF */
	0x90, 0x8F, 0xEA, 0xFA, 0xBE, 0xA0, 0xB6, 0xB3,	/* B0 - B7 */
	0x9D, 0xDA, 0x9B, 0x8B, 0xB7, 0xB8, 0xB9, 0xAB,	/* B8 - BF */
	0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9E, 0x68,	/* C0 - C7 */
	0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,	/* C8 - CF */
	0xAC, 0x69, 0xED, 0xEE, 0xEB, 0xEF, 0xEC, 0xBF,	/* D0 - D7 */
	0x80, 0xFD, 0xFE, 0xFB, 0xFC, 0xBA, 0xAE, 0x59,	/* D8 - DF */
	0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9C, 0x48,	/* E0 - E7 */
	0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,	/* E8 - EF */
	0x8C, 0x49, 0xCD, 0xCE, 0xCB, 0xCF, 0xCC, 0xE1,	/* F0 - F7 */
	0x70, 0xDD, 0xDE, 0xDB, 0xDC, 0x8D, 0x8E, 0xDF	/* F8 - FF */
	};

/* IBM Latin-1 Code Page 01047 (EBCDIC) to ISO 8859-1. */

static const BYTE ebcdicToAsciiTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F,	/* 00 - 07 */
	0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x9D, 0x0A, 0x08, 0x87,	/* 10 - 17 */
	0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1B,	/* 20 - 27 */
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,	/* 28 - 2F */
	0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04,	/* 30 - 37 */
	0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,	/* 38 - 3F */
	0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5,	/* 40 - 47 */
	0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,	/* 48 - 4F */
	0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF,	/* 50 - 57 */
	0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,	/* 58 - 5F */
	0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5,	/* 60 - 67 */
	0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,	/* 68 - 6F */
	0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF,	/* 70 - 77 */
	0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,	/* 78 - 7F */
	0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,	/* 80 - 87 */
	0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,	/* 88 - 8F */
	0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,	/* 90 - 97 */
	0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,	/* 98 - 9F */
	0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,	/* A0 - A7 */
	0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0x5B, 0xDE, 0xAE,	/* A8 - AF */
	0xAC, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC,	/* B0 - B7 */
	0xBD, 0xBE, 0xDD, 0xA8, 0xAF, 0x5D, 0xB4, 0xD7,	/* B8 - BF */
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,	/* C0 - C7 */
	0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,	/* C8 - CF */
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,	/* D0 - D7 */
	0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,	/* D8 - DF */
	0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,	/* E0 - E7 */
	0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,	/* E8 - EF */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,	/* F0 - F7 */
	0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F	/* F8 - FF */
	};

/* Convert a string to/from EBCDIC */

int asciiToEbcdic( char *string, int stringLen )
	{
	int i;

	for( i = 0; i < stringLen; i++ )
		string[ i ] = asciiToEbcdicTbl[ ( unsigned int ) string[ i ] ];
	return( CRYPT_OK );
	}

int ebcdicToAscii( char *string, int stringLen )
	{
	int i;

	for( i = 0; i < stringLen; i++ )
		string[ i ] = ebcdicToAsciiTbl[ ( unsigned int ) string[ i ] ];
	return( CRYPT_OK );
	}
#else

int asciiToEbcdic( char *string, int stringLen )
	{
	return( __atoe_l( string, stringLen ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

int ebcdicToAscii( char *string, int stringLen )
	{
	return( __etoa_l( string, stringLen ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}
#endif /* USE_ETOA */

/* Convert a string to EBCDIC via a temporary buffer, used whem passing an
   ASCII string to a system function */

char *bufferToEbcdic( char *buffer, const char *string )
	{
	strcpy( buffer, string );
	asciiToEbcdic( buffer, strlen( string ) );
	return( buffer );
	}

/* Table for ctype functions that explicitly use the ASCII character set */

#define A	ASCII_ALPHA
#define L	ASCII_LOWER
#define N	ASCII_NUMERIC
#define S	ASCII_SPACE
#define U	ASCII_UPPER
#define X	ASCII_HEX
#define AL	( A | L )
#define AU	( A | U )
#define ANX	( A | N | X )
#define AUX	( A | U | X )

const BYTE asciiCtypeTbl[ 256 ] = {
	/* 00	   01	   02	   03	   04	   05	   06	   07  */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 08	   09	   0A	   0B	   0C	   0D	   0E	   0F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 10	   11	   12	   13	   14	   15	   16	   17 */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 18	   19	   1A	   1B	   1C	   1D	   1E	   1F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/*			!		"		#		$		%		&		' */
		A,		A,		A,		A,		A,		A,		A,		A,
	/* 	(		)		*		+		,		-		.		/ */
		A,		A,		A,		A,		A,		A,		A,		A,
	/*	0		1		2		3		4		5		6		7 */
	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,
	/*	8		9		:		;		<		=		>		? */
	   ANX,	   ANX,		A,		A,		A,		A,		A,		A,
	/*	@		A		B		C		D		E		F		G */
		A,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AU,
	/*	H		I		J		K		L		M		N		O */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	P		Q		R		S		T		U		V		W */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	X		Y		Z		[		\		]		^		_ */
	   AU,	   AU,	   AU,		A,		A,		A,		A,		A,
	/*	`		a		b		c		d		e		f		g */
		A,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	h		i		j		k		l		m		n		o */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	p		q		r		s		t		u		v		w */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	x		y		z		{		|		}		~	   DL */
	   AL,	   AL,	   AL,		A,		A,		A,		A,		A,
	/* High-bit-set characters */
	0
	};

/* stricmp()/strnicmp() versions that explicitly use the ASCII character
   set.  In order for collation to be handled properly, we have to convert
   to EBCDIC and use the local stricmp()/strnicmp() */

int strCompare( const char *src, const char *dest, int length )
	{
	BYTE buffer1[ MAX_ATTRIBUTE_SIZE ], buffer2[ MAX_ATTRIBUTE_SIZE ];

	if( length > MAX_ATTRIBUTE_SIZE )
		return( 1 );	/* Invalid length */

	/* Virtually all strings are 7-bit ASCII, the following optimisation
	   speeds up checking, particularly cases where we're walking down a
	   list of keywords looking for a match */
	if( *src < 0x80 && *dest < 0x80 && \
		toLower( *src ) != toLower( *dest ) )
		return( 1 );	/* Not equal */

	/* Convert the strings to EBCDIC and use a native compare */
	src = bufferToEbcdic( buffer1, src );
	dest = bufferToEbcdic( buffer2, dest );
	return( strnicmp( src, dest, length ) );
	}

int strCompareZ( const char *src, const char *dest )
	{
	const int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strCompare( src, dest, length ) );
	}

/* sprintf() that takes an ASCII format string */

int sPrintf( char *buffer, const char *format, ... )
	{
	BYTE formatBuffer[ MAX_ATTRIBUTE_SIZE ];
	va_list argPtr;
#ifndef NDEBUG
	int i;
#endif /* NDEBUG */
	int status;

#ifndef NDEBUG
	/* Make sure that we don't have any string args, which would require
	   their own conversion to EBCDIC */
	for( i = 0; i < strlen( format ) - 1; i++ )
		if( format[ i ] == '%' && format[ i + 1 ] == 's' )
			assert( NOTREACHED );
#endif /* NDEBUG */
	format = bufferToEbcdic( formatBuffer, format );
	va_start( argPtr, format );
	status = vsprintf( buffer, format, argPtr );
	if( status > 0 )
		ebcdicToAscii( buffer, status );
	va_end( argPtr );
	return( status );
	}

/* atio() that takes an ASCII string */

int aToI( const char *str )
	{
	BYTE buffer[ 16 ];

	/* The maximum length of a numeric string value that can be converted
	   to a 4-byte integer is considered as 10 characters (9,999,999,999) */
	strncpy( buffer, str, 10 );
	buffer[ 10 ] = '\0';
	asciiToEbcdic( buffer, strlen( buffer ) );
	return( atoi( buffer ) );
	}
#endif /* EBCDIC_CHARS */

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
   whitespace at the start of the line as superfluous and strips it.  We also
   handle continued lines, denoted by a semicolon as the last non-whitespace
   character.  Stripping of repeated whitespace is also handled by the
   seenWhitespace flag, stripping of trailing whitespace is handled by
   walking back through any final whitespace once we see the EOL, and
   continued lines are handled by setting the seenSemicolon flag if we see a
   semicolon as the last non-whitespace character.

   Finally, we also need to handle generic DOS attacks.  If we see more than
   10K chars in a line, we bail out */

typedef struct {
	BOOLEAN seenWhitespace, seenSemicolon;
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
	   DOSes */
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
		while( state->bufPos && buffer[ state->bufPos - 1 ] == ' ' )
			state->bufPos--;

		/* If we've seen a semicolon as the last non-whitespace char, the
		   line continues on the next one */
		if( state->seenSemicolon )
			{
			state->seenSemicolon = FALSE;
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
		state->seenSemicolon = \
						( ch == ';' || ( state->seenSemicolon && \
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

/****************************************************************************
*																			*
*							Base64 En/Decoding Functions					*
*																			*
****************************************************************************/

/* Encode/decode tables from RFC 1113 */

#define BPAD		'='		/* Padding for odd-sized output */
#define BERR		0xFF	/* Illegal char marker */
#define BEOF		0x7F	/* EOF marker (padding char or EOL) */

static const FAR_BSS char binToAscii[] = \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#ifndef EBCDIC_CHARS__
  static const FAR_BSS BYTE asciiToBin[ 256 ] =
	{ BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BEOF, BERR, BERR, BEOF, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, 0x3E, BERR, BERR, BERR, 0x3F,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	  0x3C, 0x3D, BERR, BERR, BERR, BEOF, BERR, BERR,
	  BERR, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	  0x17, 0x18, 0x19, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	  0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	  0x31, 0x32, 0x33, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR
	};
#else
  /* EBCDIC character mappings:
		A-I C1-C9
		J-R D1-D9
		S-Z E2-E9
		a-i 81-89
		j-r 91-99
		s-z A2-A9
		0-9 F0-F9
		+   4E
		/   61
		=   7E  Uses BEOF in table */
static const FAR_BSS BYTE asciiToBin[ 256 ] =
	{ BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*00*/
	  BERR, BERR, BEOF, BERR, BERR, BEOF, BERR, BERR,	/* CR, LF */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*10*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*20*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*30*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*40*/
	  BERR, BERR, BERR, BERR, BERR, BERR, 0x3E, BERR,	/* + */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*50*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x3F, BERR, BERR, BERR, BERR, BERR, BERR,	/*60*/	/* / */
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*70*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BEOF, BERR,			/* = */
	  BERR, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,	/*80*/	/* a-i */
	  0x21, 0x22, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,	/*90*/	/* j-r */
	  0x2A, 0x2B, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31,	/*A0*/	/* s-z */
	  0x32, 0x33, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,	/*B0*/
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,	/*C0*/	/* A-I */
	  0x07, 0x08, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/*D0*/	/* J-R */
	  0x10, 0x11, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,	/*E0*/	/* S-Z */
	  0x18, 0x19, BERR, BERR, BERR, BERR, BERR, BERR,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,	/*F0*/	/* 0-9 */
	  0x3C, 0x3D, BERR, BERR, BERR, BERR, BERR, BERR
	};
#endif /* Different character code mappings */

/* The size of lines for PEM-type formatting.  This is only used for encoding,
   for decoding we adjust to whatever size the sender has used */

#define TEXT_LINESIZE	64
#define BINARY_LINESIZE	48

/* Basic single-char en/decode functions.  We cast the value to an unsigned
   char to avoid generating negative array offsets if the sign bit is set,
   since the strings are passed as char *'s */

#define encode(data)	binToAscii[ ( BYTE ) data ]
#define decode(data)	asciiToBin[ ( BYTE ) data ]

/* The headers and trailers used for base64-encoded certificate objects */

static const FAR_BSS struct {
	const CRYPT_CERTTYPE_TYPE type;
	const char *header, *trailer;
	} headerInfo[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE,
	  "-----BEGIN CERTIFICATE-----" EOL,
	  "-----END CERTIFICATE-----" EOL },
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT,
	  "-----BEGIN ATTRIBUTE CERTIFICATE-----" EOL,
	  "-----END ATTRIBUTE CERTIFICATE-----" EOL },
	{ CRYPT_CERTTYPE_CERTCHAIN,
	  "-----BEGIN CERTIFICATE CHAIN-----" EOL,
	  "-----END CERTIFICATE CHAIN-----" EOL },
	{ CRYPT_CERTTYPE_CERTREQUEST,
	  "-----BEGIN NEW CERTIFICATE REQUEST-----" EOL,
	  "-----END NEW CERTIFICATE REQUEST-----" EOL },
	{ CRYPT_CERTTYPE_REQUEST_CERT,
	  "-----BEGIN NEW CERTIFICATE REQUEST-----" EOL,
	  "-----END NEW CERTIFICATE REQUEST-----" EOL },
	{ CRYPT_CERTTYPE_CRL,
	  "-----BEGIN CERTIFICATE REVOCATION LIST-----"  EOL,
	  "-----END CERTIFICATE REVOCATION LIST-----" EOL },
	{ CRYPT_CERTTYPE_NONE,			/* Universal catch-all */
	  "-----BEGIN CERTIFICATE OBJECT-----"  EOL,
	  "-----END CERTIFICATE OBJECT-----" EOL }
	};

/* Check whether a data item has a header that identifies it as some form of
   encoded certificate object and return the start position of the encoded
   data.  For S/MIME certificate data this can in theory get quite complex
   because there are many possible variations in the headers.  Some early
   S/MIME agents used a content type of "application/x-pkcs7-mime",
   "application/x-pkcs7-signature", and "application/x-pkcs10", while newer
   ones use the same without the "x-" at the start.  In addition Netscape
   have their own MIME data types for certificates, "application/x-x509-"
   "{user-cert|ca-cert|email-cert}, and there are further types in the
   endless stream of RFCs that PKIX churns out.  There are a whole pile of
   other possible headers as well, none of them terribly relevant for our
   purposes, so all we check for is the base64 indicator.  For PEM we just
   check for the '-----..' header which is fairly simple.  Finally we check
   for raw base64-encoded data that can occur if an object is extracted from
   a MIME message and the headers discarded */

static int readLine( STREAM *stream, char *buffer, const int maxSize )
	{
	MIME_STATE state;
	int status;

	initMIMEstate( &state, maxSize );
	do
		{
		const int ch = sgetc( stream );

		status = ( cryptStatusError( ch ) ) ? ch : \
				 addMIMEchar( &state, buffer, ch );
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	return( endMIMEstate( &state ) );
	}

CRYPT_CERTFORMAT_TYPE base64checkHeader( const char *data,
										 const int dataLength, int *startPos )
	{
	STREAM stream;
	BOOLEAN seenTransferEncoding = FALSE;
	char buffer[ 1024 ];
	int position, ch1, ch2, status;

	/* Clear return value */
	*startPos = 0;

	/* If the item is too small to contain any useful data, we don't even try
	   and examine it */
	if( dataLength < 64 )
		return( CRYPT_CERTFORMAT_NONE );

	sMemConnect( &stream, data, dataLength );

	/* Sometimes the object can be preceded by a few blank lines.  We're
	   fairly lenient with this */
	do
		ch1 = sgetc( &stream );
	while( ch1 == '\r' || ch1 == '\n' );
	ch2 = sgetc( &stream );
	position = stell( &stream ) - 2;

	/* Perform a quick check to weed out non-encoded cert data, which is
	   usually the case */
	if( ( ch1 == 0x30 ) && ( !isAlpha( ch2 ) || \
							!isAlpha( sgetc( &stream ) ) || \
							!isAlpha( sgetc( &stream ) ) ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_CERTFORMAT_NONE );
		}
	sseek( &stream, position );

	/* If it starts with a dash, check for PEM header encapsulation */
	if( ch1 == '-' )
		{
		int i;

		/* We always have to start with 5 dashes and 'BEGIN '.  After this
		   there can be all sorts of stuff, but it has to end with another
		   five dashes and a newline */
		if( cryptStatusError( sread( &stream, buffer, 11 ) ) || \
			memcmp( buffer, "-----BEGIN ", 11 ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_CERTFORMAT_NONE );
			}
		for( i = 0; i < 40; i++ )
			if( sgetc( &stream ) == '-' )
				break;
		if( i == 40 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_CERTFORMAT_NONE );
			}
		if( cryptStatusError( sread( &stream, buffer, 4 ) ) || \
			memcmp( buffer, "----", 4 ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_CERTFORMAT_NONE );
			}
		ch1 = sgetc( &stream );
		if( ch1 != '\n' )
			{
			if( ch1 == '\r' )
				{
				if( sPeek( &stream ) == '\n' )
					sgetc( &stream );
				}
			else
				{
				sMemDisconnect( &stream );
				return( CRYPT_CERTFORMAT_NONE );
				}
			}

		/* Return the start position of the payload */
		*startPos = stell( &stream );
		sMemDisconnect( &stream );
		return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
		}

	/* It's not PEM header encapsulation, check for raw base64 containing
	   some form of encoded cert.  There isn't a 100% reliable check for
	   this, but if the first 60 chars (the minimum base64 line length) are
	   all valid base64 chars and the first chars match the required values
	   then it's reasonably certain that it's base64 cert data.

	   First we do a quick check to see if the content is some form of
	   encoded cert.  For cert data that begins with 30 8x, the
	   corresponding base64 values are MI... */
	if( ch1 == 'M' && ch2 == 'I' )
		{
		BOOLEAN base64OK = TRUE;
		int i;

		/* It looks like an encoded cert, make sure that it's really base64
		   data */
		for( i = 0; i < 15; i++ )
			{
			status = sread( &stream, buffer, 4 );
			if( cryptStatusError( status ) )
				{
				base64OK = FALSE;
				break;
				}
			else
				{
				const BYTE c0 = decode( buffer[ 0 ] );
				const BYTE c1 = decode( buffer[ 1 ] );
				const BYTE c2 = decode( buffer[ 2 ] );
				const BYTE c3 = decode( buffer[ 3 ] );
				const BYTE cx = c0 | c1 | c2 | c3;

				if( cx == BEOF || cx == BERR )
					{
					base64OK = FALSE;
					break;
					}
				}
			}

		/* If everything was OK, it's raw base64 */
		if( base64OK )
			{
			sMemDisconnect( &stream );
			*startPos = position;
			return( CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
			}
		}
	sseek( &stream, position );

	/* It doesn't look like raw base64, check for an S/MIME header */
	do
		{
		status = readLine( &stream, buffer, 1024 );
		if( !cryptStatusError( status ) && status >= 32 && \
			strCompare( buffer, "Content-Transfer-Encoding: bas64", 32 ) )
			seenTransferEncoding = TRUE;
		}
	while( status > 0 );
	if( cryptStatusError( status ) || !seenTransferEncoding )
		{
		sMemDisconnect( &stream );
		return( CRYPT_CERTFORMAT_NONE );
		}

	/* Skip trailing blank lines */
	do
		ch1 = sgetc( &stream );
	while( ch1 == '\r' || ch1 == '\n' );

	/* Make sure that the content is some form of encoded cert.  For cert
	   data that begins with 30 8x, the corredponding base64 values are
	   MI... */
	*startPos = stell( &stream ) - 1;
	status = CRYPT_ICERTFORMAT_SMIME_CERTIFICATE;
	if( ch1 != 'M' || sgetc( &stream ) != 'I' )
		status = CRYPT_CERTFORMAT_NONE;
	sMemDisconnect( &stream );
	return( status );
	}

/* Encode a block of binary data into the base64 format, returning the total
   number of output bytes */

int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType )
	{
	BYTE *inBufferPtr = ( BYTE * ) inBuffer;
	int srcIndex = 0, destIndex = 0, lineCount = 0, remainder = count % 3;
	int headerInfoIndex;

	/* If it's a certificate object, add the header */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		for( headerInfoIndex = 0;
			 headerInfo[ headerInfoIndex ].type != certType && \
				headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE;
			 headerInfoIndex++ );
		assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );
		strcpy( outBuffer, headerInfo[ headerInfoIndex ].header );
		destIndex = strlen( headerInfo[ headerInfoIndex ].header );
		}

	/* Encode the data */
	while( srcIndex < count )
		{
		/* If we've reached the end of a line of binary data and it's a
		   certificate, add the EOL marker */
		if( certType != CRYPT_CERTTYPE_NONE && lineCount == BINARY_LINESIZE )
			{
			strcpy( outBuffer + destIndex, EOL );
			destIndex += EOL_LEN;
			lineCount = 0;
			}
		lineCount += 3;

		/* Encode a block of data from the input buffer */
		outBuffer[ destIndex++ ] = encode( inBufferPtr[ srcIndex ] >> 2 );
		outBuffer[ destIndex++ ] = encode( ( ( inBufferPtr[ srcIndex ] << 4 ) & 0x30 ) |
										   ( ( inBufferPtr[ srcIndex + 1 ] >> 4 ) & 0x0F ) );
		srcIndex++;
		outBuffer[ destIndex++ ] = encode( ( ( inBufferPtr[ srcIndex ] << 2 ) & 0x3C ) |
										   ( ( inBufferPtr[ srcIndex + 1 ] >> 6 ) & 0x03 ) );
		srcIndex++;
		outBuffer[ destIndex++ ] = encode( inBufferPtr[ srcIndex++ ] & 0x3F );
		}

	/* Go back and add padding and correctly encode the last char if we've
	   encoded too many characters */
	if( remainder == 2 )
		{
		/* There were only 2 bytes in the last group */
		outBuffer[ destIndex - 1 ] = BPAD;
		outBuffer[ destIndex - 2 ] = \
					encode( ( inBufferPtr[ srcIndex - 2 ] << 2 ) & 0x3C );
		}
	else
		if( remainder == 1 )
			{
			/* There was only 1 byte in the last group */
			outBuffer[ destIndex - 2 ] = outBuffer[ destIndex - 1 ] = BPAD;
			outBuffer[ destIndex - 3 ] = \
					encode( ( inBufferPtr[ srcIndex - 3 ] << 4 ) & 0x30 );
			}

	/* If it's a certificate object, add the trailer */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		strcpy( outBuffer + destIndex, EOL );
		strcpy( outBuffer + destIndex + EOL_LEN,
				headerInfo[ headerInfoIndex ].trailer );
		destIndex += strlen( headerInfo[ headerInfoIndex ].trailer );
		}
	else
		{
		/* It's not a certificate, truncate the unnecessary padding and add
		   der terminador */
		destIndex -= ( 3 - remainder ) % 3;
		outBuffer[ destIndex ] = '\0';
		}

	/* Return a count of encoded bytes */
	return( destIndex );
	}

/* Decode a block of binary data from the base64 format, returning the total
   number of decoded bytes */

static int fixedBase64decode( void *outBuffer, const char *inBuffer,
							  const int count )
	{
	int srcIndex = 0, destIndex = 0;
	BYTE *outBufferPtr = outBuffer;

	/* Decode the base64 string as a fixed-length continuous string without
	   padding or newlines */
	while( srcIndex < count )
		{
		BYTE c0, c1, c2 = 0, c3 = 0;
		const int delta = count - srcIndex;

		/* Decode a block of data from the input buffer */
		c0 = decode( inBuffer[ srcIndex++ ] );
		c1 = decode( inBuffer[ srcIndex++ ] );
		if( delta > 2 )
			{
			c2 = decode( inBuffer[ srcIndex++ ] );
			if( delta > 3 )
				c3 = decode( inBuffer[ srcIndex++ ] );
			}
		if( ( c0 | c1 | c2 | c3 ) == BERR )
			return( 0 );

		/* Copy the decoded data to the output buffer */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( delta > 2 )
			{
			outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
			if( delta > 3 )
				outBufferPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
			}
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

int base64decode( void *outBuffer, const char *inBuffer, const int count,
				  const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0, destIndex = 0, lineCount = 0, lineSize = 0;
	BYTE c0, c1, c2, c3, *outBufferPtr = outBuffer;

	/* If it's not a certificate, it's a straight base64 string and we can
	   use the simplified decoding routines */
	if( format == CRYPT_CERTFORMAT_NONE )
		return( fixedBase64decode( outBuffer, inBuffer, count ) );

	/* Decode the certificate body */
	while( TRUE )
		{
		BYTE cx;

		/* Depending on implementations, the length of the base64-encoded
		   line can vary from 60 to 72 chars, we ajust for this by checking
		   for an EOL and setting the line length to this size */
		if( !lineSize && \
			( inBuffer[ srcIndex ] == '\r' || inBuffer[ srcIndex ] == '\n' ) )
			lineSize = lineCount;

		/* If we've reached the end of a line of text, look for the EOL
		   marker.  There's one problematic special case here where, if the
		   encoding has produced bricktext, the end of the data will coincide
		   with the EOL.  For CRYPT_CERTFORMAT_TEXT_CERTIFICATE this will give
		   us '-----END' on the next line which is easy to check for, but for
		   CRYPT_ICERTFORMAT_SMIME_CERTIFICATE what we end up with depends on
		   the calling code, it could truncate immediately at the end of the
		   data (which it isn't supposed to) so we get '\0', it could truncate
		   after the EOL (so we get EOL + '\0'), it could continue with a
		   futher content type after a blank line (so we get EOL + EOL), or
		   it could truncate without the '\0' so we get garbage, which is the
		   caller's problem.  Because of this we look for all of these
		   situations and, if any are found, set c0 to BEOF and advance
		   srcIndex by 4 to take into account the adjustment for overshoot
		   that occurs when we break out of the loop */
		if( lineCount == lineSize )
			{
			/* Check for '\0' at the end of the data */
			if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
				!inBuffer[ srcIndex ] )
				{
				c0 = c1 = c2 = BEOF;
				srcIndex += 4;
				break;
				}

			/* Check for EOL */
			if( inBuffer[ srcIndex ] == '\n' )
				srcIndex++;
			else
				if( inBuffer[ srcIndex ] == '\r' )
					{
					srcIndex++;

					/* Some broken implementations emit two CRs before the
					   LF.  Stripping these extra CRs clashes with other
					   broken implementations that emit only CRs, which means
					   that we'll be stripping the EOT blank line in MIME
					   encapsulation, however it looks like the two-CR bug
					   (usually from Netscape) appears to be more prevalent
					   than the CR-only bug (old Mac software) */
					if( inBuffer[ srcIndex ] == '\r' )
						srcIndex++;

					if( inBuffer[ srcIndex ] == '\n' )
						srcIndex++;
					}
			lineCount = 0;

			/* Check for '\0' or EOL (S/MIME) or '----END' (PEM) after EOL */
			if( ( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
				  ( !inBuffer[ srcIndex ] || inBuffer[ srcIndex ] == '\n' || \
					inBuffer[ srcIndex ] == '\r' ) ) || \
				( format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE && \
				  !strncmp( inBuffer + srcIndex, "-----END ", 9 ) ) )
				{
				c0 = c1 = c2 = BEOF;
				srcIndex += 4;
				break;
				}
			}

		/* Decode a block of data from the input buffer */
		c0 = decode( inBuffer[ srcIndex++ ] );
		c1 = decode( inBuffer[ srcIndex++ ] );
		c2 = decode( inBuffer[ srcIndex++ ] );
		c3 = decode( inBuffer[ srcIndex++ ] );
		cx = c0 | c1 | c2 | c3;
		if( c0 == BEOF || cx == BEOF )
			/* We need to check c0 separately since hitting an EOF at c0 may
			   cause later chars to be decoded as BERR */
			break;
		else
			if( cx == BERR )
				return( 0 );
		lineCount += 4;

		/* Copy the decoded data to the output buffer */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2 );
		outBufferPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
		}

	/* Handle the truncation of data at the end.  Due to the 3 -> 4 encoding,
	   we have the following mapping: 0 chars -> nothing, 1 char -> 2 + 2 pad,
	   2 chars = 3 + 1 pad */
	if( c0 == BEOF )
		/* No padding, move back 4 chars */
		srcIndex -= 4;
	else
		{
		/* 2 chars padding, decode 1 from 2 */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( c2 != BEOF )
			/* 1 char padding, decode 2 from 3 */
			outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

/* Calculate the size of a quantity of data once it's en/decoded as a
   certificate */

int base64decodeLen( const char *data, const int dataLength )
	{
	STREAM stream;
	int ch, length;

	/* Skip ahead until we find the end of the decodable data */
	sMemConnect( &stream, data, dataLength );
	do
		{
		ch = sgetc( &stream );
		if( cryptStatusError( ch ) || ch == BPAD )
			break;
		ch = decode( ch );
		}
	while( ch != BERR );
	length = stell( &stream );
	sMemDisconnect( &stream );

	/* Return a rough estimate of how much room the decoded data will occupy.
	   This ignores the EOL size so it always overestimates, but a strict
	   value isn't necessary since the user never sees it anyway */
	return( ( length * 3 ) / 4 );
	}

int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType )
	{
	int length = roundUp( ( dataLength * 4 ) / 3, 4 ), headerInfoIndex;

	for( headerInfoIndex = 0;
		 headerInfo[ headerInfoIndex ].type != certType && \
			headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE;
		 headerInfoIndex++ );
	assert( headerInfo[ headerInfoIndex ].type != CRYPT_CERTTYPE_NONE );

	/* Calculate extra length due to EOL's */
	length += ( ( roundUp( dataLength, BINARY_LINESIZE ) / BINARY_LINESIZE ) * EOL_LEN );

	/* Return the total length due to delimiters */
	return( strlen( headerInfo[ headerInfoIndex ].header ) + length + \
			strlen( headerInfo[ headerInfoIndex ].trailer ) );
	}

/****************************************************************************
*																			*
*						PKI User ID En/Decoding Functions					*
*																			*
****************************************************************************/

/* En/decode text representations of binary keys */

static const char codeTable[] = \
						"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";	/* No O/0, I/1 */
static const int hiMask[] = { 0x00, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x03, 0x01 };
static const int loMask[] = { 0x00, 0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0xF0 };

BOOLEAN isPKIUserValue( const char *encVal, const int encValueLength )
	{
	int i = 0;

	/* Check whether a user value is of the form XXXXX-XXXXX-XXXXX{-XXXXX} */
	if( ( encValueLength != ( 3 * 5 ) + 2 ) && \
		( encValueLength != ( 4 * 5 ) + 3 ) )
		return( FALSE );
	while( i < encValueLength )
		{
		int j;

		for( j = 0; j < 5; j++ )
			{
			const int ch = encVal[ i++ ];

			if( !isAlnum( ch ) )
				return( FALSE );
			}
		if( i < encValueLength && encVal[ i++ ] != '-' )
			return( FALSE );
		}
	return( TRUE );
	}

int adjustPKIUserValue( BYTE *value, const int noCodeGroups )
	{
	const int noBits = noCodeGroups * 25;
	const int length = ( roundUp( noBits, 8 ) / 8 ) - 1;

	/* Mask off the bits at the end of the data that can't be encoded in
	   the given number of code groups */
	value[ length - 1 ] &= 0xFF << ( 8 - ( noBits % 8 ) );
	return( length );
	}

int encodePKIUserValue( char *encVal, const BYTE *value,
						const int noCodeGroups )
	{
	BYTE valBuf[ 128 ];
	const int dataBytes = ( roundUp( noCodeGroups * 25, 8 ) / 8 );
	int i, hi = 0, lo = 0, byteCount = 0, bitCount = 0, length;

	/* Copy across the data bytes, leaving a gap at the start for the
	   checksum */
	memcpy( valBuf + 1, value, dataBytes );
	length = adjustPKIUserValue( valBuf + 1, noCodeGroups ) + 1;

	/* Calculate the Fletcher checksum and prepend it to the data bytes
	   This is easier than handling the addition of a non-byte-aligned
	   quantity to the end of the data.  In fact this isn't quite a pure
	   Fletcher checksum because we don't bother keeping the accumulators
	   at 8 bits, and also don't need to set the initial value to nonzero
	   since we'll never see a sequence of zero bytes.  This isn't a big
	   deal since all we need is a consistent result */
	for( i = 1; i < length; i++ )
		{
		lo += valBuf[ i ];
		hi += lo;
		}
	valBuf[ 0 ] = hi & 0xFF;

	/* Encode the binary data as text */
	for( length = 0, i = 1; i <= noCodeGroups * 5; i++ )
		{
		int chunkValue;

		/* Extract the next 5-bit chunk and convert it to text form */
		if( bitCount < 3 )
			/* Everything's present in one byte, shift it down to the LSB */
			chunkValue = ( valBuf[ byteCount ] >> ( 3 - bitCount ) ) & 0x1F;
		else
			if( bitCount == 3 )
				/* It's the 5 LSB's */
				chunkValue = valBuf[ byteCount ] & 0x1F;
			else
				/* The data spans two bytes, shift the bits from the high
				   byte up and the bits from the low byte down */
				chunkValue = ( ( valBuf[ byteCount ] & \
								hiMask[ bitCount ] ) << ( bitCount - 3 ) ) | \
							( ( valBuf[ byteCount + 1 ] & \
								loMask[ bitCount ] ) >> ( 11 - bitCount ) );
		encVal[ length++ ] = codeTable[ chunkValue ];
		if( !( i % 5 ) && i < noCodeGroups * 5 )
			encVal[ length++ ] = '-';

		/* Advance by 5 bits */
		bitCount += 5;
		if( bitCount >= 8 )
			{
			bitCount -= 8;
			byteCount++;
			}
		}

	return( length );
	}

int decodePKIUserValue( BYTE *value, const char *encVal,
						const int encValueLength )
	{
	BYTE valBuf[ 128 ];
	char encBuf[ 128 ], *encBufPtr = encBuf;
	int i = 0, hi = 0, lo = 0, byteCount = 0, bitCount = 0, length = 0;

	/* Undo the formatting of the encoded value */
	while( i < encValueLength )
		{
		int j;

		for( j = 0; j < 5; j++ )
			{
			const int ch = encVal[ i++ ];

			if( !isAlnum( ch ) || length >= encValueLength )
				return( CRYPT_ERROR_BADDATA );
			encBuf[ length++ ] = toUpper( ch );
			}
		if( i < encValueLength && encVal[ i++ ] != '-' )
			return( CRYPT_ERROR_BADDATA );
		}
	if( length % 5 )
		return( CRYPT_ERROR_BADDATA );

	/* Decode the text data into binary */
	memset( valBuf, 0, 128 );
	for( i = 0; i < length; i ++ )
		{
		const int ch = *encBufPtr++;
		int chunkValue;

		for( chunkValue = 0; chunkValue < 0x20; chunkValue++ )
			if( codeTable[ chunkValue ] == ch )
				break;
		if( chunkValue == 0x20 )
			return( CRYPT_ERROR_BADDATA );

		/* Extract the next 5-bit chunk and convert it to text form */
		if( bitCount < 3 )
			/* Everything's present in one byte, shift it up into position */
			valBuf[ byteCount ] |= chunkValue << ( 3 - bitCount );
		else
			if( bitCount == 3 )
				/* It's the 5 LSB's */
				valBuf[ byteCount ] |= chunkValue;
			else
				{
				/* The data spans two bytes, shift the bits from the high
				   byte down and the bits from the low byte up */
				valBuf[ byteCount ] |= \
							( chunkValue >> ( bitCount - 3 ) ) & hiMask[ bitCount ];
				valBuf[ byteCount + 1 ] = \
							( chunkValue << ( 11 - bitCount ) ) & loMask[ bitCount ];
				}

		/* Advance by 5 bits */
		bitCount += 5;
		if( bitCount >= 8 )
			{
			bitCount -= 8;
			byteCount++;
			}
		}

	/* Calculate the Fletcher checksum and make sure that it matches the
	   value at the start of the data bytes */
	if( bitCount )
		byteCount++;	/* More bits in the last partial byte */
	for( i = 1; i < byteCount; i++ )
		{
		lo += valBuf[ i ];
		hi += lo;
		}
	if( valBuf[ 0 ] != ( hi & 0xFF ) )
		return( CRYPT_ERROR_BADDATA );

	/* Return the decoded value to the caller */
	if( value != NULL )
		memcpy( value, valBuf + 1, byteCount - 1 );
	return( byteCount - 1 );
	}
