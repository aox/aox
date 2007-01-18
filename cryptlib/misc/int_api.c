/****************************************************************************
*																			*
*							cryptlib Internal API							*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#if defined( INC_ALL )
  #include "crypt.h"
  #ifdef USE_MD2
	#include "md2.h"
  #endif /* USE_MD2 */
  #ifdef USE_MD5
	#include "md5.h"
  #endif /* USE_MD5 */
  #ifdef USE_RIPEMD160
	#include "ripemd.h"
  #endif /* USE_RIPEMD160 */
  #include "sha.h"
  #ifdef USE_SHA2
	#include "sha2.h"
  #endif /* USE_SHA2 */
  #include "stream.h"
#else
  #include "crypt.h"
  #ifdef USE_MD2
	#include "crypt/md2.h"
  #endif /* USE_MD2 */
  #ifdef USE_MD5
	#include "crypt/md5.h"
  #endif /* USE_MD5 */
  #ifdef USE_RIPEMD160
	#include "crypt/ripemd.h"
  #endif /* USE_RIPEMD160 */
  #include "crypt/sha.h"
  #ifdef USE_SHA2
	#include "crypt/sha2.h"
  #endif /* USE_SHA2 */
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Perform the FIPS-140 statistical checks that are feasible on a byte
   string.  The full suite of tests assumes that an infinite source of
   values (and time) is available, the following is a scaled-down version
   used to sanity-check keys and other short random data blocks.  Note that
   this check requires at least 64 bits of data in order to produce useful
   results */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength )
	{
	const int delta = ( dataLength < 16 ) ? 1 : 0;
	int bitCount[ 4 + 8 ] = { 0 }, noOnes, i;

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
   the caller, this is just a backup check).  We also have a second function 
   that's used internally for data-copying */

int attributeCopy( MESSAGE_DATA *msgData, const void *attribute,
				   const int attributeLength )
	{
	const int maxLength = msgData->length;

	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );

	/* Clear return value */
	msgData->length = 0;

	if( attributeLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( msgData->data != NULL )
		{
		assert( isReadPtr( attribute, attributeLength ) );

		if( attributeLength > maxLength || \
			!isWritePtr( msgData->data, attributeLength ) )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( msgData->data, attribute, attributeLength );
		}
	msgData->length = attributeLength;

	return( CRYPT_OK );
	}

int dataCopy( void *dest, const int destMaxLength, int *destLength,
			  const void *source, const int sourceLength )
	{
	assert( isWritePtr( dest, destMaxLength ) );
	assert( isWritePtr( destLength, sizeof( int ) ) );
	assert( isReadPtr( source, sourceLength ) );

	/* Clear return value */
	*destLength = 0;

	if( sourceLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( sourceLength > destMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( dest, source, sourceLength );
	*destLength = sourceLength;

	return( CRYPT_OK );
	}

/* Check whether a given algorithm is available */

BOOLEAN algoAvailable( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO queryInfo;

	assert( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );

	return( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
									cryptAlgo ) ) ? TRUE : FALSE );
	}

/* For a given algorithm pair, check whether the first is stronger than the
   second.  For hashes the order is:

	SHA2 > RIPEMD160 > SHA-1 > all others */

BOOLEAN isStrongerHash( const CRYPT_ALGO_TYPE algorithm1,
						const CRYPT_ALGO_TYPE algorithm2 )
	{
	static const CRYPT_ALGO_TYPE algoPrecedence[] = {
		CRYPT_ALGO_SHA2, CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_SHA,
		CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
	int algo1index, algo2index;

	assert( algorithm1 >= CRYPT_ALGO_FIRST_HASH && \
			algorithm1 <= CRYPT_ALGO_LAST_HASH );
	assert( algorithm2 >= CRYPT_ALGO_FIRST_HASH && \
			algorithm2 <= CRYPT_ALGO_LAST_HASH );

	/* Find the relative positions on the scale of the two algorithms */
	for( algo1index = 0; 
		 algoPrecedence[ algo1index ] != algorithm1 && \
			algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo1index++ )
		{
		/* If we've reached an unrated algorithm, it can't be stronger than 
		   the other one */
		if( algoPrecedence[ algo1index ] == CRYPT_ALGO_NONE )
			return( FALSE );
		}
	if( algo1index >= FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE ) )
		retIntError_Boolean();
	for( algo2index = 0; 
		 algoPrecedence[ algo2index ] != algorithm2 && \
			algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo2index++ )
		{
		/* If we've reached an unrated algorithm, it's weaker than the other 
		   one */
		if( algoPrecedence[ algo2index ] == CRYPT_ALGO_NONE )
			return( TRUE );
		}
	if( algo2index >= FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE ) )
		retIntError_Boolean();

	/* If the first algorithm has a smaller index than the second, it's a
	   stronger algorithm */
	return( ( algo1index < algo2index ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*								Time Functions 								*
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

	return( ( theTime <= MIN_TIME_VALUE ) ? 0 : theTime );
	}

time_t getApproxTime( void )
	{
	const time_t theTime = time( NULL );

	return( ( theTime <= MIN_TIME_VALUE ) ? CURRENT_TIME_VALUE : theTime );
	}

time_t getReliableTime( const CRYPT_HANDLE cryptHandle )
	{
	CRYPT_DEVICE cryptDevice;
	MESSAGE_DATA msgData;
	time_t theTime;
	int status;

	assert( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			isHandleRangeValid( cryptHandle ) );

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
	return( ( theTime <= MIN_TIME_VALUE ) ? 0 : theTime );
	}

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

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
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void md5HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void ripemd160HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
						  const int outBufMaxLength, const BYTE *inBuffer, 
						  const int inLength, const HASH_STATE hashState );
void shaHashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void sha2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					 const int outBufMaxLength, const BYTE *inBuffer, 
					 const int inLength, const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashSize )
	{
	assert( hashAlgorithm >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgorithm <= CRYPT_ALGO_LAST_HASH );
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

#ifdef USE_MD5
		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			if( hashSize != NULL )
				*hashSize = MD5_DIGEST_LENGTH;
			return;
#endif /* USE_MD5 */

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

/****************************************************************************
*																			*
*								String Functions							*
*																			*
****************************************************************************/

/* Perform various string-processing operations */

int strFindCh( const char *str, const int strLen, const char findCh )
	{
	int i;

	assert( isReadPtr( str, strLen ) );

	for( i = 0; i < strLen; i++ )
		if( str[ i ] == findCh )
			return( i );

	return( -1 );
	}

int strFindStr( const char *str, const int strLen, 
				const char *findStr, const int findStrLen )
	{
	const char findCh = *findStr;
	int i;

	assert( isReadPtr( str, strLen ) );
	assert( isReadPtr( findStr, findStrLen ) );

	for( i = 0; i < strLen - findStrLen; i++ )
		if( str[ i ] == findCh && \
			!strCompare( str + i, findStr, findStrLen ) )
			return( i );

	return( -1 );
	}

int strStripWhitespace( char **newStringPtr, const char *string,
						const int stringLen )
	{
	int startPos, endPos;

	assert( isWritePtr( newStringPtr, sizeof( char * ) ) );
	assert( isReadPtr( string, stringLen ) );

	/* Skip leading and trailing whitespace */
	for( startPos = 0;
		 startPos < stringLen && string[ startPos ] <= ' ';
		 startPos++ );
	*newStringPtr = ( char * ) string + startPos;
	for( endPos = stringLen;
		 endPos > startPos && string[ endPos - 1 ] <= ' ';
		 endPos-- );
	return( endPos - startPos );
	}

/* Sanitise a string before passing it back to the user.  This is used to
   clear potential problem characters (for example control characters)
   from strings passed back from untrusted sources.  It returns a pointer
   to the string to allow it to be used in the form 
   printf( "..%s..", sanitiseString( string, length ) ) */

char *sanitiseString( char *string, const int stringLength )
	{
	int i;

	assert( isWritePtr( string, stringLength ) );

	/* Remove any potentially unsafe characters from the string */
	for( i = 0; i < stringLength; i++ )
		{
		if( !isPrint( string[ i ] ) )
			string[ i ] = '.';
		}

	/* Terminate the string to allow it to be used in printf()-style
	   functions */
	string[ i ] = '\0';

	return( string );
	}

/****************************************************************************
*																			*
*						TR 24731 Safe stdlib Extensions						*
*																			*
****************************************************************************/

#ifndef __STDC_LIB_EXT1__

/* Minimal wrappers for the TR 24731 functions to map them to older stdlib 
   equivalents */

int mbstowcs_s( size_t *retval, wchar_t *dst, size_t dstmax, 
				const char *src, size_t len )
	{
	*retval = mbstowcs( dst, src, len );
	return( ( *retval > 0 ) ? 0 : -1 );
	}

int wcstombs_s( size_t *retval, char *dst, size_t dstmax, 
				const wchar_t *src, size_t len )
	{
	*retval = wcstombs( dst, src, len );
	return( ( *retval > 0 ) ? 0 : -1 );
	}
#endif /* !__STDC_LIB_EXT1__ */

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
	MESSAGE_DATA msgData;
	const MESSAGE_TYPE message = \
						( attributeType == CRYPT_CERTFORMAT_CERTIFICATE ) ? \
						IMESSAGE_CRT_EXPORT : IMESSAGE_GETATTRIBUTE_S;
	void *dataPtr = NULL;
	int status;

	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isHandleRangeValid( cryptHandle ) && \
			( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) ) );

	/* Clear return value.  Note that we don't use the usual memset() to clear 
	   the value since the structure contains the storage for the fixed-size
	   portion of the buffer appended to it, and using memset() to clear that
	   is just unnecessary overhead */
	dynBuf->data = dynBuf->dataBuffer;
	dynBuf->length = 0;

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
	assert( isWritePtr( dynBuf->data, dynBuf->length ) );

	zeroise( dynBuf->data, dynBuf->length );
	if( dynBuf->data != dynBuf->dataBuffer )
		clFree( "dynDestroy", dynBuf->data );
	}

/****************************************************************************
*																			*
*							Memory Management Routines						*
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
	assert( memPoolSize >= 64 );
	assert( sizeof( MEMPOOL_STATE ) >= sizeof( MEMPOOL_INFO ) );

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

#ifdef __WINCE__

static void wcPrintf( const char *format, ... )
	{
	wchar_t wcBuffer[ 1024 + 8 ];
	char buffer[ 1024 + 8 ];
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsprintf( buffer, format, argPtr );
	va_end( argPtr );
	mbstowcs( wcBuffer, buffer, length + 1 );
	NKDbgPrintfW( wcBuffer );

	return( length );
	}

#define printf		wcPrintf

#endif /* __WINCE__ */

static int clAllocIndex = 0;

void *clAllocFn( const char *fileName, const char *fnName,
				 const int lineNo, size_t size )
	{
	char buffer[ 512 + 8 ];
	BYTE *memPtr;
#ifndef __WINCE__
	int length;
#endif /* __WINCE__ */

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d - %d bytes.\n", clAllocIndex, size );
	if( ( memPtr = malloc( size + sizeof( LONG ) ) ) == NULL )
		return( NULL );
	mputLong( memPtr, clAllocIndex );	/* Implicit memPtr += sizeof( LONG ) */
	clAllocIndex++;
	return( memPtr );
	}

void clFreeFn( const char *fileName, const char *fnName,
			   const int lineNo, void *memblock )
	{
	char buffer[ 512 + 8 ];
	BYTE *memPtr = ( BYTE * ) memblock - sizeof( LONG );
	int index;

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	index = mgetLong( memPtr );
	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d.\n", index );
	free( memPtr - sizeof( LONG ) );
	}
#endif /* CONFIG_DEBUG_MALLOC */

/****************************************************************************
*																			*
*							Stream Export/Import Routines					*
*																			*
****************************************************************************/

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream, however
   we can save some overhead by writing it directly to the stream's buffer.
   
   Some attributes are variable-size (e.g. CRYPT_IATTRIBUTE_RANDOM_NONCE), so
   we allow the caller to specify an optional length parameter indicating
   how much of the attribute should be exported */

static int exportAttr( STREAM *stream, const CRYPT_HANDLE cryptHandle,
					   const CRYPT_ATTRIBUTE_TYPE attributeType,
					   const int length )
	{
	MESSAGE_DATA msgData;
	int attrLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );
	assert( ( length == CRYPT_UNUSED ) || \
			( length >= 8 && length <= 16384 ) );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( length != CRYPT_UNUSED )
		{
		/* It's an explicit-length attribute, make sure that there's enough 
		   room left in the stream for it */
		if( sMemDataLeft( stream ) < length )
			return( CRYPT_ERROR_OVERFLOW );
		attrLength = length;
		}
	else
		{
		/* It's an implicit-length attribute whose maximum length is defined 
		   by the stream size */
		attrLength = sMemDataLeft( stream );
		}

	/* Export the attribute to the stream */
	setMessageData( &msgData, sMemBufPtr( stream ), attrLength );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );

	return( exportAttr( streamPtr, cryptHandle, attributeType, \
						CRYPT_UNUSED ) );
	}

int exportVarsizeAttributeToStream( void *streamPtr, 
									const CRYPT_HANDLE cryptHandle,
									const CRYPT_ATTRIBUTE_TYPE attributeType,
									const int attributeDataLength )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( cryptHandle == SYSTEM_OBJECT_HANDLE );
	assert( attributeType == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	assert( attributeDataLength >= 8 && attributeDataLength <= 1024 );

	return( exportAttr( streamPtr, cryptHandle, attributeType, 
						attributeDataLength ) );
	}

int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	MESSAGE_DATA msgData;
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
						  const CRYPT_CERTTYPE_TYPE certType,
						  const int certDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isWritePtr( cryptCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( certDataLength > 0 && certDataLength < INT_MAX );
	assert( ( certType > CRYPT_CERTTYPE_NONE && \
			  certType < CRYPT_CERTTYPE_LAST ) || \
			( certType == CERTFORMAT_CTL ) );

	/* Clear return value */
	*cryptCertificate = CRYPT_ERROR;

	/* Before we try the import, make sure that everything is OK with the
	   stream and parameters */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE || \
		certDataLength > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Import the cert from the stream */
	setMessageCreateObjectIndirectInfo( &createInfo, sMemBufPtr( stream ),
										certDataLength, certType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = sSkip( stream, certDataLength );
		if( cryptStatusOK( status ) )
			*cryptCertificate = createInfo.cryptHandle;
		else
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Safe Text-line Read Functions					*
*																			*
****************************************************************************/

/* Read a line of text data ending in an EOL.  When we read data we're 
   mostly looking for the EOL marker.  If we find more data than will fit in 
   the input buffer, we discard it until we find an EOL.  As a secondary 
   concern, we want to strip leading, trailing, and repeated whitespace.  We 
   handle the former by setting the seen-whitespace flag to true initially, 
   this treats any whitespace at the start of the line as superfluous and 
   strips it.  We also handle continued lines, denoted by a semicolon or 
   occasionally a backslash as the last non-whitespace character.  Stripping 
   of repeated whitespace is also handled by the seenWhitespace flag, 
   stripping of trailing whitespace is handled by walking back through any 
   final whitespace once we see the EOL, and continued lines are handled by
   setting the seenContinuation flag if we see a semicolon or backslash as
   the last non-whitespace character.

   Finally, we also need to handle generic DoS attacks.  If we see more than
   MAX_LINE_LENGTH chars in a line, we bail out */

#define MAX_LINE_LENGTH		4096

int readTextLine( READCHARFUNCTION readCharFunction, void *streamPtr, 
				  char *buffer, const int maxSize, BOOLEAN *textDataError )
	{
	BOOLEAN seenWhitespace, seenContinuation = FALSE;
	int totalChars, bufPos = 0;

	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( maxSize > 16 );
	assert( isWritePtr( buffer, maxSize ) );
	assert( textDataError == NULL || \
			isWritePtr( textDataError, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	if( textDataError != NULL )
		*textDataError = FALSE;

	/* Set the seen-whitespace flag initially to strip leading whitespace */
	seenWhitespace = TRUE;

	/* Read up to MAX_LINE_LENGTH chars.  Anything longer than this is 
	   probably a DoS */
	for( totalChars = 0; totalChars < MAX_LINE_LENGTH; totalChars++ )
		{
		int ch;

		/* Get the next input character */
		ch = readCharFunction( streamPtr );
		if( cryptStatusError( ch ) )
			return( ch );

		/* If we're over the maximum buffer size, the only character that we 
		   recognise is EOL */
		if( ( bufPos > maxSize - 8 ) && ( ch != '\n' ) )
			{
			/* If we've run off into the weeds (for example we're reading 
			   binary data following the text header), bail out */
			if( !isPrint( ch ) && ch != '\r' )
				{
				*textDataError = TRUE;
				return( CRYPT_ERROR_BADDATA );
				}
			continue;
			}

		/* Process EOL */
		if( ch == '\n' )
			{
			/* Strip trailing whitespace.  At this point it's all been
			   canonicalised so we don't need to check for anything other 
			   than spaces */
			while( bufPos > 0 && buffer[ bufPos - 1 ] == ' ' )
				bufPos--;

			/* If we've seen a continuation marker as the last non-
			   whitespace char, the line continues on the next one */
			if( seenContinuation )
				{
				seenContinuation = FALSE;
				continue;
				}

			/* We're done */
			buffer[ bufPos ] = '\0';
			break;
			}

		/* Process whitespace.  We can't use isspace() for this because it
		   includes all sorts of extra control characters */
		if( ch == ' ' || ch == '\t' )
			{
			if( seenWhitespace )
				/* Ignore leading and repeated whitespace */
				continue;
			ch = ' ';	/* Canonicalise whitespace */
			}

		/* Process any remaining chars */
		if( ch != '\r' )
			{
			if( !( isPrint( ch ) ) )
				{
				*textDataError = TRUE;
				return( CRYPT_ERROR_BADDATA );
				}
			buffer[ bufPos++ ] = ch;
			seenWhitespace = ( ch == ' ' ) ? TRUE : FALSE;
			seenContinuation = ( ch == ';' || ch == '\\' || \
							     ( seenContinuation && \
								   seenWhitespace ) ) ? \
							   TRUE : FALSE;
			}
		}
	if( totalChars >= MAX_LINE_LENGTH )
		{
		*textDataError = TRUE;
		return( CRYPT_ERROR_OVERFLOW );
		}

	return( bufPos );
	}
