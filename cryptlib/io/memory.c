/****************************************************************************
*																			*
*						  Memory Stream I/O Functions						*
*						Copyright Peter Gutmann 1993-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Initialise and shut down a memory stream */

static int initMemoryStream( STREAM *stream, const void *buffer,
							 const int length, const BOOLEAN nullStreamOK )
	{
	/* Check that the input parameters are in order.  Since the return
	   value for the memory stream open functions is rarely (if ever)
	   checked, we validate the buffer and length parameters later and
	   create a read-only null stream if they're invalid, so that reads and
	   writes return error conditions if they're attempted */
	if( !isWritePtr( stream, sizeof( STREAM ) ) )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_WRITE );
		}

	/* Clear the stream data and make it a null stream if required.  Note 
	   that we specifically check for length == 0, since the length < 0 case
	   is handled below */
	memset( stream, 0, sizeof( STREAM ) );
	if( nullStreamOK && buffer == NULL && length == 0 )
		{
		stream->type = STREAM_TYPE_NULL;
		return( CRYPT_OK );
		}

	/* If there's a problem with the parameters, return an error code but
	   also make it a (non-readable, non-writeable) null stream so that it
	   can be safely used */
	if( length < 1 || !isReadPtr( buffer, length ) )
		{
		assert( NOTREACHED );
		stream->type = STREAM_TYPE_NULL;
		stream->flags = STREAM_FLAG_READONLY;
		return( CRYPT_ERROR_WRITE );
		}

	/* Initialise the stream structure */
	stream->type = STREAM_TYPE_MEMORY;
	stream->buffer = ( void * ) buffer;
	stream->bufSize = length;

	return( CRYPT_OK );
	}

static int shutdownMemoryStream( STREAM *stream,
								 const BOOLEAN clearStreamBuffer )
	{
	/* Check that the input parameters are in order */
	if( !isWritePtr( stream, sizeof( STREAM ) ) )
		retIntError();

	/* Clear the stream structure */
	if( clearStreamBuffer && stream->buffer != NULL && stream->bufEnd > 0 )
		zeroise( stream->buffer, stream->bufEnd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Open/close a memory stream.  If the buffer parameter is NULL and the
   length is zero, this creates a null stream that serves as a data sink -
   this is useful for implementing sizeof() functions by writing data to
   null streams */

int sMemOpen( STREAM *stream, void *buffer, const int length )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( buffer == NULL && length == 0 ) || \
			isWritePtr( buffer, length ) );

	/* Initialise the memory stream */
	status = initMemoryStream( stream, buffer, length, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's not a null stream, clear the stream buffer.  Since this can
	   be arbitrarily large, we only clear the entire buffer in the debug
	   version */
	if( buffer != NULL )
		{
#ifdef NDEBUG
		memset( stream->buffer, 0, min( 16, stream->bufSize ) );
#else
		memset( stream->buffer, 0, stream->bufSize );
#endif /* NDEBUG */
		}

	return( CRYPT_OK );
	}

int sMemClose( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY );
	assert( !( stream->flags & STREAM_FLAG_READONLY ) );

	return( shutdownMemoryStream( stream, TRUE ) );
	}

/* Connect/disconnect a memory stream without destroying the buffer
   contents */

int sMemConnect( STREAM *stream, const void *buffer, const int length )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 1 );
	assert( isReadPtr( buffer, length ) );

	/* Initialise the memory stream */
	status = initMemoryStream( stream, buffer, length, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Initialise further portions of the stream structure */
	stream->bufEnd = length;
	stream->flags = STREAM_FLAG_READONLY;

	return( CRYPT_OK );
	}

int sMemDisconnect( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY );

	return( shutdownMemoryStream( stream, FALSE ) );
	}
