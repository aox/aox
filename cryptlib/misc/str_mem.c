/****************************************************************************
*																			*
*						  Memory Stream I/O Functions						*
*						Copyright Peter Gutmann 1993-2003					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "stream.h"
#else
  #include "misc/stream.h"
#endif /* Compiler-specific includes */

/* Open/close a memory stream.  If the buffer parameter is NULL and the 
   length is zero, this creates a null stream that serves as a data sink - 
   this is useful for implementing sizeof() functions by writing data to 
   null streams */

int sMemOpen( STREAM *stream, void *buffer, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( buffer == NULL && length == 0 ) || \
			( isWritePtr( buffer, length ) && \
			  ( length > 1 || length == STREAMSIZE_UNKNOWN ) ) );

	memset( stream, 0, sizeof( STREAM ) );
	if( buffer == NULL )
		{
		/* Make it a null stream */
		stream->type = STREAM_TYPE_NULL;
		return( CRYPT_OK );
		}

	/* Initialise the stream structure */
	stream->type = STREAM_TYPE_MEMORY;
	stream->buffer = buffer;
	stream->bufSize = length;
	if( stream->bufSize != STREAMSIZE_UNKNOWN )
		{
		/* The stream buffers can be arbitrarily large so we only clear
		   the entire buffer in the debug version */
#ifdef NDEBUG
		memset( stream->buffer, 0, min( 256, stream->bufSize ) );
#else
		assert( isWritePtr( buffer, length ) );
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

	/* Clear the stream structure */
	if( stream->buffer != NULL && stream->bufEnd > 0 )
		zeroise( stream->buffer, stream->bufEnd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Connect/disconnect a memory stream without destroying the buffer 
   contents */

int sMemConnect( STREAM *stream, const void *buffer, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( buffer, length ) );
	assert( length >= 1 || length == STREAMSIZE_UNKNOWN );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_MEMORY;
	stream->buffer = ( void * ) buffer;
	stream->bufSize = stream->bufEnd = length;
	stream->flags = STREAM_FLAG_READONLY;

	return( CRYPT_OK );
	}

int sMemDisconnect( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY );

	/* Clear the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	return( CRYPT_OK );
	}
