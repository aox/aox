/****************************************************************************
*																			*
*							Stream I/O Functions							*
*						Copyright Peter Gutmann 1993-2003					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <stdlib.h>
#if defined( INC_ALL )
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "stream.h"
#else
  #include "misc/stream.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in str_file.c */

int fileRead( STREAM *stream, void *buffer, const int length );
int fileWrite( STREAM *stream, const void *buffer, const int length );
int fileFlush( STREAM *stream );
int fileSeek( STREAM *stream, const long position );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after saving a detailed error message.  This is used by the stream
   transport-layer code to provide more information to the caller than a
   basic error code */

int retExtStreamFn( STREAM *stream, const int status, const char *format, ... )
	{
#ifdef USE_TCP
	va_list argPtr;

	va_start( argPtr, format );
	vsprintf( stream->errorMessage, format, argPtr );
	va_end( argPtr );
#endif /* USE_TCP */
	stream->status = status;
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/* Refill a stream buffer from backing storage */

static int refillStream( STREAM *stream )
	{
	int status;

	assert( stream->type == STREAM_TYPE_FILE );

	/* If we've reached EOF we can't refill it */
	if( stream->flags & STREAM_FFLAG_EOF )
		{
		/* If partial reads are allowed, return an indication of how much 
		   data we got.  This only works once, after this the persistent 
		   error state will return an underflow error before we get to this
		   point */
		stream->status = CRYPT_ERROR_UNDERFLOW;
		return( ( stream->flags & STREAM_FFLAG_PARTIALREAD ) ? \
				OK_SPECIAL : CRYPT_ERROR_UNDERFLOW );
		}

	/* If we've moved to a different place in the file, get new data into 
	   the buffer */
	if( ( stream->flags & STREAM_FFLAG_POSCHANGED ) && \
		!( stream->flags & STREAM_FFLAG_POSCHANGED_NOSKIP ) )
		{
		status = fileSeek( stream, stream->bufCount * stream->bufSize );
		if( cryptStatusError( status ) )
			{
			stream->status = status;
			return( status );
			}
		}

	/* Try and read more data into the stream buffer */
	status = fileRead( stream, stream->buffer, stream->bufSize );
	if( cryptStatusError( status ) )
		{
		stream->status = status;
		return( status );
		}
	if( status < stream->bufSize )
		{
		/* If we got less than we asked for, remember that we're at the end
		   of the file */
		stream->flags |= STREAM_FFLAG_EOF;
		if( status == 0 )
			{
			/* We ran out of input on an exact buffer boundary.  If partial 
			   reads are allowed, return an indication of how much data we 
			   got.  This only works once, after this the persistent error 
			   state will return an underflow error before we get to this 
			   point */
			stream->status = CRYPT_ERROR_UNDERFLOW;
			return( ( stream->flags & STREAM_FFLAG_PARTIALREAD ) ? \
					OK_SPECIAL : CRYPT_ERROR_UNDERFLOW );
			}
		}

	/* We've refilled the stream buffer from the file, remember the 
	   details */
	if( !( stream->flags & STREAM_FFLAG_POSCHANGED ) )
		{
		stream->bufCount++;
		stream->bufPos = 0;
		}
	stream->bufEnd = status;
	stream->flags &= ~( STREAM_FFLAG_POSCHANGED | \
						STREAM_FFLAG_POSCHANGED_NOSKIP );

	return( CRYPT_OK );
	}

/* Empty a stream buffer to backing storage */

static int emptyStream( STREAM *stream, const BOOLEAN forcedFlush )
	{
	int status = CRYPT_OK;

	assert( stream->type == STREAM_TYPE_FILE );

	/* If the stream position has been changed, this can only have been from 
	   a rewind of the stream, in which case we move back to the start of 
	   the file */
	if( stream->flags & STREAM_FFLAG_POSCHANGED )
		{
		status = fileSeek( stream, 0 );
		if( cryptStatusError( status ) )
			{
			stream->status = status;
			return( status );
			}
		}

	/* Try and write the data to the stream's backing storage */
	status = fileWrite( stream, stream->buffer, stream->bufPos );
	if( cryptStatusError( status ) )
		{
		stream->status = status;
		return( status );
		}

	/* Reset the position-changed flag and, if we've written another buffer 
	   full of data, remember the details.  If it's a forced flush we leave
	   everything as is, to remember the last write position in the file */
	stream->flags &= ~STREAM_FFLAG_POSCHANGED;
	if( !forcedFlush )
		{
		stream->bufCount++;
		stream->bufPos = 0;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/Write Functions							*
*																			*
****************************************************************************/

/* Read data from a stream */

int sgetc( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE );
	assert( isReadPtr( stream->buffer, stream->bufSize ) );
	assert( stream->bufPos >= 0 && stream->bufPos <= stream->bufEnd );

	/* If there's a problem with the stream, don't try to do anything */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	switch( stream->type )
		{
		case  STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Read the data from the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				stream->bufPos >= stream->bufEnd )
				{
				stream->status = CRYPT_ERROR_UNDERFLOW;
				return( CRYPT_ERROR_UNDERFLOW );
				}
			return( stream->buffer[ stream->bufPos++ ] );

		case STREAM_TYPE_FILE:
			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* Read the data from the file */
			if( stream->bufPos >= stream->bufEnd || \
				( stream->flags & STREAM_FFLAG_POSCHANGED ) )
				{
				int status = refillStream( stream );
				if( cryptStatusError( status ) )
					return( ( status == OK_SPECIAL ) ? 0 : status );
				}
			return( stream->buffer[ stream->bufPos++ ] );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_READ );		/* Get rid of compiler warning */
	}

int sread( STREAM *stream, void *buffer, const int length )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE || \
			stream->type == STREAM_TYPE_NETWORK );
	assert( stream->bufPos >= 0 && stream->bufPos <= stream->bufEnd );
	assert( stream->type == STREAM_TYPE_NETWORK || \
			isReadPtr( stream->buffer, stream->bufSize ) );
	assert( isWritePtr( buffer, length ) );
	assert( length > 0 );

	/* If there's a problem with the stream, don't try to do anything */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	switch( stream->type )
		{
		case  STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Read the data from the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				stream->bufPos + length > stream->bufEnd )
				{
				memset( buffer, 0, length );	/* Clear the output buffer */
				stream->status = CRYPT_ERROR_UNDERFLOW;
				return( CRYPT_ERROR_UNDERFLOW );
				}
			memcpy( buffer, stream->buffer + stream->bufPos, length );
			stream->bufPos += length;

			return( CRYPT_OK );

		case STREAM_TYPE_FILE:
			{
			BYTE *bufPtr = buffer;
			int dataLength = length, bytesCopied = 0;

			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* Read the data from the file */
			while( dataLength > 0 )
				{
				int bytesToCopy;

				/* If the stream buffer is empty, try and refill it */
				if( stream->bufPos >= stream->bufEnd || \
					( stream->flags & STREAM_FFLAG_POSCHANGED ) )
					{
					status = refillStream( stream );
					if( cryptStatusError( status ) )
						return( ( status == OK_SPECIAL ) ? \
								bytesCopied : status );
					}

				/* Copy as much data as we can out of the stream buffer */
				bytesToCopy = min( dataLength, \
								   stream->bufEnd - stream->bufPos );
				memcpy( bufPtr, stream->buffer + stream->bufPos, 
						bytesToCopy );
				stream->bufPos += bytesToCopy;
				bufPtr += bytesToCopy;
				bytesCopied += bytesToCopy;
				dataLength -= bytesToCopy;
				}

			/* Usually reads are atomic so we just return an all-OK 
			   indicator, however if we're performing partial reads we need
			   to return an exact byte count */
			return( ( stream->flags & STREAM_FFLAG_PARTIALREAD ) ? \
					bytesCopied : CRYPT_OK );
			}

#ifdef USE_TCP
		case STREAM_TYPE_NETWORK:
			assert( !( stream->flags & ~STREAM_NFLAG_MASK ) );
			assert( stream->readFunction != NULL );
			assert( ( stream->flags & STREAM_NFLAG_ISSERVER ) || \
					stream->host != NULL || \
					stream->netSocket != CRYPT_ERROR );
			status = stream->readFunction( stream, buffer, length );

			/* Read the data from the network */
			if( status == CRYPT_ERROR_COMPLETE )
				{
				/* The other side has closed the connection, update the 
				   stream state and map the status to a standard read error.  
				   The exact code to return here is a bit uncertain, it 
				   isn't specifically a read error because either the other 
				   side is allowed to close the connection after it's said 
				   its bit (and so it's not a read error), or it has to 
				   perform a cryptographically protected close (in which 
				   case any non-OK status indicates a problem).  The most 
				   sensible status is probably a read error */
				sioctl( stream, STREAM_IOCTL_CONNSTATE, NULL, FALSE );
				status = CRYPT_ERROR_READ;
				}
			return( status );
#endif /* USE_TCP */
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_READ );		/* Get rid of compiler warning */
	}

/* Write data to a stream */

int sputc( STREAM *stream, const int ch )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->bufSize == STREAMSIZE_UNKNOWN || \
			isWritePtr( stream->buffer, stream->bufSize ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->bufSize == STREAMSIZE_UNKNOWN || \
			stream->bufPos >= 0 && stream->bufPos <= stream->bufSize );
	assert( !( stream->flags & STREAM_FLAG_READONLY ) );

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	switch( stream->type )
		{
		case STREAM_TYPE_NULL:
			assert( !stream->flags );

			/* It's a null stream, just record the write and return */
			stream->bufPos++;
			return( CRYPT_OK );

		case STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Write the data to the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				stream->bufPos >= stream->bufSize )
				{
				stream->status = CRYPT_ERROR_OVERFLOW;
				return( CRYPT_ERROR_OVERFLOW );
				}
			stream->buffer[ stream->bufPos++ ] = ch;

			return( CRYPT_OK );

		case STREAM_TYPE_FILE:
			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* Write the data to the file */
			if( stream->bufPos >= stream->bufSize )
				{
				int status;

				status = emptyStream( stream, FALSE );
				if( cryptStatusError( stream ) )
					return( status );
				}
			stream->buffer[ stream->bufPos++ ] = ch;
			stream->flags |= STREAM_FFLAG_DIRTY;

			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_WRITE );	/* Get rid of compiler warning */
	}

int swrite( STREAM *stream, const void *buffer, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE || \
			stream->type == STREAM_TYPE_NETWORK );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_NETWORK || \
			stream->bufSize == STREAMSIZE_UNKNOWN || \
			isWritePtr( stream->buffer, stream->bufSize ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_NETWORK || \
			stream->bufSize == STREAMSIZE_UNKNOWN || \
			( stream->bufPos >= 0 && stream->bufPos <= stream->bufSize ) );
	assert( isReadPtr( buffer, length ) );
	assert( length > 0 );
	assert( !( stream->flags & STREAM_FLAG_READONLY ) );

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	switch( stream->type )
		{
		case STREAM_TYPE_NULL:
			assert( !stream->flags );

			/* It's a null stream, just record the write and return */
			stream->bufPos += length;
			return( CRYPT_OK );

		case STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Write the data to the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				stream->bufPos + length > stream->bufSize )
				{
				stream->status = CRYPT_ERROR_OVERFLOW;
				return( CRYPT_ERROR_OVERFLOW );
				}
			memcpy( stream->buffer + stream->bufPos, buffer, length );
			stream->bufPos += length;

			return( CRYPT_OK );

		case STREAM_TYPE_FILE:
			{
			const BYTE *bufPtr = buffer;
			int dataLength = length;

			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* Write the data to the file */
			while( dataLength > 0 )
				{
				const int bytesToCopy = \
						min( dataLength, stream->bufSize - stream->bufPos );

				if( bytesToCopy > 0 )
					{
					memcpy( stream->buffer + stream->bufPos, bufPtr, 
							bytesToCopy );
					stream->bufPos += bytesToCopy;
					bufPtr += bytesToCopy;
					dataLength -= bytesToCopy;
					}
				if( stream->bufPos >= stream->bufSize )
					{
					int status;

					status = emptyStream( stream, FALSE );
					if( cryptStatusError( stream ) )
						return( status );
					}
				}
			stream->flags |= STREAM_FFLAG_DIRTY;

			return( CRYPT_OK );
			}

#ifdef USE_TCP
		case STREAM_TYPE_NETWORK:
			assert( !( stream->flags & ~STREAM_NFLAG_MASK ) );
			assert( stream->writeFunction != NULL );
			assert( ( stream->flags & STREAM_NFLAG_ISSERVER ) || \
					stream->host != NULL || \
					stream->netSocket != CRYPT_ERROR );

			/* Write the data to the network */
			return( stream->writeFunction( stream, buffer, length ) );
#endif /* USE_TCP */
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_WRITE );	/* Get rid of compiler warning */
	}

/* Commit data in a stream to backing storage */

int sflush( STREAM *stream )
	{
	int status = CRYPT_OK, flushStatus;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_FILE );
	assert( isReadPtr( stream->buffer, stream->bufSize ) );
	assert( !( stream->flags & STREAM_FLAG_READONLY ) );

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	/* If the data is unchanged, there's nothing to do */
	if( !( stream->flags & STREAM_FFLAG_DIRTY ) )
		return( CRYPT_OK );

	/* If there's data still in the stream buffer, write it to disk */
	if( stream->bufPos > 0 )
		status = emptyStream( stream, TRUE );

	/* Commit the data */
	flushStatus = fileFlush( stream );
	stream->flags &= ~STREAM_FFLAG_DIRTY;

	return( cryptStatusOK( status ) ? flushStatus : status );
	}

/****************************************************************************
*																			*
*								Meta-data Functions							*
*																			*
****************************************************************************/

/* Move to an absolute position in a stream */

int sseek( STREAM *stream, const long position )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_NULL || \
			stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE );
	assert( position >= 0 );

	switch( stream->type )
		{
		case STREAM_TYPE_NULL:
			assert( !stream->flags );

			/* Move to the position in the stream buffer.  We never get 
			   called directly with an sseek on a memory stream, but end up 
			   here via a translated sSkip() call */
			stream->bufPos = ( int ) position;
			return( CRYPT_OK );

		case STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Move to the position in the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				( int ) position > stream->bufSize )
				{
				stream->bufPos = stream->bufSize;
				stream->status = CRYPT_ERROR_UNDERFLOW;
				return( CRYPT_ERROR_UNDERFLOW );
				}
			stream->bufPos = ( int ) position;
			return( CRYPT_OK );

		case STREAM_TYPE_FILE:
			{
			int newBufCount;

			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* If it's a currently-disconnected file stream, all that we can 
			   do is rewind the stream.  This occurs when we're doing an 
			   atomic flush of data to disk and we rewind the stream prior 
			   to writing the new/updated data.  The next buffer-connect 
			   operation will reset the stream state, so there's nothing to 
			   do at this point */
			if( stream->bufSize <= 0 )
				{
				assert( position == 0 );
				return( CRYPT_OK );
				}

			/* It's a file stream, remember the new position in the file */
			newBufCount = position / stream->bufSize;
			if( newBufCount != stream->bufCount )
				{
				/* We're not within the current buffer any more, remember 
				   that we have to explicitly update the file position on
				   the next read */
				stream->flags |= STREAM_FFLAG_POSCHANGED;

				/* If we're already positioned to read the next bufferful 
				   of data, we don't have to explicitly skip ahead to it */
				if( newBufCount == stream->bufCount + 1 ) 
					stream->flags |= STREAM_FFLAG_POSCHANGED_NOSKIP ;

				stream->bufCount = newBufCount;
				}
			stream->bufPos = position % stream->bufSize;
			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_WRITE );	/* Get rid of compiler warning */
	}

/* Peek at the next data value in a stream */

int sPeek( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stream->type == STREAM_TYPE_MEMORY || \
			stream->type == STREAM_TYPE_FILE );
	assert( isReadPtr( stream->buffer, stream->bufSize ) );
	assert( stream->bufPos >= 0 && stream->bufPos <= stream->bufEnd );

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( cryptStatusError( stream->status ) )
		return( stream->status );

	/* Read the data from the buffer, but without advancing the read pointer
	   like sgetc() does */
	switch( stream->type )
		{
		case  STREAM_TYPE_MEMORY:
			assert( !( stream->flags & ~STREAM_FLAG_MASK ) );

			/* Read the data from the stream buffer */
			if( stream->bufSize != STREAMSIZE_UNKNOWN && \
				stream->bufPos >= stream->bufEnd )
				{
				stream->status = CRYPT_ERROR_UNDERFLOW;
				return( CRYPT_ERROR_UNDERFLOW );
				}
			return( stream->buffer[ stream->bufPos ] );

		case STREAM_TYPE_FILE:
			assert( !( stream->flags & ~STREAM_FFLAG_MASK ) );

			/* Read the data from the file */
			if( stream->bufPos >= stream->bufEnd || \
				( stream->flags & STREAM_FFLAG_POSCHANGED ) )
				{
				int status = refillStream( stream );
				if( cryptStatusError( status ) )
					return( ( status == OK_SPECIAL ) ? 0 : status );
				}
			return( stream->buffer[ stream->bufPos ] );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_READ );		/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								IOCTL Functions								*
*																			*
****************************************************************************/

/* Perform an IOCTL on a stream */

int sioctl( STREAM *stream, const STREAM_IOCTL_TYPE type, void *data,
			const int dataLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( stream->type == STREAM_TYPE_FILE && \
			  ( type == STREAM_IOCTL_IOBUFFER || \
				type == STREAM_IOCTL_PARTIALREAD ) ) || \
			( stream->type == STREAM_TYPE_NETWORK && \
			  type != STREAM_IOCTL_PARTIALREAD ) );
	assert( type > STREAM_IOCTL_NONE && type < STREAM_IOCTL_LAST );

	switch( type )
		{
		case STREAM_IOCTL_IOBUFFER:
			assert( ( data == NULL && dataLen == 0 ) || \
					isWritePtr( data, dataLen ) );
			assert( dataLen == 0 || \
					dataLen == 512 || dataLen == 1024 || \
					dataLen == 2048 || dataLen == 4096 || \
					dataLen == 8192 || dataLen == 16384 );

			stream->buffer = data;
			stream->bufSize = dataLen;

			/* We've switched to a new I/O buffer, reset all buffer- and 
			   stream-state related variables and remember that we have to 
			   reset the stream position, since there may be a position-
			   change pending that hasn't been reflected down to the 
			   underlying file yet (if it was within the same buffer, the 
			   POSCHANGED flag won't have been set since only the bufPos is 
			   changed) */
			stream->bufPos = stream->bufEnd = stream->bufCount = 0;
			stream->status = CRYPT_OK;
			stream->flags &= ~( STREAM_FFLAG_EOF | \
								STREAM_FFLAG_POSCHANGED_NOSKIP );
			stream->flags |= STREAM_FFLAG_POSCHANGED;
			break;

		case STREAM_IOCTL_PARTIALREAD:
			assert( data == NULL && dataLen == 0 );

			stream->flags |= STREAM_FFLAG_PARTIALREAD;
			break;

#ifdef USE_TCP
		case STREAM_IOCTL_TIMEOUT:
			if( data != NULL )
				{
				assert( dataLen == 0 );

				*( ( int * ) data ) = stream->timeout;
				}
			else
				{
				assert( dataLen >= 0 );
				stream->timeout = dataLen;
				if( stream->iTransportSession != CRYPT_ERROR )
					krnlSendMessage( stream->iTransportSession,
									 IMESSAGE_SETATTRIBUTE, &stream->timeout,
									 CRYPT_OPTION_NET_TIMEOUT );
				}
			break;

		case STREAM_IOCTL_HANDSHAKETIMEOUT:
			{
			int value;

			assert( data == NULL );
			assert( dataLen == 0 );

			/* We're overriding the standard stream timeout to allow the
			   handshake to proceed correctly even if the user has selected
			   nonblocking reads.  This is done by swapping the actual and
			   saved timeout, and undone by swapping them back again */
			value = stream->savedTimeout;
			stream->savedTimeout = stream->timeout;
			stream->timeout = value;
			if( stream->iTransportSession != CRYPT_ERROR )
				krnlSendMessage( stream->iTransportSession,
								 IMESSAGE_SETATTRIBUTE, &stream->timeout,
								 CRYPT_OPTION_NET_CONNECTTIMEOUT );
			break;
			}

		case STREAM_IOCTL_CONNSTATE:
			if( data != NULL )
				{
				assert( dataLen == 0 );

				*( ( int * ) data ) = \
								( stream->flags & STREAM_NFLAG_LASTMSG ) ? \
								FALSE : TRUE;
				}
			else
				{
				assert( dataLen == TRUE || dataLen == FALSE );
				if( dataLen )
					stream->flags &= ~STREAM_NFLAG_LASTMSG;
				else
					stream->flags |= STREAM_NFLAG_LASTMSG;
				}
			break;

		case STREAM_IOCTL_GETCLIENTNAME:
			assert( data != NULL );
			assert( dataLen == 0 );

			strcpy( data, stream->clientAddress );
			break;

		case STREAM_IOCTL_GETCLIENTPORT:
			assert( data != NULL );
			assert( dataLen == 0 );

			*( ( int * ) data ) = stream->clientPort;
			break;

		case STREAM_IOCTL_CONTENTTYPE:
			assert( stream->protocol == STREAM_PROTOCOL_HTTP || \
					stream->protocol == STREAM_PROTOCOL_HTTP_TRANSACTION );
			assert( isWritePtr( data, dataLen ) );
			assert( dataLen > 0 && dataLen < CRYPT_MAX_TEXTSIZE );

			memcpy( stream->contentType, data, dataLen );
			stream->contentType[ dataLen ] = '\0';
			break;

		case STREAM_IOCTL_QUERY:
			assert( stream->protocol == STREAM_PROTOCOL_HTTP || \
					stream->protocol == STREAM_PROTOCOL_HTTP_TRANSACTION );
			assert( isWritePtr( data, dataLen ) );
			assert( dataLen > 0 && dataLen < CRYPT_MAX_TEXTSIZE );

			/* Set up the buffer to contain the query if necessary */
			if( stream->queryLen <= dataLen + 1 )
				{
				if( stream->query != NULL )
					{
					clFree( "sioctl", stream->query );
					stream->queryLen = 0;
					}
				if( ( stream->query = \
						clAlloc( "sioctl", max( CRYPT_MAX_TEXTSIZE, \
												dataLen + 1 ) ) ) == NULL )
					{
					stream->status = CRYPT_ERROR_MEMORY;
					return( CRYPT_ERROR_MEMORY );
					}
				stream->queryLen = dataLen;
				}

			/* Copy in the query */
			memcpy( stream->query, data, dataLen );
			stream->query[ dataLen ] = '\0';
			break;

		case STREAM_IOCTL_LASTMESSAGE:
			assert( stream->protocol == STREAM_PROTOCOL_HTTP || \
					stream->protocol == STREAM_PROTOCOL_HTTP_TRANSACTION || \
					stream->protocol == STREAM_PROTOCOL_CMP );
			assert( data == NULL );
			assert( dataLen == TRUE );

			stream->flags |= STREAM_NFLAG_LASTMSG;
			break;

		case STREAM_IOCTL_CALLBACKFUNCTION:
			assert( stream->protocol == STREAM_PROTOCOL_HTTP || \
					stream->protocol == STREAM_PROTOCOL_HTTP_TRANSACTION );
			assert( data != NULL );
			assert( dataLen == 0 );

			stream->callbackFunction = ( CALLBACKFUNCTION ) data;
			break;

		case STREAM_IOCTL_CALLBACKPARAMS:
			assert( stream->protocol == STREAM_PROTOCOL_HTTP || \
					stream->protocol == STREAM_PROTOCOL_HTTP_TRANSACTION );
			assert( data != NULL );
			assert( dataLen == 0 );

			stream->callbackParams = data;
			break;

		case STREAM_IOCTL_CLOSESENDCHANNEL:
			assert( data == NULL );
			assert( dataLen == 0 );
			assert( !( stream->flags & STREAM_NFLAG_USERSOCKET ) );

			/* If this is a user-supplied socket, we can't perform a partial 
			   close without affecting the socket as seen by the user, so we 
			   only perform the partial close if it's a cryptlib-controlled 
			   socket */
			if( !( stream->flags & STREAM_NFLAG_USERSOCKET ) )
				stream->transportDisconnectFunction( stream, FALSE );
			break;
#endif /* USE_TCP */

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}
