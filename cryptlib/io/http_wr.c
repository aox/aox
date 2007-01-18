/****************************************************************************
*																			*
*						  cryptlib HTTP Write Routines						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "http.h"
#else
  #include "crypt.h"
  #include "io/http.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Encode a string as per RFC 1866 (although the list of characters that 
   need to be escaped is itself given in RFC 2396).  Characters that are 
   permitted/not permitted are:

	 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	x..x.xx....x...xxxxxxxxxxxx.xxxxx

   Because of this it's easier to check for the most likely permitted
   characters (alphanumerics), and then to check for any special-case
   chars */

static void encodeRFC1866( STREAM *headerStream, const char *string, 
						   const int stringLength )
	{
	static const char allowedChars[] = "$-_.!*'(),\"/";	/* RFC 1738 + '/' */
	int index = 0;

	assert( isWritePtr( headerStream, sizeof( STREAM ) ) );
	assert( isReadPtr( string, stringLength ) );

	while( index < stringLength )
		{
		const int ch = string[ index++ ];
		int i;

		if( isAlnum( ch ) )
			{
			sputc( headerStream, ch );
			continue;
			}
		if( ch == ' ' )
			{
			sputc( headerStream, '+' );
			continue;
			}
		for( i = 0; allowedChars[ i ] != '\0' && ch != allowedChars[ i ] && \
					i < FAILSAFE_ARRAYSIZE( allowedChars, char ) + 1; i++ );
		if( i >= FAILSAFE_ARRAYSIZE( allowedChars, char ) + 1 )
			retIntError_Void();
		if( allowedChars[ i ] != '\0' )
			/* It's in the allowed-chars list, output it verbatim */
			sputc( headerStream, ch );
		else
			{
			char escapeString[ 16 ];
			int escapeStringLen;

			/* It's a special char, escape it */
			escapeStringLen = sPrintf_s( escapeString, 8, "%%%02X", ch );
			swrite( headerStream, escapeString, escapeStringLen );
			}
		}
	}

/* If we time out when sending HTTP header data this would usually be 
   reported as a CRYPT_ERROR_TIMEOUT by the lower-level network I/O 
   routines, however due to the multiple layers of I/O and special case 
   timeout handling when (for example) a cryptlib transport session is 
   layered over the network I/O layer and the fact that to the caller the
   write of the out-of-band HTTP header data (which can occur as part of a 
   standard HTTP write, but also in a GET or when sending an error
   response) is invisible, we have to perform an explicit check to make 
   sure that we sent everything */

int sendHTTPData( STREAM *stream, void *buffer, const int length,
				  const int flags )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( buffer, length ) );

	status = stream->bufferedTransportWriteFunction( stream, buffer, length, 
													 flags );
	if( cryptStatusError( status ) )
		/* Network-level error, the lower-level layers have reported the 
		   error details */
		return( status );
	if( status < length )
		/* The write timed out, convert the incomplete HTTP header write to 
		   the appropriate timeout error */
		retExtStream( stream, CRYPT_ERROR_TIMEOUT,
					  "HTTP write timed out before all data could be "
					  "written" );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write Request/Response Header					*
*																			*
****************************************************************************/

/* Write an HTTP request header */

int writeRequestHeader( STREAM *stream, const int contentLength )
	{
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	const int transportFlag = ( contentLength > 0 ) ? TRANSPORT_FLAG_NONE : \
													  TRANSPORT_FLAG_FLUSH;
	const int hostLen = strlen( stream->host );
	int headerLength;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( contentLength >= 0 );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( stream->flags & STREAM_NFLAG_HTTPTUNNEL )
		swrite( &headerStream, "CONNECT ", 8 );
	else
		if( contentLength > 0 )
			swrite( &headerStream, "POST ", 5 );
		else
			swrite( &headerStream, "GET ", 4 );
	if( ( stream->flags & STREAM_NFLAG_HTTPPROXY ) || \
		( stream->flags & STREAM_NFLAG_HTTPTUNNEL ) )
		{
		/* If we're going through an HTTP proxy/tunnel, send an absolute URL 
		   rather than just the relative location */
		if( stream->flags & STREAM_NFLAG_HTTPPROXY )
			swrite( &headerStream, "http://", 7 );
		swrite( &headerStream, stream->host, hostLen );
		if( stream->port != 80 )
			{
			char portString[ 16 + 8 ];
			int portStringLength;

			portStringLength = sprintf_s( portString, 16, ":%d", 
										  stream->port );
			swrite( &headerStream, portString, portStringLength );
			}
		}
	if( !( stream->flags & STREAM_NFLAG_HTTPTUNNEL ) )
		{
		if( stream->path != NULL && *stream->path != '\0' )
			swrite( &headerStream, stream->path, strlen( stream->path ) );
		else
			sputc( &headerStream, '/' );
		}
	if( stream->query != NULL && *stream->query != '\0' )
		{
		sputc( &headerStream, '?' );
		encodeRFC1866( &headerStream, stream->query, 
					   strlen( stream->query ) );
		}
	if( isHTTP10( stream ) )
		swrite( &headerStream, " HTTP/1.0\r\n", 11 );
	else
		{
		swrite( &headerStream, " HTTP/1.1\r\nHost: ", 17 );
		swrite( &headerStream, stream->host, hostLen );
		swrite( &headerStream, "\r\n", 2 );
		if( stream->flags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	if( contentLength > 0 )
		{
		char lengthString[ 8 + 8 ];
		int lengthStringLength;

		swrite( &headerStream, "Content-Type: ", 14 );
		swrite( &headerStream, stream->contentType, 
				strlen( stream->contentType ) );
		swrite( &headerStream, "\r\nContent-Length: ", 18 );
		lengthStringLength = sPrintf_s( lengthString, 8, "%d", 
										contentLength );
		swrite( &headerStream, lengthString, lengthStringLength );
		swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
		}
	swrite( &headerStream, "\r\n", 2 );
	headerLength = stell( &headerStream );
	assert( sStatusOK( &headerStream ) );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, headerLength, 
						  transportFlag ) );
	}

/* Write an HTTP response header */

static int writeResponseHeader( STREAM *stream, const int contentLength )
	{
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ], lengthString[ 8 + 8 ];
	int headerLength, lengthStringLength;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( contentLength > 0 );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "HTTP/1.0 200 OK\r\n", 17 );
	else
		{
		swrite( &headerStream, "HTTP/1.1 200 OK\r\n", 17 );
		if( stream->flags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	swrite( &headerStream, "Content-Type: ", 14 );
	swrite( &headerStream, stream->contentType, 
			strlen( stream->contentType ) );
	swrite( &headerStream, "\r\nContent-Length: ", 18 );
	lengthStringLength = sPrintf_s( lengthString, 8, "%d", 
									contentLength );
	swrite( &headerStream, lengthString, lengthStringLength );
	swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "Pragma: no-cache\r\n", 18 );
	swrite( &headerStream, "\r\n", 2 );
	headerLength = stell( &headerStream );
	assert( sStatusOK( &headerStream ) );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, headerLength,
						  TRANSPORT_FLAG_NONE ) );
	}

/****************************************************************************
*																			*
*							HTTP Access Functions							*
*																			*
****************************************************************************/

/* Write data to an HTTP stream */

static int writeFunction( STREAM *stream, const void *buffer,
						  const int length )
	{
	int localLength = length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( buffer, length ) );

	/* Send the out-of-band HTTP header data to the client or server */
	if( stream->flags & STREAM_NFLAG_ISSERVER )
		{
		/* If it's an idempotent get, decode the returned data */
		if( stream->flags & STREAM_NFLAG_IDEMPOTENT )
			{
			const BYTE *bufPtr = buffer;

			status = ( short int ) mgetWord( bufPtr );
			if( cryptStatusError( status ) )
				{
				char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];

				/* It's an error status response, send the translated
				   error status and exit.  We have to map the send return
				   value to a written byte count to avoid triggering the
				   incomplete-write check at the higher level */
				status = sendHTTPError( stream, headerBuffer, HTTP_LINEBUF_SIZE,
							( status == CRYPT_ERROR_NOTFOUND ) ? 404 : \
							( status == CRYPT_ERROR_PERMISSION ) ? 401 : \
																400 );
				return( cryptStatusError( status ) ? status : length );
				}
			buffer = bufPtr;
			localLength -= 2;
			}

		status = writeResponseHeader( stream, localLength );
		}
	else
		{
		assert( ( stream->flags & STREAM_NFLAG_HTTPTUNNEL ) || \
				strlen( stream->contentType ) );
		assert( !( ( stream->flags & STREAM_NFLAG_HTTPPROXY ) && 
				   ( stream->flags & STREAM_NFLAG_HTTPTUNNEL ) ) );
		assert( stream->host != NULL );

		status = writeRequestHeader( stream, localLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the payload data to the client/server.  Since we may have 
	   modified the length of the data being written we have to be careful 
	   to return the correct amount to avoid triggering incomplete-write 
	   checks */
	status = stream->bufferedTransportWriteFunction( stream, buffer, localLength,
													 TRANSPORT_FLAG_FLUSH );
	return( ( status == localLength ) ? length : status );
	}

void setStreamLayerHTTPwrite( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Set the remaining access method pointers */
	stream->writeFunction = writeFunction;
	}
#endif /* USE_HTTP */
