/****************************************************************************
*																			*
*						Network Stream I/O Functions						*
*						Copyright Peter Gutmann 1993-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "stream.h"
#else
  #include "misc/stream.h"
#endif /* Compiler-specific includes */

#ifdef USE_TCP

/* Network streams can work on multiple levels.  At the lowest level we have
   the raw network I/O layer, handled by calling setAccessMethodXXX(), which
   hooks up the transport-level I/O functions.  If there's a requirement to
   replace the built-in network I/O, it can be done by replacing the 
   functionality at this level.

   Layered on top of the transport-level I/O via setStreamLayerXXX() is an
   optional higher layer protocol such as HTTP, which is added by calling
   the appropriate function to layer the higher-level protocol over the
   transport-level I/O.  Alternatively, we can use setStreamLayerDirect()
   to just pass the call straight down to the transport layer.

   In addition to these two layers, the higher level read requires an extra
   buffering layer in order to avoid making many calls to the transport-
   level I/O function, which is a particular problem for HTTP which has to
   take input a character at a time.  To avoid this problem, we use the
   bufferedRead layer which reads ahead as far as it can and then feeds the
   buffered result back to the caller as required.  We also need to use write 
   buffering to avoid potential problems with interactions with some 
   transport layers, details are given in the comment for the buffered write 
   function.

   The layering looks as follows:

	--- httpRead ---+-- bufferedRead ---+--- tcpRead
		cmpRead							|
										+--- clibRead
										|
	------------------------------------+--- otherRead

	--- httpWrite --+-- bufferedWrite --+---- tcpWrite
		cmpWrite						|
										+---- clibWrite
										|
	------------------------------------+---- otherWrite

   When we allocate the readahead/write buffers we try and make them an 
   optimal size to minimise unnecessary copying and not negatively affect 
   network I/O.  If we make them too big, we'll have to move too much data 
   around when we partially empty them.  If we make them too small, the 
   buffering effect is suboptimal.  Since what we're buffering is PKI 
   traffic, a 4K buffer should get most messages in one go.  This also 
   matches many network stacks that use 4K I/O buffers, the BSD default */

#define NETWORK_BUFFER_SIZE		4096

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Open a connection through a proxy.  This is currently disabled since it 
   appears to be unused by anyone */

#if 0

static int connectStreamProxy( STREAM *stream )
	{
	RESOURCE_DATA msgData;
	BYTE socksBuffer[ 64 + CRYPT_MAX_TEXTSIZE ], *bufPtr = socksBuffer;
	const char *hostNamePtr = stream->host;
	char proxyName[ MAX_URL_SIZE + 1 ], userName[ CRYPT_MAX_TEXTSIZE + 1 ];
	unsigned short localPort = stream->port;
	int length, status;

	/* Get the proxy and user name, defaulting to "cryptlib" if there's none 
	   set */
	setMessageData( &msgData, proxyName, MAX_URL_SIZE );
	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_OPTION_NET_SOCKS_SERVER );
	if( cryptStatusError( status ) )
		retExtStream( stream, CRYPT_ERROR_OPEN, 
					  "Couldn't get SOCKS server name" );
	proxyName[ msgData.length ] = '\0';
	setMessageData( &msgData, userName, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_OPTION_NET_SOCKS_USERNAME );
	if( cryptStatusOK( status ) )
		userName[ msgData.length ] = '\0';
	else
		strcpy( userName, "cryptlib" );
	hostNamePtr = proxyName;
	localPort = 1080;	/* SOCKS port */

	/* Try and open the connection to the proxy server */
	status = stream->transportConnectFunction( stream, hostNamePtr, 
											   localPort );
	if( cryptStatusError( status ) )
		return( status );

	/* Build up the socks request string:
		BYTE: version = 4
		BYTE: command = 1 (connect)
		WORD: port
		LONG: IP address
		STRING: userName + '\0' */
	*bufPtr++ = 4; *bufPtr++ = 1;
	mputWord( bufPtr, stream->port );
	status = getIPAddress( stream, bufPtr, stream->host );
	strcpy( bufPtr + 4, userName );
	length = 1 + 1 + 2 + 4 + strlen( userName ) + 1;
	if( cryptStatusError( status ) )
		{
		stream->transportDisconnectFunction( stream, TRUE );
		return( status );
		}

	/* Send the data to the server and read back the reply */
	status = stream->transportWriteFunction( stream, socksBuffer, length,
											 TRANSPORT_FLAG_FLUSH );
	if( cryptStatusOK( status ) )
		status = stream->transportReadFunction( stream, socksBuffer, 8,
												TRANSPORT_FLAG_BLOCKING );
	if( cryptStatusError( status ) )
		{
		/* The involvement of a proxy complicates matters somewhat because
		   we can usually connect to the proxy OK but may run into problems
		   going from the proxy to the remote server, so if we get an error
		   at this stage (which will typically show up as a read error from
		   the proxy) we report it as an open error instead */
		if( status == CRYPT_ERROR_READ || status == CRYPT_ERROR_COMPLETE )
			status = CRYPT_ERROR_OPEN;
		stream->transportDisconnectFunction( stream, TRUE );
		return( status );
		}

	/* Make sure that everything is OK, the second returned byte should be 
	   90 */
	if( socksBuffer[ 1 ] != 90 )
		{
		int i;

		stream->transportDisconnectFunction( stream, TRUE );
		strcpy( stream->errorMessage, "Socks proxy returned" );
		for( i = 0; i < 8; i++ )
			sPrintf( stream->errorMessage + 20 + ( i * 3 ),
					 " %02X", socksBuffer[ i ] );
		strcat( stream->errorMessage, "." );
		stream->errorCode = socksBuffer[ 1 ];
		return( CRYPT_ERROR_OPEN );
		}

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Copy error information from a cryptlib transport-layer session into a 
   stream */

static int getSessionErrorInfo( STREAM *stream, const int errorStatus )
	{
	RESOURCE_DATA msgData;
	int status;

	status = krnlSendMessage( stream->iTransportSession,
							  IMESSAGE_GETATTRIBUTE, &stream->errorCode,
							  CRYPT_ATTRIBUTE_INT_ERRORCODE );
	if( cryptStatusError( status ) )
		stream->errorCode = CRYPT_OK;
	setMessageData( &msgData, stream->errorMessage, MAX_ERRMSG_SIZE );
	krnlSendMessage( stream->iTransportSession, IMESSAGE_GETATTRIBUTE, 
					 &msgData, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );
	return( errorStatus );
	}

/****************************************************************************
*																			*
*							URL Processing Functions						*
*																			*
****************************************************************************/

/* Perform various string-processing operations */

static int strFindCh( const char *str, const int strLen, const char findCh )
	{
	int i;

	for( i = 0; i < strLen; i++ )
		if( str[ i ] == findCh )
			return( i );

	return( -1 );
	}

static int strFindStr( const char *str, const int strLen, 
					   const char *findStr, const int findStrLen )
	{
	const char findCh = *findStr;
	int i;

	for( i = 0; i < strLen - findStrLen; i++ )
		if( str[ i ] == findCh && \
			!strCompare( str + i, findStr, findStrLen ) )
			return( i );

	return( -1 );
	}

static int strStripWhitespace( char **newStringPtr, const char *string, 
							   const int stringLen )
	{
	int startPos, endPos;

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

/* Parse a URI into <schema>://<host>[:<port>]/<path>[?<query>] components */

static int parseURL( URL_INFO *urlInfo, const char *url, const int urlLen,
					 const int defaultPort )
	{
	static const FAR_BSS struct {
		const char *schema;
		const int schemaLength;
		const URL_TYPE type;
		} urlSchemaInfo[] = {
		{ "http://", 7, URL_TYPE_HTTP },
		{ "https://", 8, URL_TYPE_HTTPS },
		{ "ssh://", 6, URL_TYPE_SSH },
		{ "scp://", 6, URL_TYPE_SSH },
		{ "sftp://", 7, URL_TYPE_SSH },
		{ "cmp://", 6, URL_TYPE_CMP },
		{ "tsp://", 6, URL_TYPE_TSP },
		{ NULL, 0, URL_TYPE_NONE }
		};
	char *strPtr;
	int offset, length;

	/* Clear return values */
	memset( urlInfo, 0, sizeof( URL_INFO ) );
	if( defaultPort != CRYPT_UNUSED )
		urlInfo->port = defaultPort;

	/* Skip leading and trailing whitespace and syntactic sugar */
	length = strStripWhitespace( &strPtr, url, urlLen );
	if( length <= 0 )
		return( CRYPT_ERROR_BADDATA );
	if( length >= MAX_URL_SIZE )
		return( CRYPT_ERROR_OVERFLOW );
	if( ( offset = strFindStr( strPtr, length, "://", 3 ) ) >= 0 )
		{
		int i;

		/* Extract the URI schema */
		urlInfo->schema = strPtr;
		urlInfo->schemaLen = offset + 3;
		length -= offset + 3;
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );
		strPtr += offset + 3;
		length = strStripWhitespace( &strPtr, strPtr, length );
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );

		/* Check whether the schema is one that we recognise */
		for( i = 0; urlSchemaInfo[ i ].type != URL_TYPE_NONE; i++ )
			if( urlSchemaInfo[ i ].schemaLength == urlInfo->schemaLen && \
				!strCompare( urlSchemaInfo[ i ].schema, urlInfo->schema,
							 urlInfo->schemaLen ) )
				break;
		urlInfo->type = urlSchemaInfo[ i ].type;
		}

	/* Check for user info before an '@' sign */
	if( ( offset = strFindCh( strPtr, length, '@' ) ) >= 0 )
		{
		/* Extract the user info */
		urlInfo->userInfoLen = \
					strStripWhitespace( ( char ** ) &urlInfo->userInfo, 
										strPtr, offset );
		length -= offset + 1;
		if( length <= 0 || urlInfo->userInfoLen <= 0 )
			return( CRYPT_ERROR_BADDATA );
		strPtr += offset + 1;
		length = strStripWhitespace( &strPtr, strPtr, length );
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );
		}

	/* IPv6 addresses use colons in their string representation, RFC 2732 
	   requires that IPv6 addresses in URLs be delimited by square brackets 
	   so if we find one at the start of the URI we treat it as an IPv6 
	   address */
	if( *strPtr == '[' && \
		( length != 12 || strCompareZ( strPtr, "[Autodetect]" ) ) )
		{
		/* Strip the leading '[' delimiter */
		length = strStripWhitespace( &strPtr, strPtr + 1, length - 1 );
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );

		/* Locate the end of the RFC 2732 IPv6 address.  Trailing whitespace
		   will be stripped later */
		if( ( offset = strFindCh( strPtr, length, ']' ) ) <= 0 )
			return( CRYPT_ERROR_BADDATA );
		urlInfo->host = strPtr;
		urlInfo->hostLen = offset;
		strPtr += offset + 1;
		length -= offset + 1;
		}
	else
		{
		int offset2;

		/* It's a non-IPv6 host name, check whether there's anything 
		   following the name */
		urlInfo->host = strPtr;
		offset = strFindCh( strPtr, length, ':' );
		offset2 = strFindCh( strPtr, length, '/' );
		if( offset < 0 )
			offset = offset2;
		else
			{
			assert( offset >= 0 );
			if( offset2 >= 0 )
				offset = min( offset, offset2 );
			}
		if( offset <= 0 )
			{
			/* It's a standalone server name, we're done */
			urlInfo->hostLen = length;
			return( CRYPT_OK );
			}

		/* There's port/location info following the server name.  Trailing 
		   whitespace will be stripped later */
		urlInfo->hostLen = offset;
		strPtr += offset;
		length -= offset;
		}
	urlInfo->hostLen = strStripWhitespace( ( char ** ) &urlInfo->host, 
										   urlInfo->host, urlInfo->hostLen );
	if( urlInfo->hostLen <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* If there's nothing beyond the host name, we're done */
	if( length <= 0 )
		return( CRYPT_OK );
	length = strStripWhitespace( &strPtr, strPtr, length );
	if( length <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Parse the remainder of the URI into port/location */
	if( *strPtr == ':' )
		{
		char portBuffer[ 16 ];
		const int portStrLen = min( length - 1, 15 );
		int port;

		/* Get the port to connect to.  If it's an invalid port we ignore it
		   and use the default one, which was set earlier */
		if( portStrLen <= 0 )
			return( CRYPT_ERROR_BADDATA );
		memcpy( portBuffer, strPtr + 1, portStrLen );
		portBuffer[ portStrLen ] = '\0';
		port = aToI( portBuffer );
		if( port >= 22 && port < 65535 )
			urlInfo->port = port;
		}
	if( ( offset = strFindCh( strPtr, length, '/' ) ) >= 0 )
		{
		const int locationLength = length - offset;

		if( locationLength <= 0 )
			return( CRYPT_ERROR_BADDATA );
		urlInfo->locationLen = \
					strStripWhitespace( ( char ** ) &urlInfo->location, 
										strPtr + offset, locationLength );
		if( urlInfo->locationLen <= 0 )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/* Copy parsed URL info to a stream structure */

static int copyUrlToStream( STREAM *stream, const URL_INFO *urlInfo )
	{
	if( ( stream->host = clAlloc( "copyUrlToStream", \
								  urlInfo->hostLen + 1 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( stream->host, urlInfo->host, urlInfo->hostLen );
	stream->host[ urlInfo->hostLen ] = '\0';
	if( urlInfo->location != NULL )
		{
		if( ( stream->path = \
				clAlloc( "copyUrlToStream", urlInfo->locationLen + 1 ) ) == NULL )
			{
			clFree( "copyUrlToStream", stream->host );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( stream->path, urlInfo->location, urlInfo->locationLen );
		stream->path[ urlInfo->locationLen ] = '\0';
		}
	stream->port = urlInfo->port;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Buffering Functions							*
*																			*
****************************************************************************/

/* Buffered transport-layer read function.  This sits on top of the 
   transport-layer read function and performs speculative read-ahead 
   buffering to improve performance in protocols such as HTTP that have to
   read a byte at a time in places:

		   bPos		   bEnd
			|			|
			v			v
	+-------+-----------+-------+
	|		|///////////|		|
	+-------+-----------+-------+
			 -- Read -->

   We fill the buffer to bEnd, then empty it advancing bPos until there isn't
   enough data left to satisfy the read, whereupon we move the data down and
   refill from bEnd:

   bPos		   bEnd
	|			|
	v			v
	+-----------+---------------+
	|///////////|				|
	+-----------+---------------+
				 -- Write -->	  */

static int bufferedTransportReadFunction( STREAM *stream, BYTE *buffer,
										  const int length, const int flags )
	{
	const int bytesLeft = stream->bufEnd - stream->bufPos;
	int bytesToRead, status;

	assert( isWritePtr( buffer, length ) );
	assert( length > 0 );
	assert( bytesLeft >= 0 );

	/* If there's enough data in the buffer to satisfy the request, return it
	   directly */
	if( length <= bytesLeft )
		{
		if( length == 1 )
			/* Optimisation for HTTP header reads */
			*buffer = stream->buffer[ stream->bufPos++ ];
		else
			{
			memcpy( buffer, stream->buffer + stream->bufPos, length );
			stream->bufPos += length;
			}
		assert( stream->bufPos <= stream->bufEnd );
		return( length );
		}

	/* We're about to refill the buffer, if there's a gap at the start move 
	   everything down to make room for the new data */
	if( stream->bufPos > 0 )
		{
		if( bytesLeft > 0 )
			memmove( stream->buffer, stream->buffer + stream->bufPos, 
					 bytesLeft );
		stream->bufEnd = bytesLeft;
		stream->bufPos = 0;
		}

	assert( stream->bufPos == 0 );
	assert( length > bytesLeft );

	/* If there's more room in the buffer, refill it */
	if( stream->bufEnd < stream->bufSize )
		{
		int bytesRead;

		/* Perform an explicitly blocking read of as many bytes as we can/are
		   asked for.  Since there may be data already present from an
		   earlier speculative read, we only read as much as we need to 
		   fulfill the request */
		bytesRead = stream->transportReadFunction( stream, 
										stream->buffer + stream->bufEnd,
										min( length - bytesLeft, \
											 stream->bufSize - stream->bufEnd ),
										TRANSPORT_FLAG_BLOCKING );
		if( cryptStatusError( bytesRead ) )
			return( bytesRead );
		stream->bufEnd += bytesRead;

		/* If there's room for more, perform a second, nonblocking read for
		   whatever might still be there.  An error at this point isn't
		   fatal since this was only a speculative read  */
		if( stream->bufEnd < stream->bufSize )
			{
			bytesRead = stream->transportReadFunction( stream, 
										stream->buffer + stream->bufEnd,
										stream->bufSize - stream->bufEnd,
										TRANSPORT_FLAG_NONBLOCKING );
			if( !cryptStatusError( bytesRead ) )
				stream->bufEnd += bytesRead;
			}
		}
	assert( stream->bufEnd <= stream->bufSize );

	/* Read as much as we can from the buffer */
	bytesToRead = min( length, stream->bufEnd );
	memcpy( buffer, stream->buffer, bytesToRead );
	stream->bufPos += bytesToRead;
	assert( stream->bufPos <= stream->bufEnd );

	/* If we could satisfy the read from the buffer, we're done */
	if( length <= bytesToRead )
		return( length );

	/* We're drained the stream buffer and there's more to go, read it 
	   directly into the caller's buffer */
	status = stream->transportReadFunction( stream, 
								buffer + bytesToRead, length - bytesToRead,
								TRANSPORT_FLAG_BLOCKING );
	return( cryptStatusError( status ) ? status : status + bytesToRead );
	}

/* Buffered transport-layer write function.  This sits on top of the 
   transport-layer write function and combines two (or more, although in
   practice only two ever occur) writes into a single write.  The reason for
   this is that when using TCP transport the delayed-ACK handling means
   that performing two writes followed by a read (typical for HTTP and CMP
   messages) leads to very poor performance, usually made even worse by TCP 
   slow-start.

   The reason for this is that the TCP MSS is typically 1460 bytes on a LAN 
   (Ethernet) or 512/536 bytes on a WAN, while HTTP headers are ~200-300 
   bytes, far less than the MSS.  When an HTTP message is first sent, the 
   TCP congestion window begins at one segment, with the TCP slow-start then
   doubling its size for each ACK.  Sending the headers separately will 
   send one short segment and a second MSS-size segment, whereupon the TCP 
   stack will wait for the responder's ACK before continuing.  The responder 
   gets both segments, then delays its ACK for 200ms in the hopes of 
   piggybacking it on responder data, which is never sent since it's still 
   waiting for the rest of the HTTP body from the initiator.  As a result,
   this results in a 200ms (+ assorted RTT) delay in each message sent.
   
   There is a somewhat related situation that occurs as a result of TCP
   slow-start and that can't be avoided programmatically in which we can't
   send more than a single request initially, however most BSD-derived 
   implementations set the server's congestion window to two segments in 
   response to receiving the TCP handshake ACK, so for the initial message
   exchange the client can send a request of 1MSS and the server a response
   of 2MSS without running into congestion-control problems.

   A related problem is the fact that many TCP implementations will reset the
   congestion window after one retransmission timeout period if all data sent
   at that point has been acked, which means that both sides now restart with
   a congestion window of size 1.  Unfortunately there's nothing that can be
   done about this, however hopefully at some point TCP implementations will
   start to fall into line with RFC 3390 and allow initial windows of ~4K,
   which will fix this particular problem */

static int bufferedTransportWriteFunction( STREAM *stream, const BYTE *buffer,
										   const int length, const int flags )
	{
	const BYTE *bufPtr = buffer;
	int byteCount = length;

	assert( isReadPtr( buffer, length ) );
	assert( length > 0 );

	/* If it's not a flush and the buffer can absorb the data, copy it in and
	   exit */
	if( !( flags & TRANSPORT_FLAG_FLUSH ) && \
		stream->writeBufEnd + length <= stream->writeBufSize )
		{
		memcpy( stream->writeBuffer + stream->writeBufEnd, buffer, length );
		stream->writeBufEnd += length;
		assert( stream->writeBufEnd <= stream->writeBufSize );

		return( CRYPT_OK );
		}

	/* It's a flush or too much data to buffer, assemble a complete buffer 
	   and write it */
	if( stream->writeBufEnd > 0 )
		{
		const int bytesToCopy = min( byteCount, \
									 stream->writeBufSize - stream->writeBufEnd );
		int status;

		if( bytesToCopy > 0 )
			memcpy( stream->writeBuffer + stream->writeBufEnd, buffer, 
					bytesToCopy );
		status = stream->transportWriteFunction( stream, stream->writeBuffer,
												 stream->writeBufEnd + \
													bytesToCopy,
												 TRANSPORT_FLAG_FLUSH );
		stream->writeBufEnd = 0;
		bufPtr += bytesToCopy;
		byteCount -= bytesToCopy;
		if( byteCount <= 0 )
			return( CRYPT_OK );
		}

	/* Write anything that's left directly */
	return( stream->transportWriteFunction( stream, bufPtr, byteCount,
											TRANSPORT_FLAG_FLUSH ) );
	}

/****************************************************************************
*																			*
*							Transport-layer Functions						*
*																			*
****************************************************************************/

/* Map the upper-layer I/O functions directly to the transport-layer
   equivalent.  This is used if we're performing raw I/O without any
   intermediate protocol layers or buffering */

static int transportDirectReadFunction( STREAM *stream, void *buffer,
										const int length )
	{
	return( stream->transportReadFunction( stream, buffer, length, 
										   TRANSPORT_FLAG_NONE ) );
	}

static int transportDirectWriteFunction( STREAM *stream, const void *buffer,
										 const int length )
	{
	return( stream->transportWriteFunction( stream, buffer, length,
											TRANSPORT_FLAG_NONE ) );
	}

static int setStreamLayerDirect( STREAM *stream )
	{
	stream->writeFunction = transportDirectWriteFunction;
	stream->readFunction = transportDirectReadFunction;

	return( CRYPT_OK );
	}

/* Send and receive data with a cryptlib session as the transport layer */

static int transportSessionConnectFunction( STREAM *stream, 
											const char *server, 
											const int port )
	{
	int isActive, status;

	assert( server == NULL );
	assert( port == 0 );

	/* If the transport session hasn't been activated yet, activate it now */
	status = krnlSendMessage( stream->iTransportSession,
							  IMESSAGE_GETATTRIBUTE, &isActive,
							  CRYPT_SESSINFO_ACTIVE );
	if( cryptStatusOK( status ) && isActive )
		return( CRYPT_OK );
	status = krnlSendMessage( stream->iTransportSession,
							  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE, 
							  CRYPT_SESSINFO_ACTIVE );
	if( cryptStatusError( status ) )
		return( getSessionErrorInfo( stream, status ) );
	return( CRYPT_OK );
	}

static void transportSessionDisconnectFunction( STREAM *stream,
												const BOOLEAN fullDisconnect )
	{
	krnlSendNotifier( stream->iTransportSession, IMESSAGE_DECREFCOUNT );
	}

static BOOLEAN transportSessionOKFunction( void )
	{
	return( TRUE );
	}

static int transportSessionReadFunction( STREAM *stream, BYTE *buffer,
										 const int length, const int flags )
	{
	RESOURCE_DATA msgData;
	int newTimeout = CRYPT_UNUSED, status;

	/* Read data from the session, overriding the timeout handling if
	   requested */
	if( ( flags & TRANSPORT_FLAG_NONBLOCKING ) && stream->timeout > 0 )
		newTimeout = 0;
	else
		if( ( flags & TRANSPORT_FLAG_BLOCKING ) && stream->timeout == 0 )
			newTimeout = 30;
	if( newTimeout != CRYPT_UNUSED )
		krnlSendMessage( stream->iTransportSession, IMESSAGE_SETATTRIBUTE, 
						 &newTimeout, CRYPT_OPTION_NET_TIMEOUT );
	setMessageData( &msgData, buffer, length );
	status = krnlSendMessage( stream->iTransportSession, IMESSAGE_ENV_POPDATA, 
							  &msgData, 0 );
	if( newTimeout != CRYPT_UNUSED )
		krnlSendMessage( stream->iTransportSession, IMESSAGE_SETATTRIBUTE, 
						 &stream->timeout, CRYPT_OPTION_NET_TIMEOUT );
	if( cryptStatusError( status ) )
		return( getSessionErrorInfo( stream, status ) );
	if( msgData.length < length )
		retExtStream( stream, CRYPT_ERROR_READ, 
					  "Only read %d out of %d bytes via cryptlib session "
					  "object", msgData.length, length );
	return( length );
	}

static int transportSessionWriteFunction( STREAM *stream, const BYTE *buffer,
										  const int length, const int flags )
	{
	RESOURCE_DATA msgData;
	int status;

	setMessageData( &msgData, ( void * ) buffer, length );
	status = krnlSendMessage( stream->iTransportSession,
							  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( stream->iTransportSession,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusError( status ) )
		return( getSessionErrorInfo( stream, status ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Network Stream Functions						*
*																			*
****************************************************************************/

/* Clean up a stream to shut it down, optionally closing the underlying 
   network connection */

static void cleanupStream( STREAM *stream, const BOOLEAN cleanupTransport )
	{
	assert( stream != NULL && stream->type == STREAM_TYPE_NETWORK );
	assert( stream->errorMessage != NULL );

	if( cleanupTransport && !( stream->flags & STREAM_NFLAG_USERSOCKET ) )
		stream->transportDisconnectFunction( stream, TRUE );
	if( stream->bufSize )
		{
		zeroise( stream->buffer, stream->bufSize );
		clFree( "cleanupStream", stream->buffer );
		}
	if( stream->writeBufSize )
		{
		zeroise( stream->writeBuffer, stream->writeBufSize );
		clFree( "cleanupStream", stream->writeBuffer );
		}
	if( stream->host != NULL )
		clFree( "cleanupStream", stream->host );
	if( stream->path != NULL )
		clFree( "cleanupStream", stream->path );
	if( stream->query != NULL )
		clFree( "cleanupStream", stream->query );
	clFree( "cleanupStream", stream->errorMessage );
	zeroise( stream, sizeof( STREAM ) );
	}

/* Complete a network connection after the client- or server-specific
   portions have been handled */

static int completeConnect( STREAM *stream,
							const STREAM_PROTOCOL_TYPE protocol,
							const NET_OPTION_TYPE options,
							const char *proxyURL, 
							const CRYPT_USER iUserObject, 
							const int netTimeout, char *errorMessage, 
							int *errorCode )
	{
	const BOOLEAN useTransportBuffering = \
						( options == NET_OPTION_TRANSPORTSESSION || \
						  protocol == STREAM_PROTOCOL_TCPIP ) ? \
						FALSE : TRUE;
	int timeout, status = CRYPT_OK;

	/* Set up the access method pointers.  We can use either direct TCP/IP
	   access or a cryptlib stream for transport, and layered over that
	   either HTTP, the CMP socket protocol, or direct access to the
	   transport layer */
	if( options == NET_OPTION_TRANSPORTSESSION )
		{
		stream->transportConnectFunction = transportSessionConnectFunction;
		stream->transportDisconnectFunction = transportSessionDisconnectFunction;
		stream->transportWriteFunction = transportSessionWriteFunction;
		stream->transportReadFunction = transportSessionReadFunction;
		stream->transportOKFunction = transportSessionOKFunction;
		}
	else
		setAccessMethodTCP( stream );
	switch( protocol )
		{
		case STREAM_PROTOCOL_HTTP:
		case STREAM_PROTOCOL_HTTP_TRANSACTION:
			setStreamLayerHTTP( stream );
			break;

		case STREAM_PROTOCOL_CMP:
			setStreamLayerCMP( stream );
			break;

		case STREAM_PROTOCOL_TCPIP:
			setStreamLayerDirect( stream );
			break;

		default:
			assert( NOTREACHED );
		}
	if( useTransportBuffering )
		{
		stream->bufferedTransportReadFunction = bufferedTransportReadFunction;
		stream->bufferedTransportWriteFunction = bufferedTransportWriteFunction;
		}
	else
		{
		stream->bufferedTransportReadFunction = stream->transportReadFunction;
		stream->bufferedTransportWriteFunction = stream->transportWriteFunction;
		}

	/* If we're running over a cryptlib session, make sure that we wait around 
	   for a minimum amount of time during network comms in case the user has
	   specified nonblocking behaviour or quick timeouts */
	if( options == NET_OPTION_TRANSPORTSESSION )
		{
		static const int fixedTimeout = 30;

		status = krnlSendMessage( iUserObject, IMESSAGE_GETATTRIBUTE, 
								  &timeout, CRYPT_OPTION_NET_CONNECTTIMEOUT );
		if( cryptStatusOK( status ) && timeout < fixedTimeout )
			krnlSendMessage( stream->iTransportSession,
							 IMESSAGE_SETATTRIBUTE, ( void * ) &fixedTimeout, 
							 CRYPT_OPTION_NET_CONNECTTIMEOUT );
		status = krnlSendMessage( iUserObject, IMESSAGE_GETATTRIBUTE, 
								  &timeout, CRYPT_OPTION_NET_TIMEOUT );
		if( cryptStatusOK( status ) && timeout < fixedTimeout )
			krnlSendMessage( stream->iTransportSession, IMESSAGE_SETATTRIBUTE,
							 ( void * ) &fixedTimeout, CRYPT_OPTION_NET_TIMEOUT );
		status = CRYPT_OK;	/* Reset status from above checks */
		}

	/* Wait for any async network driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Make sure that the network interface has been initialised */
	if( !stream->transportOKFunction() )
		{
		/* Provide more information on the nature of the problem */
		strcpy( errorMessage, "cryptlib network interface not initialised" );

		/* Clean up.  We can't use cleanupStream() at this point because the
		   stream hasn't been fully initialised yet */
		if( stream->host != NULL )
			clFree( "completeConnect", stream->host );
		zeroise( stream, sizeof( STREAM ) );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Allocate room for the I/O buffers and error messages returned from the 
	   lower-level networking code */
	if( ( stream->errorMessage = clAlloc( "completeConnect", \
										  MAX_ERRMSG_SIZE + 1 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( useTransportBuffering )
		{
		if( ( stream->buffer = clAlloc( "completeConnect", \
										NETWORK_BUFFER_SIZE ) ) != NULL )
			{
			stream->bufSize = NETWORK_BUFFER_SIZE;
			if( ( stream->writeBuffer = \
					clAlloc( "completeConnect", NETWORK_BUFFER_SIZE ) ) != NULL )
				stream->writeBufSize = NETWORK_BUFFER_SIZE;
			}
		if( stream->writeBufSize <= 0 )
			{
			cleanupStream( stream, FALSE );
			return( CRYPT_ERROR_MEMORY );
			}
		}
	memset( stream->errorMessage, 0, MAX_ERRMSG_SIZE + 1 );

	/* If we're not using an already-active network socket supplied by the 
	   user, activate the connection */
	if( !( stream->flags & STREAM_NFLAG_USERSOCKET ) )
		{
		if( proxyURL != NULL )
			{
			URL_INFO urlInfo;

			/* We're going via a proxy, open the connection to the proxy 
			   rather than directly to the target system.  Since this is an
			   HTTP proxy, we specify the default port as port 80 */
			status = parseURL( &urlInfo, proxyURL, strlen( proxyURL ), 80 );
			if( cryptStatusError( status ) )
				{
				/* The proxy URL was invalid, provide more information for 
				   the caller */
				status = CRYPT_ERROR_OPEN;
				stream->errorCode = CRYPT_ERROR_BADDATA;
				strcpy( stream->errorMessage, "Invalid HTTP proxy URL" );
				}
			else
				{
				char urlBuffer[ MAX_DNS_SIZE + 1 ];

				memcpy( urlBuffer, urlInfo.host, urlInfo.hostLen );
				urlBuffer[ urlInfo.hostLen ] = '\0';
				status = stream->transportConnectFunction( stream, urlBuffer,
														   urlInfo.port );
				}
			}
		else
			status = stream->transportConnectFunction( stream, stream->host,
													   stream->port );
		}
	else
		/* If it's a dummy open to check parameters that can't be validated 
		   at a higher level, pass the info on down to the low-level 
		   checking routines */
		if( options == NET_OPTION_NETWORKSOCKET_DUMMY )
			status = stream->transportCheckFunction( stream );
	if( cryptStatusError( status ) )
		{
		/* Copy back the error information to the caller */
		*errorCode = stream->errorCode;
		strcpy( errorMessage, stream->errorMessage );

		/* Clean up */
		cleanupStream( stream, FALSE );
		return( status );
		}
	if( options == NET_OPTION_NETWORKSOCKET_DUMMY )
		/* If it's a dummy open to check parameters, don't do anything 
		   further */
		return( CRYPT_OK );

	/* We're connected, update the stream timeout value to contain the 
	   network I/O timeout rather than the connect timeout.  We use sioctl() 
	   rather than setting it directly to ensure that it gets reflected down 
	   to any underlying transport-layer objects */
	if( netTimeout != CRYPT_ERROR )
		timeout = netTimeout;
	else
		if( cryptStatusError( \
				krnlSendMessage( iUserObject, IMESSAGE_GETATTRIBUTE, 
								 &timeout, CRYPT_OPTION_NET_TIMEOUT ) ) )
			timeout = 30;
	sioctl( stream, STREAM_IOCTL_TIMEOUT, NULL, timeout );

	return( CRYPT_OK );
	}

/* Open and close a network connection.  This parses a location string
   (usually a URL) into <scheme>://<host>[:<port>]/<path>[?<query>]
   components and opens a connection to the host for non-stateless
   protocols */

int sNetConnect( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				 const NET_CONNECT_INFO *connectInfo, char *errorMessage, 
				 int *errorCode )
	{
	URL_INFO urlInfo;
	char proxyUrlBuffer[ MAX_DNS_SIZE + 1 ], *proxyURL = NULL;
	int timeout, status;

	assert( isWritePtr( stream, STREAM ) );
	assert( protocol == STREAM_PROTOCOL_TCPIP || \
			protocol == STREAM_PROTOCOL_HTTP || \
			protocol == STREAM_PROTOCOL_HTTP_TRANSACTION || \
			protocol == STREAM_PROTOCOL_CMP );
	assert( isReadPtr( connectInfo, NET_CONNECT_INFO ) );
	assert( errorMessage != NULL && errorCode != NULL );
	assert( connectInfo->options != NET_OPTION_HOSTNAME || \
			( connectInfo->options == NET_OPTION_HOSTNAME && \
			  connectInfo->name != NULL && connectInfo->name[ 0 ] && \
			  connectInfo->iCryptSession == CRYPT_ERROR && \
			  connectInfo->networkSocket == CRYPT_ERROR ) );
	assert( connectInfo->options != NET_OPTION_TRANSPORTSESSION || \
			( connectInfo->options == NET_OPTION_TRANSPORTSESSION && \
			  connectInfo->name == NULL && \
			  connectInfo->iCryptSession != CRYPT_ERROR && \
			  connectInfo->networkSocket == CRYPT_ERROR ) );
	assert( ( connectInfo->options != NET_OPTION_NETWORKSOCKET && \
			  connectInfo->options != NET_OPTION_NETWORKSOCKET_DUMMY ) || \
			( ( connectInfo->options == NET_OPTION_NETWORKSOCKET || \
				connectInfo->options == NET_OPTION_NETWORKSOCKET_DUMMY ) && \
			  connectInfo->name == NULL && \
			  connectInfo->iCryptSession == CRYPT_ERROR && \
			  connectInfo->networkSocket != CRYPT_ERROR ) );
	assert( connectInfo->iUserObject >= DEFAULTUSER_OBJECT_HANDLE && 
			connectInfo->iUserObject < MAX_OBJECTS );

	/* Clear the return values */
	*errorMessage = '\0';
	*errorCode = 0;

	/* Initialise the stream structure.  While we're connecting, the stream 
	   timeout is the connect timeout.  Once we've connected it's set to the
	   communication timeout */
	if( connectInfo->connectTimeout != CRYPT_ERROR )
		timeout = connectInfo->connectTimeout;
	else
		if( cryptStatusError( \
				krnlSendMessage( connectInfo->iUserObject, IMESSAGE_GETATTRIBUTE, 
								 &timeout, CRYPT_OPTION_NET_CONNECTTIMEOUT ) ) )
			timeout = 30;
	if( timeout < 5 )
		{
		/* Enforce the same minimum connect timeout as the kernel ACLs */
		assert( NOTREACHED );
		timeout = 5;
		}
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_NETWORK;
	stream->protocol = protocol;
	stream->timeout = stream->savedTimeout = timeout;
	stream->port = connectInfo->port;
	stream->netSocket = stream->listenSocket = CRYPT_ERROR;
	stream->iTransportSession = CRYPT_ERROR;
	switch( connectInfo->options )
		{
		case NET_OPTION_HOSTNAME:
			/* If we're using standard HTTP then only an HTTP GET is 
			   possible, use of POST requires the HTTP_TRANSACTION variant */
			if( protocol == STREAM_PROTOCOL_HTTP )
				stream->flags = STREAM_FLAG_READONLY;

			/* Parse the URI into its various components */
			status = parseURL( &urlInfo, connectInfo->name, 
						strlen( connectInfo->name ), connectInfo->port );
			if( cryptStatusError( status ) )
				{
				/* There's an error in the URL format, provide more 
				   information to the caller */
				strcpy( errorMessage, "Invalid host name/URL" );
				return( CRYPT_ERROR_OPEN );
				}
			status = copyUrlToStream( stream, &urlInfo );
			if( cryptStatusError( status ) )
				return( status );

			/* If it's going to something other than the local system, check 
			   to see whether we're going through a proxy.  We only use the
			   case-insensitive string compares for the text-format host 
			   names, since the numeric forms don't need this */
			if( ( protocol == STREAM_PROTOCOL_HTTP || \
				  protocol == STREAM_PROTOCOL_HTTP_TRANSACTION ) && \
				( strcmp( stream->host, "127.0.0.1" ) && \
				  strcmp( stream->host, "::1" ) && \
				  strCompareZ( stream->host, "localhost" ) && \
				  strCompare( stream->host, "localhost.", 10 ) ) )	/* Are you local? */
				{
				RESOURCE_DATA msgData;

				/* Check whether there's an HTTP proxy configured */
				setMessageData( &msgData, proxyUrlBuffer, MAX_DNS_SIZE );
				status = krnlSendMessage( connectInfo->iUserObject, 
										  IMESSAGE_GETATTRIBUTE_S, &msgData, 
										  CRYPT_OPTION_NET_HTTP_PROXY );
				if( cryptStatusOK( status ) )
					{
					proxyUrlBuffer[ msgData.length ] = '\0';
					proxyURL = proxyUrlBuffer;
					stream->flags |= STREAM_NFLAG_HTTPPROXY;
					}
				}
			break;

		case NET_OPTION_TRANSPORTSESSION:
			stream->iTransportSession = connectInfo->iCryptSession;
			break;

		case NET_OPTION_NETWORKSOCKET:
		case NET_OPTION_NETWORKSOCKET_DUMMY:
			stream->netSocket = connectInfo->networkSocket;
			stream->flags |= STREAM_NFLAG_USERSOCKET;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}

	/* Set up access mechanisms and complete the connection */
	return( completeConnect( stream, protocol, connectInfo->options, proxyURL,
							 connectInfo->iUserObject, connectInfo->timeout, 
							 errorMessage, errorCode ) );
	}

int sNetListen( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				const NET_CONNECT_INFO *connectInfo, char *errorMessage,
				int *errorCode )
	{
	URL_INFO urlInfo;
	int timeout;

	assert( isWritePtr( stream, STREAM ) );
	assert( protocol == STREAM_PROTOCOL_TCPIP || \
			protocol == STREAM_PROTOCOL_HTTP_TRANSACTION || \
			protocol == STREAM_PROTOCOL_CMP );
	assert( isReadPtr( connectInfo, NET_CONNECT_INFO ) );
	assert( errorMessage != NULL && errorCode != NULL );
	assert( connectInfo->options != NET_OPTION_HOSTNAME || \
			( connectInfo->options == NET_OPTION_HOSTNAME && \
			  connectInfo->iCryptSession == CRYPT_ERROR && \
			  connectInfo->networkSocket == CRYPT_ERROR ) );
	assert( connectInfo->options != NET_OPTION_TRANSPORTSESSION || \
			( connectInfo->options == NET_OPTION_TRANSPORTSESSION && \
			  connectInfo->name == NULL && \
			  connectInfo->iCryptSession != CRYPT_ERROR && \
			  connectInfo->networkSocket == CRYPT_ERROR ) );
	assert( ( connectInfo->options != NET_OPTION_NETWORKSOCKET && \
			  connectInfo->options != NET_OPTION_NETWORKSOCKET_DUMMY ) || \
			( ( connectInfo->options == NET_OPTION_NETWORKSOCKET || \
				connectInfo->options == NET_OPTION_NETWORKSOCKET_DUMMY ) || \
			  connectInfo->name == NULL && \
			  connectInfo->iCryptSession == CRYPT_ERROR && \
			  connectInfo->networkSocket != CRYPT_ERROR ) );
	assert( connectInfo->iUserObject >= DEFAULTUSER_OBJECT_HANDLE && 
			connectInfo->iUserObject < MAX_OBJECTS );

	/* Clear the return values */
	*errorMessage = '\0';
	*errorCode = 0;

	/* Initialise the stream structure.  While we're connecting, the stream 
	   timeout is the connect timeout.  Once we've connected it's set to the
	   communication timeout */
	if( connectInfo->connectTimeout != CRYPT_ERROR )
		timeout = connectInfo->connectTimeout;
	else
		if( cryptStatusError( \
				krnlSendMessage( connectInfo->iUserObject, IMESSAGE_GETATTRIBUTE, 
								 &timeout, CRYPT_OPTION_NET_CONNECTTIMEOUT ) ) )
			timeout = 30;
	if( timeout < 5 )
		{
		/* Enforce the same minimum connect timeout as the kernel ACLs */
		assert( NOTREACHED );
		timeout = 5;
		}
	memset( stream, 0, sizeof( STREAM ) );
	stream->type = STREAM_TYPE_NETWORK;
	stream->protocol = protocol;
	stream->timeout = INT_MAX - 1;
	stream->savedTimeout = timeout;
	stream->port = connectInfo->port;
	stream->netSocket = stream->listenSocket = CRYPT_ERROR;
	stream->iTransportSession = CRYPT_ERROR;
	stream->flags = STREAM_NFLAG_ISSERVER;
	switch( connectInfo->options )
		{
		case NET_OPTION_HOSTNAME:
			if( connectInfo->name != NULL )
				{
				int status;

				/* Parse the interface URI into its various components */
				status = parseURL( &urlInfo, connectInfo->name, 
							strlen( connectInfo->name ), connectInfo->port );
				if( cryptStatusError( status ) )
					{
					/* There's an error in the format, provide more 
					   information to the caller */
					strcpy( errorMessage, "Invalid interface name" );
					return( CRYPT_ERROR_OPEN );
					}
				status = copyUrlToStream( stream, &urlInfo );
				if( cryptStatusError( status ) )
					return( status );
				}
			break;

		case NET_OPTION_TRANSPORTSESSION:
			stream->iTransportSession = connectInfo->iCryptSession;
			break;

		case NET_OPTION_NETWORKSOCKET:
		case NET_OPTION_NETWORKSOCKET_DUMMY:
			stream->netSocket = connectInfo->networkSocket;
			stream->flags |= STREAM_NFLAG_USERSOCKET;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}

	/* Set up access mechanisms and complete the connection */
	return( completeConnect( stream, protocol, connectInfo->options, NULL,
							 connectInfo->iUserObject, connectInfo->timeout, 
							 errorMessage, errorCode ) );
	}

int sNetDisconnect( STREAM *stream )
	{
	cleanupStream( stream, TRUE );

	return( CRYPT_OK );
	}

/* Parse a URL into its various components */

int sNetParseURL( URL_INFO *urlInfo, const char *url, const int urlLen )
	{
	return( parseURL( urlInfo, url, urlLen, CRYPT_UNUSED ) );
	}

/* Get extended information about an error status on a network connection */

void sNetGetErrorInfo( STREAM *stream, char *errorString, int *errorCode )
	{
	assert( isReadPtr( stream, STREAM ) );
	assert( stream->type == STREAM_TYPE_NETWORK );

	/* Remember the error code and message.  If we're running over a 
	   cryptlib transport session we have to first pull the info up from the 
	   session */
	if( stream->iTransportSession != CRYPT_ERROR )
		getSessionErrorInfo( stream, CRYPT_OK );
	*errorCode = stream->errorCode;
	strcpy( errorString, stream->errorMessage );
	}

#else

/****************************************************************************
*																			*
*							Network Stream Stubs							*
*																			*
****************************************************************************/

/* If there's no networking support present, we replace the network access
   routines with dummy ones that always return an error */

int sNetConnect( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				 const NET_CONNECT_INFO *connectInfo, char *errorMessage,
				 int *errorCode )
	{
	memset( stream, 0, sizeof( STREAM ) );
	return( CRYPT_ERROR_OPEN );
	}

int sNetListen( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				const NET_CONNECT_INFO *connectInfo, char *errorMessage,
				int *errorCode )
	{
	memset( stream, 0, sizeof( STREAM ) );
	return( CRYPT_ERROR_OPEN );
	}

int sNetDisconnect( STREAM *stream )
	{
	UNUSED( stream );

	return( CRYPT_OK );
	}

int sNetParseURL( URL_INFO *urlInfo, const char *url, const int urlLen )
	{
	memset( urlInfo, 0, sizeof( URL_INFO ) );

	return( CRYPT_ERROR_BADDATA );
	}

void sNetGetErrorInfo( STREAM *stream, char *errorString, int *errorCode )
	{
	UNUSED( stream );

	*errorString = '\0';
	*errorCode = CRYPT_OK;
	}
#endif /* USE_TCP */
