/****************************************************************************
*																			*
*					cryptlib CMP TCP transport Routines						*
*					  Copyright Peter Gutmann 2000-2002						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read and write the CMP-over-TCP header, which kludges on extra bits and
   pieces which were left out of CMP itself.  The TCP protocol version isn't
   really 10, this is a kludge to work around the fact that the original RFC
   2510 protocol doesn't work properly so it was necessary to create an
   artificially huge version number to ensure non-compatibility with earlier
   implementations (this really says it all for the design of CMP as a 
   whole) */

#define CMP_TCP_VERSION		10		/* CMP-over-TCP version */
#define CMP_HEADER_SIZE		7		/* Header overall size */
#define CMP_MIN_PACKET_SIZE	7		/* Hdr.payload size + error packet */

enum { CMPMSG_PKIREQ, CMPMSG_POLLREP, CMPMSG_POLLREQ, CMPMSG_FINREP,
	   CMPMSG_DUMMY, CMPMSG_PKIREP, CMPMSG_ERRORMSGREP };

static int writeHeader( BYTE *buffer, const int length,
						const BOOLEAN lastMessage )
	{
	BYTE *bufPtr = buffer;
	const long lengthVal = length + 3;

	/* Write the header:
		LONG: length
		BYTE: version = 10
		BYTE: flags = lastMessage
		BYTE: message type = 0
		BYTE[]: data */
	mputLong( bufPtr, lengthVal );
	*bufPtr++ = CMP_TCP_VERSION;
	*bufPtr++ = lastMessage;
	*bufPtr++ = CMPMSG_PKIREQ;

	return( CMP_HEADER_SIZE );
	}

static int readHeader( STREAM *stream, BYTE *buffer, int *length,
					   const int maxLength )
	{
	BYTE *bufPtr = buffer;
	int headerType, status;
	long headerLength;

	/* Clear return value */
	*length = CRYPT_ERROR;

	/* Read the fixed-length header fields */
	status = stream->bufferedTransportReadFunction( stream, bufPtr, 
													CMP_HEADER_SIZE, 
													TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	headerLength = mgetLong( bufPtr );
	if( headerLength < CMP_MIN_PACKET_SIZE || headerLength > maxLength || \
		*bufPtr++ != CMP_TCP_VERSION )
		return( CRYPT_ERROR_BADDATA );
	if( *bufPtr++ )
		/* This is the last message, close the connection */
		sioctl( stream, STREAM_IOCTL_CONNSTATE, NULL, FALSE );
	headerType = *bufPtr++;
	if( headerType < CMPMSG_PKIREQ || headerType > CMPMSG_ERRORMSGREP )
		return( CRYPT_ERROR_BADDATA );
	assert( CMP_MIN_PACKET_SIZE > 3 );
	headerLength -= 3;

	/* Handle individual header types */
	if( headerType == CMPMSG_PKIREQ || headerType == CMPMSG_PKIREP )
		{
		/* It's a normal reply, return the length of the payload */
		*length = headerLength;
		return( CRYPT_OK );
		}
	if( headerType == CMPMSG_ERRORMSGREP )
		{
		int unknownDataLength;

		/* Read as much of the error status info as we can:
			WORD: error code
			WORD: unknownDataLength
			BYTE[]: unknownData
			BYTE[]: error string filling remainder of packet

		   Because of the braindamaged packet format we have to jump through
		   various hoops to correctly handle data lengths in the face of a
		   hostile adversary.  First we read the error contents and shrink
		   the payload length value by that amount.  If the result is
		   positive, we're still within the read data, and copy what we've 
		   got out as the error message.  If not, there's a problem 
		   (probably due to a bogus unknownDataLength) and we substitute a 
		   generic error message.

		   Unfortunately though, we can't even safely do this.  Since the
		   protocol kludges an unauthenticated wrapper around the carefully
		   signed or MAC'd main CMP protocol, it's possible for an attacker
		   to manipulate the CMP-over-TCP layer to do things like redirect
		   users to bogus CAs via error messages spoofed from the real CA
		   (and if your client supports send-the-private-key-to-the-CA as
		   some do, you're in real trouble).  As a result we don't trust any
		   unauthenticated CMP-over-TCP messages, but simply report a
		   transport protocol problem.  Given the hit-and-miss nature of
		   implementations of this protocol, it's probably not going to make
		   things much worse than it would be if we tried to do it properly */
		bufPtr = buffer;
		status = stream->bufferedTransportReadFunction( stream, bufPtr, 
														headerLength,
														TRANSPORT_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		stream->errorCode = mgetWord( bufPtr );
		unknownDataLength = mgetWord( bufPtr );
		if( unknownDataLength < 0 )
			return( CRYPT_ERROR_BADDATA );
#if 0
		headerLength -= sizeof( WORD ) + sizeof( WORD ) + unknownDataLength;
		if( headerLength > 0 )
			{
			const int errorMessageLength = \
							min( headerLength, MAX_ERRMSG_SIZE - 1 );

			bufPtr += unknownDataLength;	/* Skip unknown data block */
			memcpy( stream->errorMessage, bufPtr, errorMessageLength );
			stream->errorMessage[ errorMessageLength ] = '\0';
			}
		else
#endif /* 0 */
			strcpy( stream->errorMessage,
					"CMP transport-level protocol error encountered" );

		/* The appropriate status values to return for a problem at this
		   level are pretty unclear, the most appropriate ones appear to be
		   a read error if there's a problem with the server (exactly what
		   the problem is is never specified in the error code) and a generic
		   bad data for anything else */
		return( ( ( stream->errorCode & 0x0F00 ) == 0x0300 ) ? \
				CRYPT_ERROR_READ : CRYPT_ERROR_BADDATA );
		}

	/* It's something weird which we don't handle */
	return( CRYPT_ERROR_BADDATA );
	}

/****************************************************************************
*																			*
*							CMP Access Functions							*
*																			*
****************************************************************************/

/* Read data from a CMP stream */

static int readFunction( STREAM *stream, void *buffer, int length )
	{
	int localLength, status;

	/* Read the CMP packet header */
	status = readHeader( stream, buffer, &localLength, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the payload data from the client/server */
	return( stream->bufferedTransportReadFunction( stream, buffer, 
												   localLength, 
												   TRANSPORT_FLAG_NONE ) );
	}

/* Write data to a CMP stream */

static int writeFunction( STREAM *stream, const void *buffer,
						  const int length )
	{
	BYTE headerBuffer[ 64 ];
	int headerLength, status;

	/* Write the CMP packet header */
	headerLength = writeHeader( headerBuffer, length,
								( stream->flags & STREAM_NFLAG_LASTMSG ) ? \
									TRUE : FALSE );
	status = stream->bufferedTransportWriteFunction( stream, headerBuffer,
													 headerLength, 
													 TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* Send the payload data to the client/server */
	return( stream->bufferedTransportWriteFunction( stream, buffer, length,
													TRANSPORT_FLAG_FLUSH ) );
	}

int setStreamLayerCMP( STREAM *stream )
	{
	/* Set the access method pointers */
	stream->writeFunction = writeFunction;
	stream->readFunction = readFunction;

	/* The CMP-over-TCP kludge provides its own data-size and flow-control 
	   indicators so we don't want the higher-level code to try and do this 
	   for us */
	stream->flags |= STREAM_NFLAG_ENCAPS;


	return( CRYPT_OK );
	}
#endif /* USE_CMP */
