/****************************************************************************
*																			*
*						cryptlib Secure Session Routines					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1_rw.h"
  #include "stream.h"
  #include "session.h"
#else
  #include "misc/asn1_rw.h"
  #include "misc/stream.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( SESSION_INFO *sessionInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( sessionInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( SESSION_INFO *sessionInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotInited( SESSION_INFO *sessionInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTINITED ) );
	}

static int exitErrorNotFound( SESSION_INFO *sessionInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Exit after saving a detailed error message.  This is used by lower-level 
   session code to provide more information to the caller than a basic error 
   code */

int retExtFnSession( SESSION_INFO *sessionInfoPtr, const int status, 
					 const char *format, ... )
	{
	va_list argPtr;

	va_start( argPtr, format );
	vsprintf( sessionInfoPtr->errorMessage, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/* Initialise network connection information based on the contents of the 
   session object */

void initSessionNetConnectInfo( const SESSION_INFO *sessionInfoPtr,
								NET_CONNECT_INFO *connectInfo )
	{
	initNetConnectInfo( connectInfo, sessionInfoPtr->ownerHandle, 
				sessionInfoPtr->timeout, sessionInfoPtr->connectTimeout, 
				( sessionInfoPtr->transportSession != CRYPT_ERROR ) ? \
					NET_OPTION_TRANSPORTSESSION : \
				( sessionInfoPtr->networkSocket != CRYPT_ERROR ) ? \
					NET_OPTION_NETWORKSOCKET : \
					NET_OPTION_HOSTNAME );
	if( sessionInfoPtr->serverName[ 0 ] )
		connectInfo->name = sessionInfoPtr->serverName;
	connectInfo->port = sessionInfoPtr->serverPort;
	connectInfo->iCryptSession = sessionInfoPtr->transportSession;
	connectInfo->networkSocket = sessionInfoPtr->networkSocket;
	}

/* Activate the network connection for a session */

static int activateConnection( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	/* Make sure that everything is set up ready to go */
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		{
		/* Check server-specific required values */
		if( ( sessionInfoPtr->serverReqAttrFlags & \
			  SESSION_NEEDS_PRIVATEKEY ) && \
			sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			/* There's no private key present, see if we can use a username
			   and password as an alternative.  In the special case of
			   password-based SSL this isn't completely foolproof since the
			   passwords are entered into a pool from which they can be
			   deleted explicitly if the session is aborted in a non-
			   resumable manner or implicitly over time as they are displaced 
			   by other entries, however this is an extremely unlikely case 
			   and it's too tricky trying to track what is and isn't still 
			   active to handle this fully */
			if( !( sessionInfoPtr->serverReqAttrFlags & \
				   SESSION_NEEDS_KEYORPASSWORD ) || \
				sessionInfoPtr->requiredPasswordStatus <= 0 )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_SESSINFO_PRIVATEKEY ) );
			}
		if( ( sessionInfoPtr->serverReqAttrFlags & \
			  SESSION_NEEDS_KEYSET ) && \
			sessionInfoPtr->cryptKeyset == CRYPT_ERROR )
			return( exitErrorNotInited( sessionInfoPtr,
										CRYPT_SESSINFO_KEYSET ) );
		}
	else
		{
		/* Check client-specific required values */
		if( sessionInfoPtr->transportSession == CRYPT_ERROR && \
			sessionInfoPtr->networkSocket == CRYPT_ERROR && \
			!sessionInfoPtr->serverName[ 0 ] )
			return( exitErrorNotInited( sessionInfoPtr,
										CRYPT_SESSINFO_SERVER_NAME ) );
		if( ( sessionInfoPtr->clientReqAttrFlags & \
			  SESSION_NEEDS_USERID ) && \
			sessionInfoPtr->userNameLength <= 0 )
			return( exitErrorNotInited( sessionInfoPtr,
										CRYPT_SESSINFO_USERNAME ) );
		if( ( sessionInfoPtr->clientReqAttrFlags & \
			  SESSION_NEEDS_PASSWORD ) && \
			sessionInfoPtr->passwordLength <= 0 )
			{
			/* There's no password present, see if we can use a private
			   key as an alternative */
			if( !( sessionInfoPtr->clientReqAttrFlags & \
				   SESSION_NEEDS_KEYORPASSWORD ) || \
				sessionInfoPtr->privateKey == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_SESSINFO_PASSWORD ) );
			}
		if( ( sessionInfoPtr->clientReqAttrFlags & \
			  SESSION_NEEDS_PRIVATEKEY ) && \
			sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			/* There's no private key present, see if we can use a password 
			   as an alternative */
			if( !( sessionInfoPtr->clientReqAttrFlags & \
				   SESSION_NEEDS_KEYORPASSWORD ) || \
				sessionInfoPtr->passwordLength <= 0 )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_SESSINFO_PRIVATEKEY ) );
			}
		if( ( sessionInfoPtr->clientReqAttrFlags & \
			  SESSION_NEEDS_REQUEST ) && \
			sessionInfoPtr->iCertRequest == CRYPT_ERROR )
			return( exitErrorNotInited( sessionInfoPtr,
										CRYPT_SESSINFO_REQUEST ) );
		}

	/* Allocate the send and receive buffers if necessary.  The send buffer 
	   isn't used for request-response session types that use the receive 
	   buffer for both outgoing and incoming data, so we only allocate it if 
	   necessary */
	if( sessionInfoPtr->sendBuffer == NULL )
		{
		assert( sessionInfoPtr->receiveBufSize >= MIN_BUFFER_SIZE && \
				( sessionInfoPtr->sendBufSize >= MIN_BUFFER_SIZE || \
				  sessionInfoPtr->sendBufSize == CRYPT_UNUSED ) );

		if( ( sessionInfoPtr->receiveBuffer = \
						clAlloc( "activateConnection", \
								 sessionInfoPtr->receiveBufSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		if( sessionInfoPtr->sendBufSize != CRYPT_UNUSED )
			{
			/* When allocating the send buffer we use the size for the 
			   receive buffer since the user may have overridden the default 
			   buffer size */
			if( ( sessionInfoPtr->sendBuffer = \
						clAlloc( "activateConnection", \
								 sessionInfoPtr->receiveBufSize ) ) == NULL )
				{
				clFree( "activateConnection", sessionInfoPtr->receiveBuffer );
				sessionInfoPtr->receiveBuffer = NULL;
				return( CRYPT_ERROR_MEMORY );
				}
			sessionInfoPtr->sendBufSize = sessionInfoPtr->receiveBufSize;
			}
		}
	assert( ( sessionInfoPtr->flags & SESSION_ISSERVER ) || \
			strlen( sessionInfoPtr->serverName ) || \
			sessionInfoPtr->networkSocket != CRYPT_ERROR );
	assert( sessionInfoPtr->serverPort );
	assert( sessionInfoPtr->receiveBuffer != NULL );

	/* Set timeouts if they're not set yet */
	if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
		{
		int timeout;

		status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &timeout, 
								  CRYPT_OPTION_NET_CONNECTTIMEOUT );
		sessionInfoPtr->connectTimeout = cryptStatusOK( status ) ? \
										 timeout : 30;
		}
	if( sessionInfoPtr->timeout == CRYPT_ERROR )
		{
		int timeout;

		status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &timeout, 
								  CRYPT_OPTION_NET_TIMEOUT );
		sessionInfoPtr->timeout = cryptStatusOK( status ) ? timeout : 30;
		}

	/* Wait for any async driver binding to complete.  We can delay this 
	   until this very late stage because no networking functionality is 
	   used until this point */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Activate the session */
	status = sessionInfoPtr->connectFunction( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a secure data transport session, complete the session state 
	   setup.  Note that some sessions dynamically change the protocol info
	   during the handshake to accommodate parameters negotiated during the
	   handshake, so we can only access the protocol info after the handshake
	   has completed */
	if( !sessionInfoPtr->protocolInfo->isReqResp )
		{
		/* Complete the session handshake to set up the secure state */
		status = sessionInfoPtr->transactFunction( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* Notify the kernel that the session key context is attached to the 
		   session object.  Note that we increment its reference count even
		   though it's an internal object used only by the session, because 
		   otherwise it'll be automatically destroyed by the kernel as a 
		   zero-reference dependent object when the session object is 
		   destroyed (but before the session object itself, since it's a 
		   dependent object).  This can cause problems for lower-level 
		   session management code that tries to work with the (apparently 
		   still-valid) handle, for example protocols that need to encrypt a 
		   close-channel message on shutdown */
		krnlSendMessage( sessionInfoPtr->objectHandle, IMESSAGE_SETDEPENDENT,
						 &sessionInfoPtr->iCryptInContext,
						 SETDEP_OPTION_INCREF );

		/* Set up the buffer management variables.  Since the handshake has
		   now completed, we can access the protocol info */
		sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd = 0;
		sessionInfoPtr->sendBufPos = sessionInfoPtr->sendBufStartOfs;
		}

	/* Remember that the session has been successfully established */
	sessionInfoPtr->flags |= SESSION_ISOPEN;

	return( CRYPT_OK );
	}

/* Activate a session */

static int activateSession( SESSION_INFO *sessionInfoPtr )
	{
	int streamState, status;

	/* Activate the connection if necessary */
	if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
		{
		status = activateConnection( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's a secure data transport session, it's up to the caller to 
	   move data over it, and we're done */
	if( !sessionInfoPtr->protocolInfo->isReqResp )
		return( CRYPT_OK );

	/* Clean up data from the preceding session activation if necessary */
	if( ( sessionInfoPtr->flags & SESSION_ISSERVER ) && \
		sessionInfoPtr->iCertRequest != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCertRequest, 
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertRequest = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCertResponse, 
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
		}

	/* Carry out the transaction for the request-response connection */
	status = sessionInfoPtr->transactFunction( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether the other side has indicated that they're closing the
	   stream and if it has, shut down our side as well and record the fact 
	   that the session is now closed */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONNSTATE, 
			&streamState, 0 );
	if( !streamState )
		{
		sessionInfoPtr->flags &= ~SESSION_ISOPEN;
		sessionInfoPtr->shutdownFunction( sessionInfoPtr );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Default Session Handlers						*
*																			*
****************************************************************************/

/* Default init/shutdown functions used when no session-specific ones are 
   provided */

static int defaultClientStartupFunction( SESSION_INFO *sessionInfoPtr )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	NET_CONNECT_INFO connectInfo;
	int status;

	/* Connect to the server */
	initSessionNetConnectInfo( sessionInfoPtr, &connectInfo );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		status = sNetConnect( &sessionInfoPtr->stream,
							  STREAM_PROTOCOL_HTTP_TRANSACTION,
							  &connectInfo, sessionInfoPtr->errorMessage, 
							  &sessionInfoPtr->errorCode );
	else
		{
		if( sessionInfoPtr->flags & SESSION_USEALTTRANSPORT )
			{
			const ALTPROTOCOL_INFO *altProtocolInfoPtr = \
									protocolInfoPtr->altProtocolInfo;

			/* If we're using the HTTP port for a session-specific protocol, 
			   change it to the default port for the session-specific 
			   protocol instead */
			if( connectInfo.port == 80 )
				connectInfo.port = altProtocolInfoPtr->port;
			status = sNetConnect( &sessionInfoPtr->stream, 
								  altProtocolInfoPtr->type, 
								  &connectInfo, sessionInfoPtr->errorMessage, 
								  &sessionInfoPtr->errorCode );
			}
		else
			status = sNetConnect( &sessionInfoPtr->stream,
								  STREAM_PROTOCOL_TCPIP, 
								  &connectInfo, sessionInfoPtr->errorMessage, 
								  &sessionInfoPtr->errorCode );
		}
	if( cryptStatusError( status ) )
		return( status );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HANDSHAKETIMEOUT, NULL, 0 );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONTENTTYPE, 
				( void * ) protocolInfoPtr->clientContentType, 
				strlen( protocolInfoPtr->clientContentType ) );

	return( CRYPT_OK );
	}

static int defaultServerStartupFunction( SESSION_INFO *sessionInfoPtr )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	NET_CONNECT_INFO connectInfo;
	int status;

	/* Wait for a client connection */
	initSessionNetConnectInfo( sessionInfoPtr, &connectInfo );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		status = sNetListen( &sessionInfoPtr->stream,
							 STREAM_PROTOCOL_HTTP_TRANSACTION, 
							 &connectInfo, sessionInfoPtr->errorMessage, 
							 &sessionInfoPtr->errorCode );
	else
		{
		if( sessionInfoPtr->flags & SESSION_USEALTTRANSPORT )
			{
			const ALTPROTOCOL_INFO *altProtocolInfoPtr = \
									protocolInfoPtr->altProtocolInfo;

			/* If we're using the HTTP port for a session-specific protocol, 
			   change it to the default port for the session-specific 
			   protocol instead */
			if( connectInfo.port == 80 )
				connectInfo.port = altProtocolInfoPtr->port;
			status = sNetListen( &sessionInfoPtr->stream, 
								 altProtocolInfoPtr->type, 
								 &connectInfo, sessionInfoPtr->errorMessage, 
								 &sessionInfoPtr->errorCode );
			}
		else
			status = sNetListen( &sessionInfoPtr->stream,
								 STREAM_PROTOCOL_TCPIP, 
								 &connectInfo, sessionInfoPtr->errorMessage, 
								 &sessionInfoPtr->errorCode );
		}
	if( cryptStatusError( status ) )
		return( status );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HANDSHAKETIMEOUT, NULL, 0 );
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONTENTTYPE,
				( void * ) protocolInfoPtr->serverContentType, 
				strlen( protocolInfoPtr->serverContentType ) );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_GETCLIENTNAME,
			sessionInfoPtr->clientName, 0 );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_GETCLIENTPORT,
			&sessionInfoPtr->clientPort, 0 );

	return( CRYPT_OK );
	}

static void defaultShutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Default get-attribute function used when no session-specific ones is
   provided */

static int defaultGetAttributeFunction( SESSION_INFO *sessionInfoPtr,
										void *data, 
										const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *responsePtr = ( CRYPT_CERTIFICATE * ) data;

	assert( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a response there's nothing to return */
	if( sessionInfoPtr->iCertResponse == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the info to the caller */
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_INCREFCOUNT );
	*responsePtr = sessionInfoPtr->iCertResponse;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Secure Session Data Handling Functions				*
*																			*
****************************************************************************/

/* Common code to read and write data over the secure connection.  This
   is called by the protocol-specific handlers, which supply three functions:

	readHeaderFunction()	- Reads the header for a packet and sets up
							  length information.
	processBodyFunction()	- Processes the body of a packet.
	writeDataFunction()		- Wraps and sends a packet.

   The read data code uses a helper function tryRead() that either reads
   everything which is available or to the end of the current packet.  In 
   other words it's an atomic, all-or-nothing function that can be used by 
   higher-level code to handle network-level packetisation.  Buffer 
   management is handled as follows: The bPos index always points to the end 
   of the decoded data (i.e. data that can be used by the user), if there's 
   no partial packet present this index is the same as bEnd:

	----+------------------------
	////|
	----+------------------------
		^
		|
	bEnd/bPos

   If there's a partial packet present, pendingPacketRemaining contains the
   number of bytes required to complete the packet and bEnd points to the 
   end of the received data, and is advanced as more data is read:

							<----> pPR
	----+-------------------+----+----
	////|///////////////////|....|
	----+-------------------+----+----
		^					^
		|					|
	  bPos				  bEnd

   Once the complete packet is read (pPR reaches 0), it's decrypted, and 
   bPos and bEnd are adjusted to point to the end of the new data:

	----+------------------------+----
	////|////////////////////////|
	----+------------------------+----
								 ^
								 |
							 bEnd/bPos

   The handling of any header data present at the start of the packet 
   depends on the packet format, if the header is independent of the 
   encrypted data it's handled entirely by readHeaderFunction() and there's 
   no need to provide special-case handling.  If the header is part of the 
   encrypted data, decryption is a two-stage operation in which 
   readHeaderFunction() decrypts just enough of the packet to extract and
   process the header (depositing any leftover non-header data at the start
   of the buffer), and processBodyFunction() processes the rest of the data.
   
   Errors in the readHeaderFunction() are fatal if they come from the session
   protocol level (e.g. a MAC failure or bad packet) and nonfatal if they 
   come from the network layer below the session (the stream-level code has 
   its own handling of fatal vs. nonfatal errors, so we don't try and get
   down to that level).

   Errors in the processBodyFunction() and writeDataFunction() are always
   fatal.  In theory we could try to recover, however the functions update 
   assorted crypto state such as packet sequence numbers and IVs that would
   be tricky to roll back, and in practice recoverable errors are likely to 
   be extremely rare (at best perhaps a CRYPT_ERROR_TIMEOUT for a context
   tied to a device, however even this won't occur since the conventional
   encryption and MAC contexts are all internal native contexts), so there's
   little point in trying to make the functions recoverable */

static int tryRead( SESSION_INFO *sessionInfoPtr, READSTATE_INFO *readInfo )
	{
	int bytesLeft, status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* If there's no pending packet information present, try and read it.  
	   This can return one of four classes of values:

		1. An error code.
		2. Zero, to indicate that nothing was read.
		3. OK_SPECIAL and read info READINFO_NOOP to indicate that header 
		   data but no payload data was read.
		4. A byte count and read info READINFO_HEADERPAYLOAD to indicate 
		   that some payload data was read as part of the header */
	if( sessionInfoPtr->pendingPacketLength <= 0 )
		{
		status = sessionInfoPtr->readHeaderFunction( sessionInfoPtr, readInfo );
		if( status <= 0 && status != OK_SPECIAL )
			return( status );
		assert( ( status == OK_SPECIAL && *readInfo == READINFO_NOOP ) || \
				( status > 0 && *readInfo == READINFO_HEADERPAYLOAD ) );
		if( *readInfo == READINFO_HEADERPAYLOAD )
			{
			/* Some protocols treat the header information for a secured
			   data packet as part of the data, so when we read the header we
			   can get part of the payload included in the read.  When the 
			   protocol-specific header read code obtained some payload data
			   alongside the header, it returns READINFO_HEADERPAYLOAD to
			   indicate that the packet info needs to be adjusted for the 
			   packet header data that was just read */
			sessionInfoPtr->receiveBufEnd += status;
			sessionInfoPtr->pendingPacketPartialLength = status;
			sessionInfoPtr->pendingPacketRemaining -= status;
			}
		}
	bytesLeft = sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd;

	assert( sessionInfoPtr->partialHeaderLength == 0 );
	assert( sessionInfoPtr->receiveBufEnd <= sessionInfoPtr->receiveBufSize );
	assert( sessionInfoPtr->receiveBufPos <= sessionInfoPtr->receiveBufEnd );

	/* Sanity-check the read state */
	if( sessionInfoPtr->pendingPacketLength < 0 || \
		sessionInfoPtr->pendingPacketRemaining < 0 || \
		sessionInfoPtr->pendingPacketPartialLength < 0 )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If there's not enough room in the receive buffer to read at least 1K
	   of packet data, don't try anything until the user has emptied more
	   data from the buffer */
	if( bytesLeft < min( sessionInfoPtr->pendingPacketRemaining, 1024 ) )
		return( 0 );

	/* Try and read more of the packet */
	status = sread( &sessionInfoPtr->stream,
					sessionInfoPtr->receiveBuffer + sessionInfoPtr->receiveBufEnd,
					min( sessionInfoPtr->pendingPacketRemaining, bytesLeft ) );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status == 0 )
		/* Nothing read, try again later */
		return( 0 );
	sessionInfoPtr->receiveBufEnd += status;
	sessionInfoPtr->pendingPacketRemaining -= status;
	if( sessionInfoPtr->pendingPacketRemaining > 0 )
		{
		/* We got some but not all of the data, try again later */
		*readInfo = READINFO_PARTIAL;
		return( OK_SPECIAL );
		}
	assert( sessionInfoPtr->pendingPacketRemaining == 0 );

	/* We've got a complete packet in the buffer, process it */
	return( sessionInfoPtr->processBodyFunction( sessionInfoPtr, readInfo ) );
	}

/* Get data from the remote system */

static int getData( SESSION_INFO *sessionInfoPtr, void *data,
					const int length )
	{
	BYTE *dataPtr = data;
	int bytesCopied = 0, savedTimeout, status;

	/* If there's an error pending (which will always be fatal, see the 
	   comment after the tryRead() call below), set the current error state 
	   to the pending state and return */
	if( cryptStatusError( sessionInfoPtr->pendingErrorState ) )
		{
		assert( sessionInfoPtr->receiveBufPos == 0 );

		status = sessionInfoPtr->readErrorState = \
						sessionInfoPtr->pendingErrorState;
		sessionInfoPtr->pendingErrorState = CRYPT_OK; 
		return( status );
		}

	/* Update the stream timeout to the current user-selected timeout in case
	   the user has changed the timeout setting */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, &savedTimeout, 0 );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, NULL, 
			sessionInfoPtr->timeout );

	while( bytesCopied < length )
		{
		const int bytesToCopy = min( length - bytesCopied, \
									 sessionInfoPtr->receiveBufPos );
		READSTATE_INFO readInfo = READINFO_NONE;
		int remainder;

		assert( bytesToCopy >= 0 );

		/* Sanity-check the read state */
		if( sessionInfoPtr->receiveBufPos < 0 || \
			sessionInfoPtr->receiveBufPos > sessionInfoPtr->receiveBufEnd || \
			sessionInfoPtr->receiveBufEnd < 0 || \
			sessionInfoPtr->receiveBufEnd > sessionInfoPtr->receiveBufSize )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
			}

		/* Copy as much data as we can across and move any remaining data down
		   to the start of the receive buffer */
		if( bytesToCopy > 0 )
			{
			memcpy( dataPtr, sessionInfoPtr->receiveBuffer, bytesToCopy );
			remainder = sessionInfoPtr->receiveBufEnd - bytesToCopy;
			assert( remainder >= 0 );
			if( remainder > 0 )
				memmove( sessionInfoPtr->receiveBuffer,
						 sessionInfoPtr->receiveBuffer + bytesToCopy, remainder );
			sessionInfoPtr->receiveBufPos -= bytesToCopy;
			sessionInfoPtr->receiveBufEnd = remainder;
			assert( sessionInfoPtr->receiveBufPos >= 0 );

			/* Adjust the byte count info and, if we've satisfied the request,
			   exit */
			bytesCopied += bytesToCopy;
			dataPtr += bytesToCopy;
			if( bytesCopied >= length )
				break;
			}
		assert( sessionInfoPtr->receiveBufPos == 0 );

		/* Try and read a complete packet.  This can return one of four classes 
		   of values:

			1. An error code.
			2. Zero to indicate that nothing was read.
			3a.OK_SPECIAL and read info READINFO_PARTIAL to indicate that a 
			   partial packet (not enough to process) was read.
			3b.OK_SPECIAL and read info READINFO_NOOP to indicate that a 
			   no-op packet was read and the caller should try again without 
			   changing the read timeout value.
			4. A byte count if a complete packet was read and processed */
		status = tryRead( sessionInfoPtr, &readInfo );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			/* If there's an error reading data, only return an error status
			   if we haven't already returned existing/earlier data.  This 
			   ensures that the caller can drain out any remaining data from 
			   the session buffer before they start getting error returns */
			if( bytesCopied <= 0 )
				{
				bytesCopied = status;
				if( readInfo == READINFO_FATAL )
					sessionInfoPtr->readErrorState = status;
				}
			else
				/* If it's a fatal error, save the pending error state for 
				   later while returning the read byte count to the caller.
				   Note that this results in non-fatal errors being quietly 
				   dropped if data is otherwise available, the alternative 
				   would be to save it as a pending (specially-marked) non-
				   fatal error, however since this error type by definition 
				   can be resumed it may already have resolved itself by the 
				   next time we're called, so this is safe to do */
				if( readInfo == READINFO_FATAL )
					sessionInfoPtr->pendingErrorState = status;
			break;
			}
		if( status == 0 )
			/* We got nothing, exit */
			break;
		if( status == OK_SPECIAL )
			{
			/* If we read a partial packet and there's room for the rest of 
			   the packet in the buffer, set a minimum timeout to try and 
			   get the rest of the packet.  This is safe because tryRead() 
			   could have behaved in only one of two ways:

				1. Blocking read, in which case we waited for the full 
				   timeout period anyway and a small additional timeout 
				   won't be noticed.
				2. Nonblocking read, in which case waiting for a nonzero 
				   time could potentially have retrieved more data */
			assert( readInfo == READINFO_PARTIAL || \
					readInfo == READINFO_NOOP );
			if( readInfo == READINFO_PARTIAL && \
				sessionInfoPtr->pendingPacketRemaining <= \
				sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd )
				sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, NULL, 1 );
			}
		else
			{
			/* Make the stream nonblocking if it was blocking before.  This is 
			   necessary to avoid having the stream always block for the set 
			   timeout value on the last read */
			assert( status > 0 );
			sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, NULL, 0 );
			}

		assert( sessionInfoPtr->receiveBufEnd <= \
				sessionInfoPtr->receiveBufSize );
		assert( sessionInfoPtr->receiveBufPos <= \
				sessionInfoPtr->receiveBufEnd );
		}

	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, NULL,
			savedTimeout );
	return( bytesCopied );
	}

/* Send data to the remote system.  Session buffer management is handled as
   follows: The startOfs index points to the start of the payload space in 
   the buffer (everything before this is header data).  The maxPos index 
   points to the end of the payload space relative to the start of the buffer.
   This is needed for cases where the packet size is smaller than the buffer
   size:

	<- hdr->|<-- payload -->|
	+-------+---------------+---+
	|		|///////////////|	|
	+-------+---------------+---+
			^				^
			|				|
		startOfs		  maxPos

   The bPos index moves from startsOfs to maxPos, after which the data is
   flushed and the bPos index reset */

static int putData( SESSION_INFO *sessionInfoPtr, const void *data,
					const int length )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	BYTE *dataPtr = ( BYTE * ) data;
	int dataLength = length;

	assert( sessionInfoPtr->sendBufPos >= sessionInfoPtr->sendBufStartOfs && \
			sessionInfoPtr->sendBufPos <= protocolInfoPtr->sendBufMaxPos );

	/* If it's a flush, send the data through to the server and restart at
	   the start of the buffer payload space */
	if( dataLength <= 0 )
		{
		int status;

		if( sessionInfoPtr->sendBufPos <= sessionInfoPtr->sendBufStartOfs )
			return( CRYPT_OK );	/* There's no data to flush, exit */
		status = sessionInfoPtr->writeDataFunction( sessionInfoPtr );
		sessionInfoPtr->sendBufPos = sessionInfoPtr->sendBufStartOfs;
		if( cryptStatusError( status ) )
			sessionInfoPtr->writeErrorState = status;
		return( status );
		}

	/* If there's too much data to fit in the buffer, send it through to the
	   host */
	while( sessionInfoPtr->sendBufPos + dataLength >= \
		   protocolInfoPtr->sendBufMaxPos )
		{
		const int bytesToCopy = protocolInfoPtr->sendBufMaxPos - \
								sessionInfoPtr->sendBufPos;
		int status;

		assert( bytesToCopy >= 0 && bytesToCopy <= dataLength );

		/* Copy in as much data as we have room for and send it through */
		if( bytesToCopy > 0 )
			{
			memcpy( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufPos,
					dataPtr, bytesToCopy );
			sessionInfoPtr->sendBufPos += bytesToCopy;
			dataPtr += bytesToCopy;
			dataLength -= bytesToCopy;
			}
		status = sessionInfoPtr->writeDataFunction( sessionInfoPtr );
		sessionInfoPtr->sendBufPos = sessionInfoPtr->sendBufStartOfs;
		if( cryptStatusError( status ) )
			{
			sessionInfoPtr->writeErrorState = status;
			return( status );
			}
		}

	/* If there's anything left, it'll fit in the buffer, just copy it in */
	if( dataLength > 0 )
		{
		assert( sessionInfoPtr->sendBufPos + dataLength < \
				protocolInfoPtr->sendBufMaxPos );

		memcpy( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufPos,
				dataPtr, dataLength );
		sessionInfoPtr->sendBufPos += dataLength;
		}

	return( length );
	}

/* Read a fixed-size packet header, called by the secure data session 
   routines to read the fixed header on a data packet.  This is an atomic 
   read of out-of-band data that isn't part of the packet payload, so we 
   have to make sure that we've got the entire header before we can 
   continue:

		| <- hdrSize ->	|
	----+---------------+--------
	////|				|
	----+---------------+--------
		^		^
		|		|
	  bEnd	partialHdr 

   The data is read into the read buffer starting at the end of the last 
   payload packet bEnd (this is safe because this function causes a 
   pipeline stall so no more data can be read until the header has been
   read), the function returns CRYPT_ERROR_TIMEOUT until partialHdr reaches 
   the full header size */

int readFixedHeader( SESSION_INFO *sessionInfoPtr, const int headerSize )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	int status;

	/* If it's the first attempt at reading the header, set the total byte
	   count */
	if( sessionInfoPtr->partialHeaderLength <= 0 )
		sessionInfoPtr->partialHeaderLength = headerSize;
	else
		bufPtr += headerSize - sessionInfoPtr->partialHeaderLength;

	assert( sessionInfoPtr->partialHeaderLength > 0 && \
			sessionInfoPtr->partialHeaderLength <= headerSize );

	/* Clear the first few bytes of returned data to make sure that the 
	   higher-level code always bails out if the read fails for some reason 
	   without returning an error status */
	memset( bufPtr, 0, min( headerSize, 8 ) );

	/* Try and read the remaining header bytes */
	status = sread( &sessionInfoPtr->stream, bufPtr, 
					sessionInfoPtr->partialHeaderLength );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}

	/* If we didn't get the whole header, treat it as a timeout error */
	if( status < sessionInfoPtr->partialHeaderLength )
		{
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
					"Timeout during packet header read, only got %d of %d "
					"bytes", status, headerSize );

		/* We're in the data-processing stage, it's a soft timeout error */
		sessionInfoPtr->partialHeaderLength -= status;
		return( 0 );
		}

	/* We've got the whole header ready to process */
	assert( sessionInfoPtr->partialHeaderLength == status );
	sessionInfoPtr->partialHeaderLength = 0;
	return( headerSize );
	}

/****************************************************************************
*																			*
*				Request/response Session Data Handling Functions			*
*																			*
****************************************************************************/

/* Read/write a PKI (i.e.ASN.1-encoded) datagram */

int readPkiDatagram( SESSION_INFO *sessionInfoPtr )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, SESSION_INFO ) );

	/* Read the datagram */
	sessionInfoPtr->receiveBufEnd = 0;
	status = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					sessionInfoPtr->receiveBufSize );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < 4 )
		/* Perform a sanity check on the length.  This avoids some 
		   assertions in the debug build, and provides somewhat more 
		   specific information for the caller than the invalid encoding
		   error that we'd get later */
		retExt( sessionInfoPtr, CRYPT_ERROR_UNDERFLOW, 
				"Invalid PKI message length %d", status );

	/* Find out how much data we got and perform a firewall check that
	   everything is OK.  We rely on this rather than the read byte count
	   since checking the ASN.1, which is the data that will actually be
	   processed, avoids any vagaries of server implementation oddities */
	length = checkObjectEncoding( sessionInfoPtr->receiveBuffer, status );
	if( cryptStatusError( length ) )
		retExt( sessionInfoPtr, length, "Invalid PKI message encoding" );
	sessionInfoPtr->receiveBufEnd = length;
	return( CRYPT_OK );
	}

int writePkiDatagram( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, SESSION_INFO ) );
	assert( sessionInfoPtr->receiveBufEnd > 4 );

	/* Write the datagram */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	if( cryptStatusError( status ) )
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
	sessionInfoPtr->receiveBufEnd = 0;
	return( status );
	}

/****************************************************************************
*																			*
*						Session Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a session object */

static int processGetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->connectTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_TIMEOUT:
			if( sessionInfoPtr->timeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->timeout;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = sessionInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = sessionInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->receiveBufSize;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:
			*valuePtr = sessionInfoPtr->errorCode;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Only secure transport sessions can be persistently active,
			   request/response sessions are only active while the 
			   transaction is in progress */
			*valuePtr = sessionInfoPtr->iCryptInContext != CRYPT_ERROR && \
						( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CONNECTIONACTIVE:
			*valuePtr = ( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
			*valuePtr = sessionInfoPtr->serverPort;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CLIENT_PORT:
			if( !sessionInfoPtr->clientPort )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_ERROR_NOTINITED ) );
			*valuePtr = sessionInfoPtr->clientPort;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_VERSION:
			*valuePtr = sessionInfoPtr->version;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( SESSION_INFO *sessionInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const int value = *( int * ) messageDataPtr;
	int status;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			sessionInfoPtr->connectTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_TIMEOUT:
			sessionInfoPtr->timeout = value;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			assert( !( sessionInfoPtr->flags & SESSION_ISOPEN ) );
			sessionInfoPtr->receiveBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Session state and persistent sessions are handled as follows:
			   The CRYPT_SESSINFO_ACTIVE attribute records the active state
			   of the session as a whole, and the 
			   CRYPT_SESSINFO_CONNECTIONACTIVE attribute records the state of
			   the underlying comms session.  Setting CRYPT_SESSINFO_ACTIVE 
			   for the first time activates the comms session, and leaves it 
			   active if the underlying mechanism (e.g. HTTP 1.1 persistent 
			   connections) support it.  The CRYPT_SESSINFO_ACTIVE attribute 
			   is reset once the transaction completes, and further 
			   transactions can be initiated as long as 
			   CRYPT_SESSINFO_CONNECTIONACTIVE is set:

										Obj.state	_active		_connactive
										---------	-------		-----------
				create						0			0			0
				setattr						0			0			0
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
				setattr						1			0			1
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
					(peer closes conn)		1			0			0
				setattr							CRYPT_ERROR_COMPLETE */
			if( value == FALSE )
				return( CRYPT_OK );	/* No-op */

			status = activateSession( sessionInfoPtr );
			if( cryptArgError( status ) )
				{
				/* Catch leaked low-level status values.  The session 
				   management code does a large amount of work involving 
				   other cryptlib objects, so it's quite possible that an 
				   unexpected failure at some point will leak through an 
				   inappropriate status value */
				assert( NOTREACHED );
				status = CRYPT_ERROR_FAILED;
				}
			return( status );

		case CRYPT_SESSINFO_SERVER_PORT:
			/* If there's already a transport session or network socket 
			   specified, we can't set a port as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			sessionInfoPtr->serverPort = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_VERSION:
			if( value < sessionInfoPtr->protocolInfo->minVersion || \
				value > sessionInfoPtr->protocolInfo->maxVersion )
				return( CRYPT_ARGERROR_VALUE );
			sessionInfoPtr->version = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PRIVATEKEY:
			{
			const int requiredAttributeFlags = \
					( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
						sessionInfoPtr->serverReqAttrFlags : \
						sessionInfoPtr->clientReqAttrFlags;

			/* Make sure that it's a private key */
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusError( status ) )
				{
				if( sessionInfoPtr->type != CRYPT_SESSION_SSL )
					return( CRYPT_ARGERROR_NUM1 );

				/* SSL can also do key-agreement-based key exchange, so we
				   fall back to this if key-transport-based exchange isn't
				   possible */
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_KA_EXPORT );
				if( cryptStatusError( status ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* If we need a private key with certain capabilities, make sure 
			   that it has these capabilities.  This is a more specific check 
			   than that allowed by the kernel */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYSIGN )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_SIGN );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCRYPT )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_DECRYPT );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}

			/* If we need a private key with a cert, make sure that the
			   appropriate type of initialised cert object is present.  This
			   is a more specific check than that allowed by the kernel */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCERT )
				{
				int attrValue;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_IMMUTABLE );
				if( cryptStatusError( status ) || !attrValue )
					return( CRYPT_ARGERROR_NUM1 );
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) ||
					( attrValue != CRYPT_CERTTYPE_CERTIFICATE && \
					  attrValue != CRYPT_CERTTYPE_CERTCHAIN ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( ( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCACERT ) && \
				cryptStatusError( \
					krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
					return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key meets the mininum height requirements.  
			   We only perform this check if we're explicitly being asked to
			   perform the check and it's a server session (which has certain
			   minimum length requirements for private keys), for client
			   sessions the permitted length/security level is controlled by
			   the server so we can't really perform much checking */
			if( sessionInfoPtr->protocolInfo->requiredPrivateKeySize && \
				( sessionInfoPtr->flags & SESSION_ISSERVER ) )
				{
				int length;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &length, CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) || \
					length < sessionInfoPtr->protocolInfo->requiredPrivateKeySize )
					return( exitError( sessionInfoPtr,
									   CRYPT_SESSINFO_PRIVATEKEY,
									   CRYPT_ERRTYPE_ATTR_SIZE,
									   CRYPT_ARGERROR_NUM1 ) );
				}

			/* Perform any protocol-specific checks if necessary */
			if( sessionInfoPtr->checkAttributeFunction != NULL )
				{
				status = sessionInfoPtr->checkAttributeFunction( sessionInfoPtr,
											value, CRYPT_SESSINFO_PRIVATEKEY );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Add the private key and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->privateKey = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_KEYSET:
			{
			int type;

			/* Make sure that it's a cert store (rather than just a generic
			   keyset) if required */
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSTORE )
				{
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &type, CRYPT_IATTRIBUTE_SUBTYPE );
				if( cryptStatusError( status ) || \
					( type != SUBTYPE_KEYSET_DBMS_STORE ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* Add the keyset and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->cryptKeyset = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_SESSION:
			/* If there's already a host or network socket specified, we 
			   can't set a transport session as well */
			if( sessionInfoPtr->serverName[ 0 ] )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Add the transport mechanism and increment its reference
			   count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->transportSession = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_NETWORKSOCKET:
			{
			NET_CONNECT_INFO connectInfo;
			STREAM stream;

			/* If there's already a host or session specified, we can't set 
			   a network socket as well */
			if( sessionInfoPtr->serverName[ 0 ] )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );

			/* Create a dummy network stream to make sure that the network 
			   socket is OK */
			initNetConnectInfo( &connectInfo, sessionInfoPtr->ownerHandle, 
								sessionInfoPtr->timeout, 
								sessionInfoPtr->connectTimeout,
								NET_OPTION_NETWORKSOCKET_DUMMY );
			connectInfo.networkSocket = value;
			status = sNetConnect( &stream, STREAM_PROTOCOL_TCPIP, 
								  &connectInfo, sessionInfoPtr->errorMessage, 
								  &sessionInfoPtr->errorCode );
			if( cryptStatusError( status ) )
				return( status );
			sNetDisconnect( &stream );

			/* Add the network socket */
			sessionInfoPtr->networkSocket = value;
			return( CRYPT_OK );
			}
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( exitErrorNotFound( sessionInfoPtr,
									   messageValue ) );

		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			if( !*sessionInfoPtr->errorMessage )
				/* We don't set extended error information for this atribute
				   because it's usually read in response to an existing error, 
				   which would overwrite the existing error information */
				return( CRYPT_ERROR_NOTFOUND );
			return( attributeCopy( msgData, sessionInfoPtr->errorMessage,
								   strlen( sessionInfoPtr->errorMessage ) ) );

		case CRYPT_SESSINFO_USERNAME:
			if( sessionInfoPtr->userNameLength <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_USERNAME ) );
			return( attributeCopy( msgData, sessionInfoPtr->userName,
								   sessionInfoPtr->userNameLength ) );

		case CRYPT_SESSINFO_PASSWORD:
			if( sessionInfoPtr->passwordLength <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_PASSWORD ) );
			return( attributeCopy( msgData, sessionInfoPtr->password,
								   sessionInfoPtr->passwordLength ) );

		case CRYPT_SESSINFO_SERVER_NAME:
			if( !strlen( sessionInfoPtr->serverName ) )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_SERVER_NAME ) );
			return( attributeCopy( msgData, sessionInfoPtr->serverName,
								   strlen( sessionInfoPtr->serverName ) ) );

		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
			if( sessionInfoPtr->keyFingerprintSize <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_SERVER_FINGERPRINT ) );
			return( attributeCopy( msgData, sessionInfoPtr->keyFingerprint,
								   sessionInfoPtr->keyFingerprintSize ) );

		case CRYPT_SESSINFO_CLIENT_NAME:
			if( !strlen( sessionInfoPtr->clientName ) )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_CLIENT_NAME ) );
			return( attributeCopy( msgData, sessionInfoPtr->clientName,
								   strlen( sessionInfoPtr->clientName ) ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( CRYPT_ARGERROR_VALUE );

		case CRYPT_SESSINFO_USERNAME:
			assert( msgData->length <= CRYPT_MAX_TEXTSIZE );
			if( sessionInfoPtr->userNameLength > 0 && \
				!( sessionInfoPtr->type == CRYPT_SESSION_SSL && \
				   sessionInfoPtr->flags & SESSION_ISSERVER ) )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_USERNAME ) );
			if( isPKIUserValue( msgData->data, msgData->length ) )
				{
				/* It's an encoded user value, make sure that it's in order.  
				   We store the encoded form at this stage in case the user
				   tries to read it back */
				const int status = decodePKIUserValue( NULL, msgData->data,
													   msgData->length );
				if( cryptStatusError( status ) )
					return( status );
				sessionInfoPtr->flags |= SESSION_ISENCODEDUSERID;
				}
			memcpy( sessionInfoPtr->userName, msgData->data,
					msgData->length );
			sessionInfoPtr->userNameLength = msgData->length;
			if( sessionInfoPtr->flags & SESSION_CHANGENOTIFY_USERID )
				{
				assert( sessionInfoPtr->setAttributeFunction != NULL );

				/* Reflect the change down to the protocol-specific code */
				return( sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
									messageDataPtr, CRYPT_SESSINFO_USERNAME ) );
				}
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PASSWORD:
			assert( msgData->length <= CRYPT_MAX_TEXTSIZE );
			if( sessionInfoPtr->passwordLength > 0 && \
				!( sessionInfoPtr->type == CRYPT_SESSION_SSL && \
				   sessionInfoPtr->flags & SESSION_ISSERVER ) )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_PASSWORD ) );
			if( isPKIUserValue( msgData->data, msgData->length ) )
				{
				BYTE decodedPassword[ CRYPT_MAX_TEXTSIZE ];
				int status;

				/* It's an encoded user value, make sure that it's in order */
				status = decodePKIUserValue( decodedPassword, msgData->data, 
											 msgData->length );
				zeroise( decodedPassword, CRYPT_MAX_TEXTSIZE );
				if( cryptStatusError( status ) )
					return( status );
				sessionInfoPtr->flags |= SESSION_ISENCODEDPW;
				}
			memcpy( sessionInfoPtr->password, msgData->data,
					msgData->length );
			sessionInfoPtr->passwordLength = msgData->length;
			if( sessionInfoPtr->flags & SESSION_CHANGENOTIFY_PASSWD )
				{
				assert( sessionInfoPtr->setAttributeFunction != NULL );

				/* Reflect the change down to the protocol-specific code */
				return( sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
									messageDataPtr, CRYPT_SESSINFO_PASSWORD ) );
				}
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_NAME:
			{
			const PROTOCOL_INFO *protocolInfoPtr = \
										sessionInfoPtr->protocolInfo;
			URL_INFO urlInfo;
			int status;

			assert( msgData->length < MAX_URL_SIZE );
			if( sessionInfoPtr->serverName[ 0 ] )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );

			/* If there's already a transport session or network socket 
			   specified, we can't set a server name as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Parse the server name */
			status = sNetParseURL( &urlInfo, msgData->data, 
								   msgData->length );
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* We can only use autodetection with PKI services */
			if( !strCompare( msgData->data, "[Autodetect]", 
							 msgData->length ) && \
				!protocolInfoPtr->isReqResp )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* If there's a port or user name specified in the URL, set the 
			   appropriate attributes */
			if( urlInfo.userInfoLen > 0 )
				{
				RESOURCE_DATA userInfoMsgData;

				krnlSendMessage( sessionInfoPtr->objectHandle, 
								 IMESSAGE_DELETEATTRIBUTE, NULL,
								 CRYPT_SESSINFO_USERNAME );
				setMessageData( &userInfoMsgData, ( void * ) urlInfo.userInfo, 
								urlInfo.userInfoLen );
				status = krnlSendMessage( sessionInfoPtr->objectHandle, 
										  IMESSAGE_SETATTRIBUTE_S, 
										  &userInfoMsgData,
										  CRYPT_SESSINFO_USERNAME );
				}
			if( cryptStatusOK( status ) && urlInfo.port > 0 )
				{
				krnlSendMessage( sessionInfoPtr->objectHandle, 
								 IMESSAGE_DELETEATTRIBUTE, NULL,
								 CRYPT_SESSINFO_SERVER_PORT );
				status = krnlSendMessage( sessionInfoPtr->objectHandle, 
										  IMESSAGE_SETATTRIBUTE, &urlInfo.port,
										  CRYPT_SESSINFO_SERVER_PORT );
				}
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   CRYPT_ARGERROR_STR1 ) );

			/* Remember the server name and transport type */
			memcpy( sessionInfoPtr->serverName, urlInfo.host, urlInfo.hostLen );
			sessionInfoPtr->serverName[ urlInfo.hostLen ] = 0;
			if( urlInfo.locationLen > 0 )
				{
				memcpy( sessionInfoPtr->serverName + urlInfo.hostLen, 
						urlInfo.location, urlInfo.locationLen );
				sessionInfoPtr->serverName[ urlInfo.hostLen + \
											urlInfo.locationLen ] = 0;
				}
			if( protocolInfoPtr->altProtocolInfo != NULL && \
				urlInfo.schemaLen == \
						strlen( protocolInfoPtr->altProtocolInfo->uriType ) && \
				!strCompare( sessionInfoPtr->serverName, 
							 protocolInfoPtr->altProtocolInfo->uriType,
							 strlen( protocolInfoPtr->altProtocolInfo->uriType ) ) )
				{
				/* The caller has specified the use of the altnernate 
				   transport protocol type, switch to that instead of HTTP */
				sessionInfoPtr->flags &= ~SESSION_ISHTTPTRANSPORT;
				sessionInfoPtr->flags |= SESSION_USEALTTRANSPORT;
				}
			else
				if( sessionInfoPtr->protocolInfo->flags & SESSION_ISHTTPTRANSPORT )
					{
					sessionInfoPtr->flags &= ~SESSION_USEALTTRANSPORT;
					sessionInfoPtr->flags |= SESSION_ISHTTPTRANSPORT;
					}
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
			/* If there's already a fingerprint set, we can't set another 
			   one */
			if( sessionInfoPtr->keyFingerprintSize > 0 )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_FINGERPRINT ) );

			/* Remember the server key fingerprint */
			memcpy( sessionInfoPtr->keyFingerprint, msgData->data,
					msgData->length );
			sessionInfoPtr->keyFingerprintSize = msgData->length;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processDeleteAttribute( SESSION_INFO *sessionInfoPtr,
								   const int messageValue )
	{
	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_NET_TIMEOUT:
			if( sessionInfoPtr->timeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->timeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_ERROR_NOTINITED ) );
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_USERNAME:
			{
			int status = CRYPT_OK;

			if( sessionInfoPtr->userNameLength <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_USERNAME ) );
			if( sessionInfoPtr->flags & SESSION_CHANGENOTIFY_USERID )
				/* Reflect the deletion down to the protocol-specific code, 
				   handled by setting a null attribute value */
				status = sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
										NULL, CRYPT_SESSINFO_USERNAME );
			memset( sessionInfoPtr->userName, 0, CRYPT_MAX_TEXTSIZE );
			sessionInfoPtr->userNameLength = 0;
			sessionInfoPtr->flags &= ~SESSION_ISENCODEDUSERID;
			return( status );
			}

		case CRYPT_SESSINFO_PASSWORD:
			{
			int status = CRYPT_OK;

			if( sessionInfoPtr->passwordLength <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_PASSWORD ) );
			if( sessionInfoPtr->flags & SESSION_CHANGENOTIFY_PASSWD )
				/* Reflect the deletion down to the protocol-specific code, 
				   handled by setting a null attribute value */
				status = sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
										NULL, CRYPT_SESSINFO_PASSWORD );
			zeroise( sessionInfoPtr->password, CRYPT_MAX_TEXTSIZE );
			sessionInfoPtr->passwordLength = 0;
			sessionInfoPtr->flags &= ~SESSION_ISENCODEDPW;
			return( status );
			}

		case CRYPT_SESSINFO_SERVER_NAME:
			if( !strlen( sessionInfoPtr->serverName ) )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_SERVER_NAME ) );
			memset( sessionInfoPtr->serverName, 0, MAX_URL_SIZE + 1 );
			return( CRYPT_OK );

		case CRYPT_SESSINFO_REQUEST:
			if( sessionInfoPtr->iCertRequest == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_REQUEST ) );
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCertRequest = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_TSP_MSGIMPRINT:
			if( sessionInfoPtr->tspImprintAlgo == CRYPT_ALGO_NONE || \
				sessionInfoPtr->tspImprintSize <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_TSP_MSGIMPRINT ) );
			sessionInfoPtr->tspImprintAlgo = CRYPT_ALGO_NONE;
			sessionInfoPtr->tspImprintSize = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Session Message Handler						*
*																			*
****************************************************************************/

/* Handle a message sent to a session object */

static int sessionMessageFunction( const void *objectInfoPtr,
								   const MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	SESSION_INFO *sessionInfoPtr = ( SESSION_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the session if required.  Nemo nisi mors */
		if( sessionInfoPtr->flags & SESSION_ISOPEN )
			sessionInfoPtr->shutdownFunction( sessionInfoPtr );

		/* Clear and free session state information if necessary */
		if( sessionInfoPtr->sendBuffer != NULL )
			{
			zeroise( sessionInfoPtr->sendBuffer,
					 sessionInfoPtr->sendBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->sendBuffer );
			}
		if( sessionInfoPtr->receiveBuffer != NULL )
			{
			zeroise( sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufSize );
			clFree( "sessionMessageFunction", sessionInfoPtr->receiveBuffer );
			}

		/* Clean up any session-related objects if necessary */
		if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthInContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertRequest != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCertResponse,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privateKey != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privateKey,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->privKeyset != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->privKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->transportSession != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->transportSession,
							  IMESSAGE_DECREFCOUNT );

		/* Delete the object itself */
		zeroise( sessionInfoPtr, sizeof( SESSION_INFO ) );
		clFree( "sessionMessageFunction", sessionInfoPtr );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		/* If it's a protocol-specific attribute, forward it directly to
		   the low-level code */
		if( message != MESSAGE_DELETEATTRIBUTE && \
			( ( messageValue >= CRYPT_SESSINFO_FIRST_SPECIFIC && \
				messageValue <= CRYPT_SESSINFO_LAST_SPECIFIC ) || \
			  messageValue == CRYPT_IATTRIBUTE_ENC_TIMESTAMP ) )
			{
			int status;

			if( message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S )
				{
				assert( sessionInfoPtr->setAttributeFunction != NULL );

				status = sessionInfoPtr->setAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_INITED )
					return( exitErrorInited( sessionInfoPtr, 
											 messageValue ) );
				}
			else
				{
				assert( message == MESSAGE_GETATTRIBUTE || \
						message == MESSAGE_GETATTRIBUTE_S );
				assert( sessionInfoPtr->getAttributeFunction != NULL );

				status = sessionInfoPtr->getAttributeFunction( sessionInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_NOTFOUND )
					return( exitErrorNotFound( sessionInfoPtr, 
											   messageValue ) );
				}
			return( status );
			}

		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( sessionInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( sessionInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_DELETEATTRIBUTE )
			return( processDeleteAttribute( sessionInfoPtr, messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_ENV_PUSHDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		/* If the session isn't open yet, perform an implicit open.  We have
		   to do this directly rather than by sending ourselves a message 
		   since it'd be enqueued for processing after the current one */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			{
			status = processSetAttribute( sessionInfoPtr, MESSAGE_VALUE_TRUE,
										  CRYPT_SESSINFO_ACTIVE );
			if( cryptStatusError( status ) )
				return( status );

			/* The session is ready to process data, move it into the high
			   state */
			krnlSendMessage( sessionInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED );
			}
		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->sendBuffer != NULL );
		assert( sessionInfoPtr->writeDataFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->flags & SESSION_SENDCLOSED )
			/* If the other side has closed its receive channel (which is 
			   our send channel), we can't send any more data, although we 
			   can still get data on our receive channel if we haven't closed
			   it as well.  The closing of the other side's send channel is 
			   detected during a read and isn't a write error but a normal 
			   state change in the channel, so we don't treat it as an error 
			   when it's seen at the read stage until the caller actually 
			   tries to write data to the closed channel */
			sessionInfoPtr->writeErrorState = CRYPT_ERROR_COMPLETE;
		if( sessionInfoPtr->writeErrorState != CRYPT_OK )
			return( sessionInfoPtr->writeErrorState );

		/* Write the data */
		clearErrorInfo( sessionInfoPtr );
		status = putData( sessionInfoPtr, msgData->data, msgData->length );
		if( cryptStatusError( status ) )
			return( status );
		msgData->length = status;
		return( CRYPT_OK );
		}
	if( message == MESSAGE_ENV_POPDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		/* If the session isn't open, there's nothing to pop */
		if( !( sessionInfoPtr->flags & SESSION_ISOPEN ) )
			return( CRYPT_ERROR_NOTINITED );

		assert( sessionInfoPtr->flags & SESSION_ISOPEN );
		assert( sessionInfoPtr->receiveBuffer != NULL );
		assert( sessionInfoPtr->readHeaderFunction != NULL );
		assert( sessionInfoPtr->processBodyFunction != NULL );

		/* Make sure that everything is in order */
		if( sessionInfoPtr->readErrorState != CRYPT_OK )
			return( sessionInfoPtr->readErrorState );

		/* Read the data */
		clearErrorInfo( sessionInfoPtr );
		status = getData( sessionInfoPtr, msgData->data, msgData->length );
		if( cryptStatusError( status ) )
			return( status );
		msgData->length = status;
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a session.  This is a low-level function encapsulated by createSession()
   and used to manage error exits */

static int openSession( CRYPT_SESSION *iCryptSession,
						const CRYPT_USER cryptOwner,
						const CRYPT_SESSION_TYPE sessionType,
						SESSION_INFO **sessionInfoPtrPtr )
	{
	SESSION_INFO *sessionInfoPtr;
	static const struct {
		const CRYPT_SESSION_TYPE sessionType;
		const CRYPT_SESSION_TYPE baseSessionType;
		const int subType;
		} sessionTypes[] = {
	{ CRYPT_SESSION_SSH, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH },
	{ CRYPT_SESSION_SSH_SERVER, CRYPT_SESSION_SSH, SUBTYPE_SESSION_SSH_SVR },
	{ CRYPT_SESSION_SSL, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL },
	{ CRYPT_SESSION_SSL_SERVER, CRYPT_SESSION_SSL, SUBTYPE_SESSION_SSL_SVR },
	{ CRYPT_SESSION_RTCS, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS },
	{ CRYPT_SESSION_RTCS_SERVER, CRYPT_SESSION_RTCS, SUBTYPE_SESSION_RTCS_SVR },
	{ CRYPT_SESSION_OCSP, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP },
	{ CRYPT_SESSION_OCSP_SERVER, CRYPT_SESSION_OCSP, SUBTYPE_SESSION_OCSP_SVR },
	{ CRYPT_SESSION_TSP, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP },
	{ CRYPT_SESSION_TSP_SERVER, CRYPT_SESSION_TSP, SUBTYPE_SESSION_TSP_SVR },
	{ CRYPT_SESSION_CMP, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP },
	{ CRYPT_SESSION_CMP_SERVER, CRYPT_SESSION_CMP, SUBTYPE_SESSION_CMP_SVR },
	{ CRYPT_SESSION_SCEP, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP },
	{ CRYPT_SESSION_SCEP_SERVER, CRYPT_SESSION_SCEP, SUBTYPE_SESSION_SCEP_SVR },
	{ CRYPT_SESSION_NONE, CRYPT_SESSION_NONE, CRYPT_ERROR }
	};
	int i, status;

	assert( sessionInfoPtrPtr != NULL );

	/* Clear the return values */
	*iCryptSession = CRYPT_ERROR;
	*sessionInfoPtrPtr = NULL;

	/* Map the external session type to a base type and internal object
	   subtype */
	for( i = 0; sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE; i++ )
		if( sessionTypes[ i ].sessionType == sessionType )
			break;
	assert( sessionTypes[ i ].sessionType != CRYPT_SESSION_NONE );

	/* Create the session object */
	status = krnlCreateObject( ( void ** ) &sessionInfoPtr, 
							   sizeof( SESSION_INFO ), OBJECT_TYPE_SESSION, 
							   sessionTypes[ i ].subType, 
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, sessionMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*sessionInfoPtrPtr = sessionInfoPtr;
	*iCryptSession = sessionInfoPtr->objectHandle = status;
	sessionInfoPtr->ownerHandle = cryptOwner;
	sessionInfoPtr->type = sessionTypes[ i ].baseSessionType;

	/* If it's a server session, mark it as such */
	if( sessionTypes[ i ].sessionType != sessionTypes[ i ].baseSessionType )
		sessionInfoPtr->flags = SESSION_ISSERVER;

	/* Set up any internal objects to contain invalid handles */
	sessionInfoPtr->iKeyexCryptContext = \
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
	sessionInfoPtr->iCryptInContext = \
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
	sessionInfoPtr->iAuthInContext = \
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
	sessionInfoPtr->iCertRequest = \
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
	sessionInfoPtr->privateKey = CRYPT_ERROR;
	sessionInfoPtr->cryptKeyset = CRYPT_ERROR;
	sessionInfoPtr->privKeyset =  CRYPT_ERROR;
	sessionInfoPtr->transportSession = CRYPT_ERROR;
	sessionInfoPtr->networkSocket = CRYPT_ERROR;
	sessionInfoPtr->timeout = sessionInfoPtr->connectTimeout = CRYPT_ERROR;

	/* Set up the access information for the session and initialise it */
	switch( sessionTypes[ i ].baseSessionType )
		{
		case CRYPT_SESSION_CMP:
			status = setAccessMethodCMP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_RTCS:
			status = setAccessMethodRTCS( sessionInfoPtr );
			break;

		case CRYPT_SESSION_OCSP:
			status = setAccessMethodOCSP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SCEP:
			status = setAccessMethodSCEP( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSH:
			status = setAccessMethodSSH( sessionInfoPtr );
			break;

		case CRYPT_SESSION_SSL:
			status = setAccessMethodSSL( sessionInfoPtr );
			break;

		case CRYPT_SESSION_TSP:
			status = setAccessMethodTSP( sessionInfoPtr );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusOK( status ) )
		{
		const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;

		/* Check that the protocol info is OK */
		assert( ( protocolInfoPtr->isReqResp && \
				  protocolInfoPtr->bufSize == 0 && \
				  protocolInfoPtr->sendBufStartOfs == 0 && \
				  protocolInfoPtr->sendBufMaxPos == 0 ) || 
				( !protocolInfoPtr->isReqResp && \
				  protocolInfoPtr->bufSize >= MIN_BUFFER_SIZE && \
				  protocolInfoPtr->sendBufStartOfs >= 5 && \
				  protocolInfoPtr->sendBufMaxPos <= protocolInfoPtr->bufSize ) );
		assert( ( ( protocolInfoPtr->flags & SESSION_ISHTTPTRANSPORT ) && \
				  protocolInfoPtr->port == 80 ) || \
				( protocolInfoPtr->port != 80 ) );
		assert( protocolInfoPtr->port > 21 );
		assert( protocolInfoPtr->version >= 0 );
		assert( ( protocolInfoPtr->isReqResp && \
				  protocolInfoPtr->clientContentType != NULL && \
				  protocolInfoPtr->serverContentType != NULL ) || 
				( !protocolInfoPtr->isReqResp && \
				  protocolInfoPtr->clientContentType == NULL && \
				  protocolInfoPtr->serverContentType == NULL ) );

		/* Copy mutable protocol-specific information into the session 
		   info */
		sessionInfoPtr->flags |= protocolInfoPtr->flags;
		sessionInfoPtr->serverPort = protocolInfoPtr->port;
		sessionInfoPtr->clientReqAttrFlags = \
								protocolInfoPtr->clientReqAttrFlags;
		sessionInfoPtr->serverReqAttrFlags = \
								protocolInfoPtr->serverReqAttrFlags;
		sessionInfoPtr->version = protocolInfoPtr->version;
		if( protocolInfoPtr->isReqResp )
			{
			sessionInfoPtr->sendBufSize = CRYPT_UNUSED;
			sessionInfoPtr->receiveBufSize = MIN_BUFFER_SIZE;
			}
		else
			{
			sessionInfoPtr->sendBufSize = \
				sessionInfoPtr->receiveBufSize = \
					protocolInfoPtr->bufSize;
			sessionInfoPtr->sendBufStartOfs = \
				sessionInfoPtr->receiveBufStartOfs = \
					protocolInfoPtr->sendBufStartOfs;
			}

		/* Install default handlers if no session-specific ones are 
		   provided */
		if( sessionInfoPtr->shutdownFunction == NULL )
			sessionInfoPtr->shutdownFunction = defaultShutdownFunction;
		if( sessionInfoPtr->connectFunction == NULL )
			sessionInfoPtr->connectFunction = \
				( sessionInfoPtr->flags & SESSION_ISSERVER ) ? 
				defaultServerStartupFunction : defaultClientStartupFunction;
		if( protocolInfoPtr->isReqResp && \
			sessionInfoPtr->getAttributeFunction == NULL )
			sessionInfoPtr->getAttributeFunction = defaultGetAttributeFunction;

		/* Check that the handlers are all OK */
		assert( sessionInfoPtr->connectFunction != NULL );
		assert( sessionInfoPtr->transactFunction != NULL );
		assert( ( protocolInfoPtr->isReqResp && \
				  sessionInfoPtr->readHeaderFunction == NULL && \
				  sessionInfoPtr->processBodyFunction == NULL && \
				  sessionInfoPtr->writeDataFunction == NULL ) || \
				( !protocolInfoPtr->isReqResp && \
				  sessionInfoPtr->readHeaderFunction != NULL && \
				  sessionInfoPtr->processBodyFunction != NULL && \
				  sessionInfoPtr->writeDataFunction != NULL ) );
		}
	return( status );
	}

int createSession( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_SESSION iCryptSession;
	SESSION_INFO *sessionInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_SESSION_NONE || \
		createInfo->arg1 >= CRYPT_SESSION_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = openSession( &iCryptSession, createInfo->cryptOwner,
							  createInfo->arg1, &sessionInfoPtr );
	if( sessionInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptSession, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptSession, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptSession;
	return( CRYPT_OK );
	}

/* Generic management function for this class of object */

int sessionManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	static int initLevel = 0;
	int status;

	assert( action == MANAGEMENT_ACTION_INIT || \
			action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			action == MANAGEMENT_ACTION_SHUTDOWN );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			status = netInitTCP();
			if( cryptStatusOK( status ) )
				{
				initLevel++;
				status = initSessionCache();
				}
			if( cryptStatusOK( status ) )
				initLevel++;
			return( status );

		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* We have to wait for the driver binding to complete before we
			   can start the shutdown process */
			waitSemaphore( SEMAPHORE_DRIVERBIND );
			if( initLevel > 0 )
				netSignalShutdown();
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_SHUTDOWN:
			if( initLevel > 1 )
				endSessionCache();
			if( initLevel > 0 )
				netEndTCP();
			initLevel = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
#endif /* USE_SESSIONS */
