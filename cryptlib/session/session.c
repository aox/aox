/****************************************************************************
*																			*
*						cryptlib Session Support Routines					*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise network connection information based on the contents of the
   session object */

void initSessionNetConnectInfo( const SESSION_INFO *sessionInfoPtr,
								NET_CONNECT_INFO *connectInfo )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	initNetConnectInfo( connectInfo, sessionInfoPtr->ownerHandle,
				sessionInfoPtr->readTimeout, sessionInfoPtr->connectTimeout,
				( sessionInfoPtr->transportSession != CRYPT_ERROR ) ? \
					NET_OPTION_TRANSPORTSESSION : \
				( sessionInfoPtr->networkSocket != CRYPT_ERROR ) ? \
					NET_OPTION_NETWORKSOCKET : \
					NET_OPTION_HOSTNAME );

	/* If there's an explicit server name set, connect to it if we're the 
	   client or bind to the named interface if we're the server */
	if( ( attributeListPtr = \
			findSessionAttribute( sessionInfoPtr->attributeList,
								  CRYPT_SESSINFO_SERVER_NAME ) ) != NULL )
		{
		connectInfo->name = attributeListPtr->value;
		connectInfo->nameLength = attributeListPtr->valueLength;
		}

	/* If there's an explicit port set, connect/bind to it, otherwise use the
	   default port for the protocol */
	if( ( attributeListPtr = \
			findSessionAttribute( sessionInfoPtr->attributeList,
								  CRYPT_SESSINFO_SERVER_PORT ) ) != NULL )
		connectInfo->port = attributeListPtr->intValue;
	else
		connectInfo->port = sessionInfoPtr->protocolInfo->port;

	/* Set the user-supplied transport session or socket if required */
	connectInfo->iCryptSession = sessionInfoPtr->transportSession;
	connectInfo->networkSocket = sessionInfoPtr->networkSocket;
	}

/****************************************************************************
*																			*
*							Session Activation Functions					*
*																			*
****************************************************************************/

/* Check client/server-specific required values */

static CRYPT_ATTRIBUTE_TYPE checkClientParameters( const SESSION_INFO *sessionInfoPtr )
	{
	/* Make sure that the network comms parameters are present */
	if( sessionInfoPtr->transportSession == CRYPT_ERROR && \
		sessionInfoPtr->networkSocket == CRYPT_ERROR && \
		findSessionAttribute( sessionInfoPtr->attributeList, 
							  CRYPT_SESSINFO_SERVER_NAME ) == NULL )
		return( CRYPT_SESSINFO_SERVER_NAME );

	/* Make sure that the username + password and/or user private key are 
	   present if required */
	if( ( sessionInfoPtr->clientReqAttrFlags & SESSION_NEEDS_USERID ) && \
		findSessionAttribute( sessionInfoPtr->attributeList, 
							  CRYPT_SESSINFO_USERNAME ) == NULL )
		return( CRYPT_SESSINFO_USERNAME );
	if( ( sessionInfoPtr->clientReqAttrFlags & SESSION_NEEDS_PASSWORD ) && \
		findSessionAttribute( sessionInfoPtr->attributeList, 
							  CRYPT_SESSINFO_PASSWORD ) == NULL )
		{
		/* There's no password present, see if we can use a private key as 
		   an alternative */
		if( !( sessionInfoPtr->clientReqAttrFlags & \
			   SESSION_NEEDS_KEYORPASSWORD ) || \
			sessionInfoPtr->privateKey == CRYPT_ERROR )
			return( CRYPT_SESSINFO_PASSWORD );
			}
	if( ( sessionInfoPtr->clientReqAttrFlags & SESSION_NEEDS_PRIVATEKEY ) && \
		sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		/* There's no private key present, see if we can use a password as 
		   an alternative */
		if( !( sessionInfoPtr->clientReqAttrFlags & \
			   SESSION_NEEDS_KEYORPASSWORD ) || \
			findSessionAttribute( sessionInfoPtr->attributeList, 
								  CRYPT_SESSINFO_PASSWORD ) == NULL )
			return( CRYPT_SESSINFO_PRIVATEKEY );
		}

	/* Make sure that request/response protocol data is present if required */
	if( ( sessionInfoPtr->clientReqAttrFlags & SESSION_NEEDS_REQUEST ) && \
		sessionInfoPtr->iCertRequest == CRYPT_ERROR )
		return( CRYPT_SESSINFO_REQUEST );

	return( CRYPT_ATTRIBUTE_NONE );
	}

static CRYPT_ATTRIBUTE_TYPE checkServerParameters( const SESSION_INFO *sessionInfoPtr )
	{
	/* Make sure that server key and keyset information is present if 
	   required */
	if( ( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_PRIVATEKEY ) && \
		sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		/* There's no private key present, see if we can use a username +
		   password as an alternative.  In the special case of password-
		   based SSL this isn't completely foolproof since the passwords are 
		   entered into a pool from which they can be deleted explicitly if 
		   the session is aborted in a non-resumable manner (but see the 
		   note in ssl_rw.c) or implicitly over time as they're displaced by 
		   other entries, however this is an extremely unlikely case and 
		   it's too tricky trying to track what is and isn't still active to 
		   handle this fully */
		if( !( sessionInfoPtr->serverReqAttrFlags & \
			   SESSION_NEEDS_KEYORPASSWORD ) || \
			findSessionAttribute( sessionInfoPtr->attributeList, 
								  CRYPT_SESSINFO_PASSWORD ) == NULL )
			return( CRYPT_SESSINFO_PRIVATEKEY );
		}
	if( ( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_KEYSET ) && \
		sessionInfoPtr->cryptKeyset == CRYPT_ERROR )
		return( CRYPT_SESSINFO_KEYSET );

	return( CRYPT_ATTRIBUTE_NONE );
	}

/* Activate the network connection for a session */

static int activateConnection( SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_ATTRIBUTE_TYPE errorAttribute;
	int status;

	/* Make sure that everything is set up ready to go */
	errorAttribute = ( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
					 checkServerParameters( sessionInfoPtr ) : \
					 checkClientParameters( sessionInfoPtr );
	if( errorAttribute != CRYPT_ATTRIBUTE_NONE )
		{
		setErrorInfo( sessionInfoPtr, errorAttribute, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Allocate the send and receive buffers if necessary.  The send buffer
	   isn't used for request-response session types that use the receive
	   buffer for both outgoing and incoming data, so we only allocate it if
	   it's actually required */
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
			findSessionAttribute( sessionInfoPtr->attributeList, 
								  CRYPT_SESSINFO_SERVER_NAME ) != NULL || \
			sessionInfoPtr->networkSocket != CRYPT_ERROR );
	assert( findSessionAttribute( sessionInfoPtr->attributeList,
								  CRYPT_SESSINFO_SERVER_PORT ) != NULL || \
			sessionInfoPtr->protocolInfo->port > 0 );
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
	if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
		{
		int timeout;

		status = krnlSendMessage( sessionInfoPtr->ownerHandle,
								  IMESSAGE_GETATTRIBUTE, &timeout,
								  CRYPT_OPTION_NET_READTIMEOUT );
		sessionInfoPtr->readTimeout = cryptStatusOK( status ) ? \
									  timeout : 30;
		}
	if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
		{
		int timeout;

		status = krnlSendMessage( sessionInfoPtr->ownerHandle,
								  IMESSAGE_GETATTRIBUTE, &timeout,
								  CRYPT_OPTION_NET_WRITETIMEOUT );
		sessionInfoPtr->writeTimeout = cryptStatusOK( status ) ? \
									   timeout : 30;
		}

	/* Wait for any async driver binding to complete.  We can delay this
	   until this very late stage because no networking functionality is
	   used until this point */
	krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );

	/* If this is the first time we've got here, activate the session */
	if( !( sessionInfoPtr->flags & SESSION_PARTIALOPEN ) )
		{
		status = sessionInfoPtr->connectFunction( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

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
			{
			/* If we need a check of a resource (for example a user name and
			   password or cert supplied by the other side) before we can 
			   complete the handshake, we remain in the handshake state so
			   the user can re-activate the session after confirming (or
			   denying) the resource */
			if( status == CRYPT_ENVELOPE_RESOURCE )
				sessionInfoPtr->flags |= SESSION_PARTIALOPEN;

			return( status );
			}

		/* Notify the kernel that the session key context is attached to the
		   session object.  Note that we increment its reference count even
		   though it's an internal object used only by the session, because
		   otherwise it'll be automatically destroyed by the kernel as a
		   zero-reference dependent object when the session object is
		   destroyed (but before the session object itself, since it's a
		   dependent object).  This automatic cleanup could cause problems 
		   for lower-level session management code that tries to work with 
		   the (apparently still-valid) handle, for example protocols that 
		   need to encrypt a close-channel message on shutdown */
		krnlSendMessage( sessionInfoPtr->objectHandle, IMESSAGE_SETDEPENDENT,
						 &sessionInfoPtr->iCryptInContext,
						 SETDEP_OPTION_INCREF );

		/* Set up the buffer management variables */
		sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd = 0;
		sessionInfoPtr->sendBufPos = sessionInfoPtr->sendBufStartOfs;

		/* For data transport sessions, partial reads and writes (that is,
		   sending and receiving partial packets in the presence of 
		   timeouts) are permitted */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_PARTIALREAD, NULL, 0 );
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_PARTIALWRITE, NULL, 0 );
		}

	/* The handshake has been completed, switch from the handshake timeout
	   to the data transfer timeout and remember that the session has been
	   successfully established */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HANDSHAKECOMPLETE, NULL, 0 );
	sessionInfoPtr->flags &= ~SESSION_PARTIALOPEN;
	sessionInfoPtr->flags |= SESSION_ISOPEN;

	return( CRYPT_OK );
	}

/* Activate a session */

static void cleanupReqResp( SESSION_INFO *sessionInfoPtr,
							const BOOLEAN isPostTransaction )
	{
	const BOOLEAN isServer = ( sessionInfoPtr->flags & SESSION_ISSERVER );

	/* Clean up server requests left over from a previous transaction/
	   created by the just-completed transaction */
	if( isServer && sessionInfoPtr->iCertRequest != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCertRequest,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertRequest = CRYPT_ERROR;
		}

	/* Clean up client/server responses left over from a previous
	   transaction and server responses created by the just-completed
	   transaction */
	if( ( isServer || !isPostTransaction ) && \
		sessionInfoPtr->iCertResponse != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCertResponse,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
		}
	}

int activateSession( SESSION_INFO *sessionInfoPtr )
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

	/* Carry out the transaction on the request-response connection.  We
	   perform a cleanup of request/response data around the activation,
	   beforehand to catch data such as responses left over from a previous
	   transaction, and afterwards to clean up ephemeral data such as
	   requests sent to a server */
	cleanupReqResp( sessionInfoPtr, FALSE );
	status = sessionInfoPtr->transactFunction( sessionInfoPtr );
	cleanupReqResp( sessionInfoPtr, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether the other side has indicated that it's closing the 
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
*							Session Shutdown Functions						*
*																			*
****************************************************************************/

/* Send a close notification.  This requires special-case handling because
   it's not certain how long we should wait around for the close to happen.
   If we're in the middle of a cryptlib shutdown we don't want to wait 
   around forever since this would stall the overall shutdown, but if it's a 
   standard session shutdown we should wait for at least a small amount of
   time to ensure that all of the data is sent */

int sendCloseNotification( SESSION_INFO *sessionInfoPtr,
						   const void *data, const int length )
	{
	BOOLEAN isShutdown = FALSE;
	int dummy, status = CRYPT_OK;

	assert( ( data == NULL && length == 0 ) || \
			isReadPtr( data, length ) );

	/* Determine whether we're being shut down as a part of a general 
	   cryptlib shutdown or just a session shutdown.  We do this by trying 
	   to read a config option from the owning user object, if the kernel is 
	   in the middle of a shutdown it disallows all frivolous messages so 
	   if we get a permission error we're in the middle of the shutdown */
	if( krnlSendMessage( sessionInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE, 
						 &dummy, CRYPT_OPTION_INFO_MAJORVERSION ) == CRYPT_ERROR_PERMISSION )
		isShutdown = TRUE;

	/* If necessary set a timeout sufficient to at least provide a chance of 
	   sending our close alert and receiving the other side's ack of the 
	   close, but without leading to excessive delays during the shutdown */
	if( isShutdown )
		/* It's a cryptlib-wide shutdown, try and get out as quickly as
		   possible */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_WRITETIMEOUT, 
				NULL, 2 );
	else
		{
		int timeout;

		/* It's a standard session shutdown, wait around for at least five
		   seconds, but not more than fifteen */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_WRITETIMEOUT, 
				&timeout, 0 );
		if( timeout < 5 )
			timeout = 5;
		if( timeout > 15 )
			timeout = 15;
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_WRITETIMEOUT, 
				NULL, timeout );
		}

	/* Send the close notification to the peer */
	if( data != NULL )
		status = swrite( &sessionInfoPtr->stream, data, length );

	/* Close the send side of the connection if it's a cryptlib-internal 
	   socket.  This is needed by some implementations that want to see a 
	   FIN before they react to a shutdown notification, as well as being
	   a hint to the network code to flush any remaining data enqueued for
	   sending before the arrival of the full close.  If it's a user-managed 
	   socket we can't perform the partial close since this would affect the 
	   state of the socket as seen by the user, since the need to see the 
	   FIN is fairly rare we choose this as the less problematic of the two 
	   options */
	if( sessionInfoPtr->networkSocket == CRYPT_ERROR )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CLOSESENDCHANNEL, 
				NULL, 0 );

	return( ( data == NULL || !cryptStatusError( status ) ) ? \
			CRYPT_OK : status );
	}

/****************************************************************************
*																			*
*							Default Action Handlers							*
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

			/* If we'd be using the HTTP port for a session-specific 
			   protocol, change it to the default port for the session-
			   specific protocol instead */
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
	int port, status;

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

			/* If we'd be using the HTTP port for a session-specific 
			   protocol, change it to the default port for the session-
			   specific protocol instead */
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
	if( sessionInfoPtr->flags & SESSION_ISHTTPTRANSPORT )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CONTENTTYPE,
				( void * ) protocolInfoPtr->serverContentType,
				strlen( protocolInfoPtr->serverContentType ) );

	/* Save the client details for the caller, using the (always-present)
	   receive buffer as the intermediate store.  We don't bother checking
	   the return values for the call since it's not critical information,
	   if it can't be added it's no big deal */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_GETCLIENTNAME,
			sessionInfoPtr->receiveBuffer, 0 );
	addSessionAttribute( &sessionInfoPtr->attributeList, 
						 CRYPT_SESSINFO_CLIENT_NAME, 
						 sessionInfoPtr->receiveBuffer,
						 strlen( sessionInfoPtr->receiveBuffer ) );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_GETCLIENTPORT, &port, 0 );
	addSessionAttribute( &sessionInfoPtr->attributeList, 
						 CRYPT_SESSINFO_CLIENT_PORT, NULL, port );

	return( CRYPT_OK );
	}

static void defaultShutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Default get-attribute function used when no session-specific one is
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

/* Set up the function pointers to the session I/O methods */

int initSessionIO( SESSION_INFO *sessionInfoPtr )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;

	/* Install default handler functions if required */
	if( sessionInfoPtr->shutdownFunction == NULL )
		sessionInfoPtr->shutdownFunction = defaultShutdownFunction;
	if( sessionInfoPtr->connectFunction == NULL )
		sessionInfoPtr->connectFunction = \
			( sessionInfoPtr->flags & SESSION_ISSERVER ) ? 
			defaultServerStartupFunction : defaultClientStartupFunction;
	if( protocolInfoPtr->isReqResp && \
		sessionInfoPtr->getAttributeFunction == NULL )
		sessionInfoPtr->getAttributeFunction = defaultGetAttributeFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SESSIONS */
