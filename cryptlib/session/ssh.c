/****************************************************************************
*																			*
*						cryptlib SSH Session Management						*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssh.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
  #include "../session/ssh.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#if defined( USE_SSH1 ) || defined( USE_SSH2 )

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise and destroy the handshake state information */

static int initHandshakeInfo( SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Initialise the handshake state info values */
	memset( handshakeInfo, 0, sizeof( SSH_HANDSHAKE_INFO ) );
	handshakeInfo->iExchangeHashcontext = \
		handshakeInfo->iServerCryptContext = CRYPT_ERROR;

	return( CRYPT_OK );
	}

static void destroyHandshakeInfo( SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->iExchangeHashcontext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iExchangeHashcontext,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->iServerCryptContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iServerCryptContext,
						  IMESSAGE_DECREFCOUNT );

	zeroise( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) );
	}

/* Initialise and destroy the security contexts */

static void destroySecurityContexts( SESSION_INFO *sessionInfoPtr )
	{
	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	}

int initSecurityContexts( SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
		krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &sessionInfoPtr->cryptBlocksize,
						 CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) && sessionInfoPtr->version == 1 && \
		sessionInfoPtr->cryptAlgo == CRYPT_ALGO_IDEA )
		{
		const int cryptMode = CRYPT_MODE_CFB;

		/* SSHv1 uses stream ciphers in places, for which we have to set the
		   mode explicitly */
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE,
								  ( void * ) &cryptMode,
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
									  IMESSAGE_SETATTRIBUTE,
									  ( void * ) &cryptMode,
									  CRYPT_CTXINFO_MODE );
		}
	if( cryptStatusOK( status ) && sessionInfoPtr->version == 2 )
		{
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
			setMessageCreateObjectInfo( &createInfo,
										sessionInfoPtr->integrityAlgo );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
			krnlSendMessage( sessionInfoPtr->iAuthInContext,
							 IMESSAGE_GETATTRIBUTE,
							 &sessionInfoPtr->authBlocksize,
							 CRYPT_CTXINFO_BLOCKSIZE );
			}
		}
	if( cryptStatusError( status ) )
		/* One or more of the contexts couldn't be created, destroy all the
		   contexts that have been created so far */
		destroySecurityContexts( sessionInfoPtr );
	return( status );
	}

/* Read the SSH version information string */

static int readVersionLine( STREAM *stream, BYTE *buffer )
	{
	int length, status;

	/* Try and read the initial ID string data */
	status = sread( stream, buffer, SSH_ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( status < SSH_ID_SIZE )
		/* This can happen if the caller sets a very short read timeout */
		return( CRYPT_ERROR_UNDERFLOW );

	/* Read the remainder of the text line, one character at a time.  If
	   this was an HTTP stream we could use speculative read-ahead buffering,
	   but there's no easy way to communicate this requirement to the stream-
	   handling code */
	for( length = SSH_ID_SIZE; length < SSH_ID_MAX_SIZE; length++ )
		{
		status = sread( stream, buffer + length, 1 );
		if( cryptStatusError( status ) )
			return( status );
		if( status <= 0 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( !buffer[ length ] )
			/* The spec doesn't really say what is and isn't valid in the ID
			   strings, although it does say that nuls shouldn't be used.  
			   In any case we can't allow these because they'd cause 
			   problems for the string-handling functions */
			return( CRYPT_ERROR_BADDATA );
		if( buffer[ length ] == '\n' )
			break;
		}
	if( ( length < SSH_ID_SIZE + 3 ) || ( length >= SSH_ID_MAX_SIZE ) )
		return( CRYPT_ERROR_BADDATA );

	/* Null-terminate the string so that we can hash it to create the SSHv2
	   exchange hash */
	while( length > 0 && \
		   ( buffer[ length - 1 ] == '\r' || buffer[ length - 1 ] == '\n' ) )
		length--;
	buffer[ length ] = '\0';

	return( CRYPT_OK );
	}

static int readVersionString( SESSION_INFO *sessionInfoPtr )
	{
	const char *versionStringPtr = sessionInfoPtr->receiveBuffer + SSH_ID_SIZE;
	int linesRead = 0, status;

	/* Read the server version info, with the format for the ID string being
	   "SSH-protocolversion-softwareversion comments", which (in the original
	   ssh.com interpretation) was "SSH-x.y-x.y vendorname" (e.g.
	   "SSH-2.0-3.0.0 SSH Secure Shell") but for almost everyone else is
	   "SSH-x.y-vendorname*version" (e.g "SSH-2.0-OpenSSH_3.0").

	   This version info handling is rather ugly since it's a variable-length
	   string terminated with a newline, so we have to process it a character
	   at a time after the initial fixed data.

	   Unfortunately the SSH RFC further complicates this by allowing 
	   implementations to send non-version-related text lines before the 
	   version line.  The theory is that this will allow applications like 
	   TCP wrappers to display a (human-readable) error message before 
	   disconnecting, however some installations use it to display general
	   banners before the ID string.  Since the RFC doesn't provide any means
	   of distinguishing this banner information from arbitrary data, we
	   can't quickly reject attempts to connect to something that isn't an
	   SSH server.  In other words we have to sit here waiting for further 
	   data in the hope that eventually an SSH ID turns up, until such time 
	   as the connect timeout expires.  In order to provide a more useful
	   message than a somewhat confusing timeout error, we remember whether
	   we've already read any lines of text and if we have, report it as an
	   invalid ID error rather than a timeout error */
	do
		{
		status = readVersionLine( &sessionInfoPtr->stream, 
								  sessionInfoPtr->receiveBuffer );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_BADDATA )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid SSH version string length" );
			if( status == CRYPT_ERROR_UNDERFLOW )
				retExt( sessionInfoPtr, CRYPT_ERROR_UNDERFLOW,
						"SSH version string read timed out before all data "
						"could be read" );
			if( status == CRYPT_ERROR_TIMEOUT && linesRead > 0 )
				/* We timed out waiting for an ID to appear, this is an 
				   invalid ID error rather than a true timeout */
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid SSH version string 0x%02X 0x%02X 0x%02X "
						"0x%02X",
						sessionInfoPtr->receiveBuffer[ 0 ],
						sessionInfoPtr->receiveBuffer[ 1 ],
						sessionInfoPtr->receiveBuffer[ 2 ],
						sessionInfoPtr->receiveBuffer[ 3 ] );
			sNetGetErrorInfo( &sessionInfoPtr->stream,
							  sessionInfoPtr->errorMessage,
							  &sessionInfoPtr->errorCode );
			return( status );
			}
		linesRead++;
		}
	while( memcmp( sessionInfoPtr->receiveBuffer, SSH_ID, SSH_ID_SIZE ) );

	/* Determine which version we're talking to */
	if( *versionStringPtr == '1' )
		{
#ifdef USE_SSH2
		if( !memcmp( versionStringPtr, "1.99", 4 ) )
			/* SSHv2 server in backwards-compatibility mode */
			sessionInfoPtr->version = 2;
		else
#endif /* USE_SSH2 */
			{
#ifdef USE_SSH1
			/* If the caller has specifically asked for SSHv2 but all that
			   the server offers is SSHv1, we can't continue */
			if( sessionInfoPtr->version == 2 )
				retExt( sessionInfoPtr, CRYPT_ERROR_NOSECURE,
						"Server can only do SSHv1 when SSHv2 was requested" );
			sessionInfoPtr->version = 1;
#else
			retExt( sessionInfoPtr, CRYPT_ERROR_NOSECURE,
					"Server can only do SSHv1" );
#endif /* USE_SSH1 */
			}
		}
	else
#ifdef USE_SSH2
		if( *versionStringPtr == '2' )
			sessionInfoPtr->version = 2;
		else
#endif /* USE_SSH2 */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid SSH version %c",
					sessionInfoPtr->receiveBuffer[ 0 ] );

	/* Find the end of the protocol version substring.  If there's no
	   software version info present this isn't really correct, but no major
	   reason for bailing out, so we just exit normally */
	while( *versionStringPtr && *versionStringPtr != '-' )
		versionStringPtr++;
	if( !versionStringPtr[ 0 ] || !versionStringPtr[ 1 ] )
		return( CRYPT_OK );
	versionStringPtr++;		/* Skip '-' */

	/* Check whether the peer is using cryptlib */
	if( !memcmp( versionStringPtr, SSH1_ID_STRING + SSH_ID_SIZE + SSH_VERSION_SIZE,
				 strlen( SSH2_ID_STRING + SSH_ID_SIZE + SSH_VERSION_SIZE ) ) )
		sessionInfoPtr->flags |= SESSION_ISCRYPTLIB;

	/* Check for various servers that require special-case handling.  The
	   versions that we check for are:

		OpenSSH:
			Omits hashing the exchange hash length when creating the hash
			to be signed for client auth for version 2.0 (all subversions).

		ssh.com:
			This implementation puts the version number first, so if we find 
			something without a vendor name at the start we treat it as an 
			ssh.com version.  However, Van Dyke's SSH server VShell also 
			uses the ssh.com-style identification (fronti nulla fides), so 
			when we check for the ssh.com implementation we make sure that 
			it isn't really VShell.  In addition CuteFTP advertises whatever 
			it's using as "1.x" (without and vendor name), which is going to 
			cause problems in the future if they ever move to 2.x of 
			whatever it is.

			Omits the DH-derived shared secret when hashing the keying
			material for versions identified as "2.0.0" (all 
			sub-versions) and "2.0.10" .

			Uses an SSH2_FIXED_KEY_SIZE-sized key for HMAC instead of the de
			facto 160 bits for versions identified as "2.0.", "2.1 ", "2.1.",
			and "2.2." (i.e. all sub-versions of 2.0, 2.1, and 2.2), and
			specifically version "2.3.0".  This was fixed in 2.3.1.

			Omits the signature algorithm name for versions identified as 
			"2.0" and "2.1" (all sub-versions).

			Requires a window adjust for every 32K sent even if the window is
			advertised as being (effectively) infinite in size for versions 
			identified as "2.0" and "2.1" (all sub-versions).

			Omits hashing the exchange hash length when creating the hash
			to be signed for client auth for versions 2.1 and 2.2 (all 
			subversions).

			Dumps text diagnostics (that is, raw text strings rather than
			SSH error packets) onto the connection if something unexpected 
			occurs, for uncertain versions probably in the 2.x range.

		Van Dyke:
			Omits hashing the exchange hash length when creating the hash to 
			be signed for client auth for version 3.0 (SecureCRT = SSH) and 
			1.7 (SecureFX = SFTP).

	   Further quirks and peculiarities exist, but fortunately these are rare
	   enough (mostly for SSHv1) that we don't have to go out of our way to
	   handle them */
	if( !memcmp( versionStringPtr, "OpenSSH_", 8 ) )
		{
		const char *subVersionStringPtr = versionStringPtr + 8;

		if( !memcmp( subVersionStringPtr, "2.0", 3 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_NOHASHLENGTH;
		}
	if( *versionStringPtr == '2' && \
		strstr( versionStringPtr, "VShell" ) == NULL )
		{
		/* ssh.com 2.x versions have quite a number of bugs so we check for 
		   them as a group */
		if( !memcmp( versionStringPtr, "2.0.0", 5 ) || \
			!memcmp( versionStringPtr, "2.0.10", 6 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_NOHASHSECRET;
		if( !memcmp( versionStringPtr, "2.0", 3 ) || \
			!memcmp( versionStringPtr, "2.1", 3 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_SIGFORMAT;
		if( !memcmp( versionStringPtr, "2.0", 3 ) || \
			!memcmp( versionStringPtr, "2.1", 3 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_WINDOWBUG;
		if( !memcmp( versionStringPtr, "2.1", 3 ) || \
			!memcmp( versionStringPtr, "2.2", 3 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_NOHASHLENGTH;
		if( !memcmp( versionStringPtr, "2.0", 3 ) || \
			!memcmp( versionStringPtr, "2.1", 3 ) || \
			!memcmp( versionStringPtr, "2.2", 3 ) || \
			!memcmp( versionStringPtr, "2.3.0", 5 ) )
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_HMACKEYSIZE;
		if( !memcmp( versionStringPtr, "2.", 2 ) )
			/* Not sure of the exact versions where this occurs */
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_TEXTDIAGS;
		}
	if( !memcmp( versionStringPtr, "3.0 SecureCRT", 13 ) || \
		!memcmp( versionStringPtr, "1.7 SecureFX", 12 ) )
		sessionInfoPtr->protocolFlags |= SSH_PFLAG_NOHASHLENGTH;

	return( CRYPT_OK );
	}

/* Encode a value as an SSH string */

int encodeString( BYTE *buffer, const BYTE *string, const int stringLength )
	{
	BYTE *bufPtr = buffer;
	const int length = ( stringLength > 0 ) ? stringLength : strlen( string );

	if( buffer != NULL )
		{
		mputLong( bufPtr, length );
		memcpy( bufPtr, string, length );
		}
	return( LENGTH_SIZE + length );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Connect to an SSH server */

static int initVersion( SESSION_INFO *sessionInfoPtr,
						SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	/* Set up handshake function pointers based on the protocol version */
	status = readVersionString( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->version == 1 )
		{
		initSSH1processing( sessionInfoPtr, handshakeInfo,
							( sessionInfoPtr->flags & SESSION_ISSERVER) ? \
								TRUE : FALSE );
		return( CRYPT_OK );
		}
	initSSH2processing( sessionInfoPtr, handshakeInfo,
						( sessionInfoPtr->flags & SESSION_ISSERVER) ? \
							TRUE : FALSE );

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes, so if we're talking to an SSHv2 peer we create a context
	   for the hash */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		handshakeInfo->iExchangeHashcontext = createInfo.cryptHandle;
	return( status );
	}

static int completeStartup( SESSION_INFO *sessionInfoPtr )
	{
	SSH_HANDSHAKE_INFO handshakeInfo;
	int status;

	/* Initialise the handshake info and begin the handshake.  Since we don't
	   know what type of peer we're talking to and since the protocols aren't
	   compatible in anything but name, we have to peek at the peer's initial
	   communication and redirect function pointers based on that */
	status = initHandshakeInfo( &handshakeInfo );
	if( cryptStatusOK( status ) )
		status = initVersion( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusOK( status ) )
		status = handshakeInfo.beginHandshake( sessionInfoPtr,
											   &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		destroyHandshakeInfo( &handshakeInfo );
		sessionInfoPtr->shutdownFunction( sessionInfoPtr );
		return( status );
		}

	/* Exchange a key with the server */
	status = handshakeInfo.exchangeKeys( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		destroySecurityContexts( sessionInfoPtr );
		destroyHandshakeInfo( &handshakeInfo );
		sessionInfoPtr->shutdownFunction( sessionInfoPtr );
		return( status );
		}

	/* Complete the handshake */
	status = handshakeInfo.completeHandshake( sessionInfoPtr,
											  &handshakeInfo );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		/* At this point we could be in the secure state, so we have to
		   keep the security info around until after we've called the 
		   shutdown function, which could require sending secured data */
		sessionInfoPtr->shutdownFunction( sessionInfoPtr );
		destroySecurityContexts( sessionInfoPtr );
		return( status );
		}
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HANDSHAKETIMEOUT, NULL, 0 );

	return( status );
	}

/* Start an SSH server */

static int serverStartup( SESSION_INFO *sessionInfoPtr )
	{
	const char *idString = ( sessionInfoPtr->version == 1 ) ? \
						   SSH1_ID_STRING "\n" : SSH2_ID_STRING "\r\n";
	int status;

	/* Send the ID string to the client before we continue with the
	   handshake.  We don't have to wait for any input from the client since
	   we know that if we got here there's a client listening.  Note that
	   standard cryptlib practice for sessions is to wait for input from the
	   client, make sure that it looks reasonable, and only then send back a
	   reply of any kind.  If anything that doesn't look right arrives, we
	   close the connection immediately without any response.  Unfortunately
	   this isn't possible with SSH, which requires that the server send data
	   before the client does */
	status = swrite( &sessionInfoPtr->stream, idString, strlen( idString ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the handshake in the shared code */
	return( completeStartup( sessionInfoPtr ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

static int getAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 void *data, const CRYPT_ATTRIBUTE_TYPE type )
	{
	RESOURCE_DATA *msgData = data;

	assert( type == CRYPT_SESSINFO_SSH_SUBSYSTEM || \
			type == CRYPT_SESSINFO_SSH_PORTFORWARD );

	switch( type )
		{
		case CRYPT_SESSINFO_SSH_SUBSYSTEM:
			if( sessionInfoPtr->sshSubsystemLength <= 0 )
				return( CRYPT_ERROR_NOTINITED );
			return( attributeCopy( msgData, sessionInfoPtr->sshSubsystem,
								   sessionInfoPtr->sshSubsystemLength ) );

		case CRYPT_SESSINFO_SSH_PORTFORWARD:
			if( sessionInfoPtr->sshPortForwardLength <= 0 )
				return( CRYPT_ERROR_NOTINITED );
			return( attributeCopy( msgData, sessionInfoPtr->sshPortForward,
								   sessionInfoPtr->sshPortForwardLength ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ARGERROR_NUM1 );
	}

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	const RESOURCE_DATA *msgData = data;

	assert( type == CRYPT_SESSINFO_SSH_SUBSYSTEM || \
			type == CRYPT_SESSINFO_SSH_PORTFORWARD );

	switch( type )
		{
		case CRYPT_SESSINFO_SSH_SUBSYSTEM:
			if( sessionInfoPtr->sshSubsystemLength > 0 )
				return( CRYPT_ERROR_INITED );
			memcpy( sessionInfoPtr->sshSubsystem, msgData->data, 
					msgData->length );
			sessionInfoPtr->sshSubsystemLength = msgData->length;
			break;

		case CRYPT_SESSINFO_SSH_PORTFORWARD:
			{
			URL_INFO urlInfo;
			int status;

			/* Make sure that we've been given a valid URL for forwarding */
			if( sessionInfoPtr->sshPortForwardLength > 0 )
				return( CRYPT_ERROR_INITED );
			status = sNetParseURL( &urlInfo, msgData->data, 
								   msgData->length );
			if( cryptStatusError( status ) )
				return( status );
			memcpy( sessionInfoPtr->sshPortForward, msgData->data, 
					msgData->length );
			sessionInfoPtr->sshPortForwardLength = msgData->length;
			break;
			}

		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodSSH( SESSION_INFO *sessionInfoPtr )
	{
	/* Set the access method pointers.  Since the protocol version is
	   negotiable, we default to SSHv2, which is the one most commonly
	   used */
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		{
		sessionInfoPtr->transactFunction = serverStartup;
		initSSH2processing( sessionInfoPtr, NULL, TRUE );
		}
	else
		{
		sessionInfoPtr->transactFunction = completeStartup;
		initSSH2processing( sessionInfoPtr, NULL, FALSE );
		}

	return( CRYPT_OK );
	}
#endif /* USE_SSH1 || USE_SSH2 */
