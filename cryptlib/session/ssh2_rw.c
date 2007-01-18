/****************************************************************************
*																			*
*					cryptlib SSHv2 Session Read/Write Routines				*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Format a string sent by the peer as a cryptlib error message */

static void formatErrorString( SESSION_INFO *sessionInfoPtr, STREAM *stream,
							   const char *prefixString )
	{
	const int stringLen = strlen( prefixString );
	char *errorMessagePtr = sessionInfoPtr->errorMessage + stringLen;
	int length, status;

	/* Build the error message string from the prefix string and string
	   supplied by the peer */
	memcpy( sessionInfoPtr->errorMessage, prefixString, stringLen );
	status = readString32( stream, errorMessagePtr, &length,
						   MAX_ERRMSG_SIZE - ( stringLen + 16 ) );
	if( cryptStatusOK( status ) )
		{
		errorMessagePtr[ length ] = '\0';
		sanitiseString( errorMessagePtr, length );
		return;
		}

	/* There was an error with the peer-supplied string, insert a generic
	   placeholder */
	strcpy( errorMessagePtr, "<No details available>" );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Get the reason why the peer closed the connection */

int getDisconnectInfo( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	typedef struct {
		const int sshStatus, cryptlibStatus;
		} ERRORMAP_INFO;
	static const ERRORMAP_INFO FAR_BSS errorMap[] = {
		/* A mapping of SSH error codes that have cryptlib equivalents to
		   the equivalent cryptlib codes.  If there's no mapping available,
		   we use a default of CRYPT_ERROR_READ */
		{ SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, CRYPT_ERROR_PERMISSION },
		{ SSH2_DISCONNECT_MAC_ERROR, CRYPT_ERROR_SIGNATURE },
		{ SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, CRYPT_ERROR_WRONGKEY },
		{ CRYPT_ERROR, CRYPT_ERROR_READ },
		{ CRYPT_ERROR, CRYPT_ERROR_READ }
		};
	int errorCode, i;

	/* Peer is disconnecting, find out why:

	  [	byte	SSH2_MSG_DISCONNECT ]
		uint32	reason
		string	description
		string	language_tag */
	errorCode = readUint32( stream );
	if( cryptStatusError( errorCode ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid status information in disconnect message" );
	sessionInfoPtr->errorCode = errorCode;
	formatErrorString( sessionInfoPtr, stream,
					   "Received disconnect message: " );

	/* Try and map the SSH status to an equivalent cryptlib one */
	for( i = 0; errorMap[ i ].sshStatus != CRYPT_ERROR && \
				i < FAILSAFE_ARRAYSIZE( errorMap, ERRORMAP_INFO ); i++ )
		{
		if( errorMap[ i ].sshStatus == sessionInfoPtr->errorCode )
			break;
		}
	if( i >= FAILSAFE_ARRAYSIZE( errorMap, ERRORMAP_INFO ) )
		retIntError();
	return( errorMap[ i ].cryptlibStatus );
	}

/* Read, decrypt if necessary, and check the start of a packet header */

int readPacketHeaderSSH2( SESSION_INFO *sessionInfoPtr,
						  const int expectedType, long *packetLength,
						  int *packetExtraLength,
						  READSTATE_INFO *readInfo )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos, *lengthPtr = bufPtr;
	const BOOLEAN isHandshake = ( readInfo == NULL ) ? TRUE : FALSE;
	long length;
	int extraLength = 0, status;

	/* Clear return values */
	*packetLength = 0;
	*packetExtraLength = 0;

	/* SSHv2 encrypts everything but the MAC (including the packet length)
	   so we need to speculatively read ahead for the minimum packet size
	   and decrypt that in order to figure out what to do.  Because of the
	   ad-hoc data handling that this requires, we use the direct memory
	   manipulation routines rather than the stream functions */
	status = readFixedHeader( sessionInfoPtr, MIN_PACKET_SIZE );
	if( cryptStatusError( status ) )
		{
		/* If it's something other than a read error or if we're past the
		   initial handshake phase, there's no special-case error handling
		   required and we're done */
		if( status != CRYPT_ERROR_READ || !isHandshake )
			return( status );

		assert( isHandshake );

		/* Some servers just close the connection in response to a bad
		   password rather than returning an error, if it looks like this
		   has occurred we return a more informative error than the low-
		   level networking one */
		if( !isServer( sessionInfoPtr ) && \
			( expectedType == SSH2_MSG_SPECIAL_USERAUTH || \
			  expectedType == SSH2_MSG_SPECIAL_USERAUTH_PAM ) )
			retExt( sessionInfoPtr, status,
					"Remote server has closed the connection, possibly in "
					"response to an incorrect password" );

		/* Some versions of CuteFTP simply drop the connection with no
		   diagnostics or error information when they get the phase 2 keyex
		   packet, the best that we can do is tell the user to hassle the
		   CuteFTP vendor about this */
		if( isServer( sessionInfoPtr ) && \
			( sessionInfoPtr->protocolFlags & SSH_PFLAG_CUTEFTP ) && \
			expectedType == SSH2_MSG_NEWKEYS )
			retExt( sessionInfoPtr, status,
					"CuteFTP client has aborted the handshake due to a "
					"CuteFTP bug, please contact the CuteFTP vendor" );

		return( status );
		}

	/* If we're in the data-processing stage (i.e. it's a post-handshake
	   data packet read), exception conditions need to be handled specially
	   if they occur */
	if( !isHandshake )
		{
		/* If we didn't get anything, let the caller know */
		if( status == 0 )
			return( OK_SPECIAL );

		/* Since data errors are always fatal, when we're in the data-
		   processing stage we make all errors fatal until we've finished
		   handling the header */
		*readInfo = READINFO_FATAL;
		}

	/* Versions of SSH derived from the original SSH code base can sometimes
	   dump raw text strings (that is, strings not encapsulated in SSH
	   packets such as error packets) onto the connection if something
	   unexpected occurs.  Normally this would result in a bad data or MAC
	   error since they decrypt to garbage, so we try and catch them here */
	assert( status == MIN_PACKET_SIZE );
	if( isHandshake && \
		( sessionInfoPtr->protocolFlags & SSH_PFLAG_TEXTDIAGS ) && \
		bufPtr [ 0 ] == 'F' && ( !memcmp( bufPtr , "FATAL: ", 7 ) || \
								 !memcmp( bufPtr , "FATAL ERROR:", 12 ) ) )
		{
		BYTE *dataStartPtr = bufPtr + MIN_PACKET_SIZE;
		const int maxLength = \
			min( MAX_ERRMSG_SIZE - ( MIN_PACKET_SIZE + 128 ),
				 sessionInfoPtr->receiveBufSize - \
					( sessionInfoPtr->receiveBufPos + MIN_PACKET_SIZE + 128 ) );

		/* Read the rest of the error message */
		for( length = 0; length < maxLength; length++ )
			{
			status = sread( &sessionInfoPtr->stream,
							dataStartPtr + length, 1 );
			if( cryptStatusError( status ) || \
				dataStartPtr[ length ] == '\n' )
				break;
			}
		while( length > 0 && \
			   ( dataStartPtr[ length - 1 ] == '\r' || \
			     dataStartPtr[ length - 1 ] == '\n' ) )
			length--;
		dataStartPtr[ length ] = '\0';

		/* Report the error as a problem with the remote software.  Since
		   the other side has bailed out, we mark the channel as closed to
		   prevent any attempt to perform a proper shutdown */
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Remote SSH software has crashed, diagnostic was '%s'",
				sanitiseString( bufPtr, MIN_PACKET_SIZE + length ) );
		}

	/* Decrypt the header if necessary */
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_CTX_DECRYPT, bufPtr,
								  MIN_PACKET_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the packet header.  The dual minimum-length checks actually
	   simplify to the following:

		Non-secure mode: length < SSH2_HEADER_REMAINDER_SIZE (extraLength = 0).
			In this case there's no MAC being used, so all that we need to
			guarantee is that the packet is at least as long as the
			(remaining) data that we've already read.

		Secure mode: length < ID_SIZE + PADLENGTH_SIZE +
			SSH2_MIN_PADLENGTH_SIZE.  In this case there's an (implicit) MAC
			present so the packet (length + extraLength) will always be
			larger than the (remaining) data that we've already read.  For
			this case we need to check that the data payload is at least as
			long as the minimum-length packet */
	length = mgetLong( lengthPtr );
	assert( SSH2_HEADER_REMAINDER_SIZE == MIN_PACKET_SIZE - LENGTH_SIZE );
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		/* The MAC size isn't included in the packet length so we have to
		   add it manually */
		extraLength = sessionInfoPtr->authBlocksize;
	if( length + extraLength < SSH2_HEADER_REMAINDER_SIZE || \
		length < ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE || \
		length + extraLength >= sessionInfoPtr->receiveBufSize )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length %ld, should be %d...%d", length,
				ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE,
				sessionInfoPtr->receiveBufSize - extraLength );
	memmove( bufPtr, lengthPtr, SSH2_HEADER_REMAINDER_SIZE );
	*packetLength = length;
	*packetExtraLength = extraLength;

	return( CRYPT_OK );
	}

/* Read an SSHv2 packet.  This function is only used during the handshake
   phase (the data transfer phase has its own read/write code) so we can
   perform some special-case handling based on this */

int readPacketSSH2( SESSION_INFO *sessionInfoPtr, int expectedType,
					const int minPacketSize )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	long length;
	int padLength = 0, packetType, iterationCount = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( expectedType >= SSH2_MSG_DISCONNECT && \
			expectedType <= SSH2_MSG_SPECIAL_REQUEST );
	assert( minPacketSize >= 1 && minPacketSize < 1024 );

	/* Alongside the expected packets the server can send us all sorts of
	   no-op messages, ranging from explicit no-ops (SSH2_MSG_IGNORE) through
	   to general chattiness (SSH2_MSG_DEBUG, SSH2_MSG_USERAUTH_BANNER).
	   Because we can receive any quantity of these at any time, we have to
	   run the receive code in a loop to strip them out */
	do
		{
		int extraLength;

		/* Read the SSHv2 packet header:

			uint32		length (excluding MAC size)
			byte		padLen
		  [	byte		type - checked but not removed ]
			byte[]		data
			byte[]		padding
			byte[]		MAC

		  The reason why the length and pad length precede the packet type
		  and other information is that these two fields are part of the
		  SSHv2 transport layer while the type and payload are seen as part
		  of the connection layer, although the different RFCs tend to mix
		  them up quite thoroughly */
		assert( sessionInfoPtr->receiveBufEnd == 0 );
		status = readPacketHeaderSSH2( sessionInfoPtr, expectedType, &length,
									   &extraLength, NULL );
		if( cryptStatusError( status ) )
			return( status );
		assert( length + extraLength >= SSH2_HEADER_REMAINDER_SIZE && \
				length + extraLength < sessionInfoPtr->receiveBufSize );

		/* Read the remainder of the message.  The change cipherspec message
		   has length 0 so we only perform the read if there's packet data
		   present */
		if( length + extraLength > SSH2_HEADER_REMAINDER_SIZE )
			{
			const long remainingLength = length + extraLength - \
										 SSH2_HEADER_REMAINDER_SIZE;

			/* Because this code is called conditionally, we can't make the
			   read part of the fixed-header read but have to do independent
			   handling of shortfalls due to read timeouts */
			status = sread( &sessionInfoPtr->stream,
							sessionInfoPtr->receiveBuffer + \
								SSH2_HEADER_REMAINDER_SIZE,
							remainingLength );
			if( cryptStatusError( status ) )
				{
				sNetGetErrorInfo( &sessionInfoPtr->stream,
								  sessionInfoPtr->errorMessage,
								  &sessionInfoPtr->errorCode );
				return( status );
				}
			if( status != remainingLength )
				retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
						"Timeout during handshake packet remainder read, "
						"only got %d of %ld bytes", status,
						remainingLength );
			}

		/* Decrypt and MAC the packet if required */
		if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
			{
			/* Decrypt the remainder of the packet except for the MAC.
			   Sometimes the payload can be zero-length, so we have to check
			   for this before we try the decrypt */
			if( length > SSH2_HEADER_REMAINDER_SIZE )
				{
				status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
										  IMESSAGE_CTX_DECRYPT,
										  sessionInfoPtr->receiveBuffer + \
											SSH2_HEADER_REMAINDER_SIZE,
										  length - SSH2_HEADER_REMAINDER_SIZE );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* MAC the decrypted payload */
			status = macPayload( sessionInfoPtr->iAuthInContext,
								 sshInfo->readSeqNo,
								 sessionInfoPtr->receiveBuffer, length, 0,
								 MAC_ALL, sessionInfoPtr->authBlocksize, TRUE );
			if( cryptStatusError( status ) )
				{
				/* If we're expecting a service control packet after a change
				   cipherspec packet and don't get it then it's more likely
				   that the problem is due to the wrong key being used than
				   data corruption, so we return a wrong key error instead
				   of bad data */
				if( expectedType == SSH2_MSG_SERVICE_REQUEST || \
					expectedType == SSH2_MSG_SERVICE_ACCEPT )
					retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
							"Bad message MAC for handshake packet type %d, "
							"length %ld, probably due to an incorrect key "
							"being used to generate the MAC",
							sessionInfoPtr->receiveBuffer[ 1 ], length );
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Bad message MAC for handshake packet type %d, "
						"length %ld", sessionInfoPtr->receiveBuffer[ 1 ],
						length );
				}
			}
		padLength = sessionInfoPtr->receiveBuffer[ 0 ];
		packetType = sessionInfoPtr->receiveBuffer[ 1 ];
		sshInfo->readSeqNo++;
		}
	while( ( packetType == SSH2_MSG_IGNORE || \
			 packetType == SSH2_MSG_DEBUG || \
			 packetType == SSH2_MSG_USERAUTH_BANNER ) && \
		   ( iterationCount++ < 20 ) );
	if( iterationCount >= 20 )
		/* We have to be a bit careful here in case this is a strange
		   implementation that sends large numbers of no-op packets as cover
		   traffic.  Complaining after 20 consecutive no-ops seems to be a
		   safe tradeoff between catching DoS's and handling cover traffic */
		retExt( sessionInfoPtr, CRYPT_ERROR_OVERFLOW,
				"Peer sent an excessive number of no-op packets, it may be "
				"stuck in a loop" );
	sshInfo->packetType = packetType;

	/* Adjust the length to account for the fixed-size fields, remember
	   where the data starts, and make sure that there's some payload
	   present (there should always be at least one byte, the packet type) */
	length -= PADLENGTH_SIZE + padLength;
	if( length < minPacketSize )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid length %ld for handshake packet type %d, should "
				"be at least %d", length, packetType, minPacketSize );

	/* Move the data down in the buffer to get rid of the header info.
	   This isn't as inefficient as it seems since it's only used for the
	   short handshake messages */
	memmove( sessionInfoPtr->receiveBuffer,
			 sessionInfoPtr->receiveBuffer + PADLENGTH_SIZE, length );

	/* If the other side has gone away, report the details */
	if( packetType == SSH2_MSG_DISCONNECT )
		{
		STREAM stream;

		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		assert( sPeek( &stream ) == SSH2_MSG_DISCONNECT );
		sgetc( &stream );		/* Skip packet type */
		status = getDisconnectInfo( sessionInfoPtr, &stream );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Make sure that we either got what we asked for or one of the allowed
	   special-case packets */
	switch( expectedType )
		{
		case SSH2_MSG_SPECIAL_USERAUTH:
			/* If we're reading a response to a user authentication message
			   then getting a failure response is valid (even if it's not
			   what we're expecting) since it's an indication that an
			   incorrect password was used rather than that there was some
			   general type of failure */
			expectedType = ( packetType == SSH2_MSG_USERAUTH_FAILURE ) ? \
								SSH2_MSG_USERAUTH_FAILURE : \
								SSH2_MSG_USERAUTH_SUCCESS;
			break;

		case SSH2_MSG_SPECIAL_USERAUTH_PAM:
			/* PAM authentication can go through multiple iterations of back-
			   and-forth negotiation, for this case an info-request is also
			   a valid response, otherwise the responses are as for
			   SSH2_MSG_SPECIAL_USERAUTH */
			expectedType = ( packetType == SSH2_MSG_USERAUTH_INFO_REQUEST ) ? \
								SSH2_MSG_USERAUTH_INFO_REQUEST : \
						   ( packetType == SSH2_MSG_USERAUTH_FAILURE ) ? \
								SSH2_MSG_USERAUTH_FAILURE : \
								SSH2_MSG_USERAUTH_SUCCESS;
			break;

		case SSH2_MSG_SPECIAL_CHANNEL:
			/* If we're reading a response to a channel open message then
			   getting a failure response is valid (even if it's not what
			   we're expecting) since it's an indication that the channel
			   open (for example a port-forwarding operation) failed rather
			   than that there was some general type of failure */
			expectedType = ( packetType == SSH2_MSG_CHANNEL_OPEN_FAILURE ) ? \
								SSH2_MSG_CHANNEL_OPEN_FAILURE : \
								SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;
			break;

		case SSH2_MSG_SPECIAL_REQUEST:
			/* If we're at the end of the handshake phase we can get either
			   a global or a channel request to tell us what to do next */
			if( packetType != SSH2_MSG_GLOBAL_REQUEST && \
				packetType != SSH2_MSG_CHANNEL_REQUEST )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid handshake packet type %d, expected global "
						"or channel request", packetType );
			expectedType = packetType;
			break;

		case SSH2_MSG_KEXDH_GEX_REQUEST_OLD:
			/* The ephemeral DH key exchange spec was changed halfway
			   through to try and work around problems with key negotiation,
			   because of this we can see two different types of ephemeral
			   DH request, although they're functionally identical */
			if( packetType == SSH2_MSG_KEXDH_GEX_REQUEST_NEW )
				expectedType = packetType;
			break;
		}
	if( packetType != expectedType )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid handshake packet type %d, expected %d", packetType,
				expectedType );

	return( length );
	}

/****************************************************************************
*																			*
*								Write/Wrap a Packet							*
*																			*
****************************************************************************/

/* Open a stream to write an SSH2 packet or continue an existing stream to
   write further packets.  This opens the stream (if it's an open), skips
   the storage for the packet header, and writes the packet type */

void openPacketStreamSSH( STREAM *stream, const SESSION_INFO *sessionInfoPtr,
						  const int bufferSize, const int packetType )
	{
	const int streamSize = ( bufferSize == CRYPT_USE_DEFAULT ) ? \
						   sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE : \
						   bufferSize + SSH2_HEADER_SIZE;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( sessionInfoPtr->sendBuffer, streamSize ) );
	assert( streamSize > SSH2_HEADER_SIZE );

	sMemOpen( stream, sessionInfoPtr->sendBuffer, streamSize );
	swrite( stream, "\x00\x00\x00\x00\x00", SSH2_HEADER_SIZE );
	sputc( stream, packetType );
	}

int continuePacketStreamSSH( STREAM *stream, const int packetType )
	{
	const int packetOffset = stell( stream );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stell( stream ) == 0 || stell( stream ) > SSH2_HEADER_SIZE + 1 );

	swrite( stream, "\x00\x00\x00\x00\x00", SSH2_HEADER_SIZE );
	sputc( stream, packetType );
	return( packetOffset );
	}

/* Send an SSHv2 packet.  During the handshake phase we may be sending
   multiple packets at once, however unlike SSL, SSH requires that each
   packet in a multi-packet group be individually gift-wrapped so we have to
   provide a facility for separately wrapping and sending packets to handle
   this */

int wrapPacketSSH2( SESSION_INFO *sessionInfoPtr, STREAM *stream,
					const int offset )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const int length = stell( stream ) - offset;
	const int payloadLength = length - SSH2_HEADER_SIZE;
	const int padBlockSize = max( sessionInfoPtr->cryptBlocksize, 8 );
	BYTE *bufPtr = sMemBufPtr( stream ) - length;
	const BYTE *bufStartPtr = bufPtr;
	int padLength, extraLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( offset >= 0 );
	assert( length >= SSH2_HEADER_SIZE );
	assert( payloadLength >= 0 );

	/* Safety check to make sure that the stream is OK */
	if( !sStatusOK( stream ) )
		{
		assert( NOTREACHED );
		return( sGetStatus( stream ) );
		}

	/* Evaluate the number of padding bytes that we need to add to a packet
	   to make it a multiple of the cipher block size long, with a minimum
	   padding size of SSH2_MIN_PADLENGTH_SIZE bytes.  Note that this padding
	   is required even when there's no encryption being applied, although we
	   set the padding to all zeroes in this case */
	if( bufPtr[ LENGTH_SIZE + PADLENGTH_SIZE ] == SSH2_MSG_USERAUTH_REQUEST )
		{
		/* It's a user-authentication packet that (probably) contains a
		   password, make it fixed-length to hide the length information */
		for( padLength = 256;
			 ( length + SSH2_MIN_PADLENGTH_SIZE ) > padLength;
			 padLength += 256 );
		padLength -= length;
		}
	else
		padLength = roundUp( length + SSH2_MIN_PADLENGTH_SIZE,
							 padBlockSize ) - length;
	assert( padLength >= SSH2_MIN_PADLENGTH_SIZE && padLength < 256 );

	/* Make sure that there's enough room for the padding and MAC */
	extraLength = padLength + \
				  ( ( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE ) ? \
					sessionInfoPtr->authBlocksize : 0 );
	if( sMemDataLeft( stream ) < extraLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Add the SSH packet header:

		uint32		length (excluding MAC size)
		byte		padLen
		byte[]		data
		byte[]		padding
		byte[]		MAC

	   Because of the ad-hoc handling that this requires, we use the direct
	   memory manipulation routines rather than the stream functions */
	mputLong( bufPtr, ( long ) ( length - LENGTH_SIZE ) + padLength );
	*bufPtr++ = padLength;
	bufPtr += payloadLength;
	if( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE )
		{
		MESSAGE_DATA msgData;
		const int totalLength = SSH2_HEADER_SIZE + payloadLength + padLength;

		/* Append the padding */
		setMessageData( &msgData, bufPtr, padLength );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		assert( bufPtr + padLength == bufStartPtr + totalLength );

		/* MAC the data.  We skip the length value at the start since this
		   is computed by the MAC'ing code */
		status = macPayload( sessionInfoPtr->iAuthOutContext,
							 sshInfo->writeSeqNo, bufStartPtr + LENGTH_SIZE,
							 totalLength - LENGTH_SIZE, 0,
							 MAC_ALL, sessionInfoPtr->authBlocksize, FALSE );
		if( cryptStatusError( status ) )
			return( status );

		/* Encrypt the entire packet except for the MAC */
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_CTX_ENCRYPT, ( void * ) bufStartPtr,
								  totalLength );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* If there's no security in effect yet, the padding is all zeroes */
		memset( bufPtr, 0, padLength );
	sshInfo->writeSeqNo++;

	/* Sync the stream info to match the new payload size */
	return( sSkip( stream, extraLength ) );
	}

int sendPacketSSH2( SESSION_INFO *sessionInfoPtr, STREAM *stream,
					const BOOLEAN sendOnly )
	{
	int status;

	if( !sendOnly )
		{
		status = wrapPacketSSH2( sessionInfoPtr, stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = swrite( &sessionInfoPtr->stream,
					 sMemBufPtr( stream ) - stell( stream ),
					 stell( stream ) );
	if( cryptStatusError( status ) && \
		!( sessionInfoPtr->flags & SESSION_NOREPORTERROR ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	return( CRYPT_OK );	/* swrite() returns a byte count */
	}
#endif /* USE_SSH */
