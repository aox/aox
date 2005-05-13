/****************************************************************************
*																			*
*				cryptlib SSL v3/TLS Session Read/Write Routines				*
*					   Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Legacy SSLv2 Functions						*
*																			*
****************************************************************************/

/* Handle a legacy SSLv2 client hello:

	uint16	length code = { 0x80, len }
	byte	type = SSL_HAND_CLIENT_HELLO
	byte[2]	vers = { 0x03, 0x0n } */

static int handleSSLv2Header( SESSION_INFO *sessionInfoPtr, 
							  SSL_HANDSHAKE_INFO *handshakeInfo, 
							  const BYTE *bufPtr )
	{
	STREAM stream;
	int length, value, status;

	assert( bufPtr[ 0 ] == SSL_MSG_V2HANDSHAKE );

	/* Make sure that the length is in order.  Beyond the header we need at 
	   least the three 16-bit field lengths, one 24-bit cipher suite, and at 
	   least 16 bytes of nonce */
	bufPtr++;			/* Skip SSLv2 length ID, already checked by caller */
	length = *bufPtr++;
	if( length < ID_SIZE + VERSIONINFO_SIZE + \
				 ( UINT16_SIZE * 3 ) + 3 + 16 || \
		length > sessionInfoPtr->receiveBufSize )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid legacy SSLv2 hello packet length %d", length );

	/* Due to the different ordering of header fields in SSLv2, the type and 
	   version is regarded as part of the payload that needs to be 
	   hashed, rather than the header as for SSLv3 */
	sMemConnect( &stream, bufPtr, ID_SIZE + VERSIONINFO_SIZE );
	dualMacData( handshakeInfo, &stream, TRUE );
	value = sgetc( &stream );
	if( value != SSL_HAND_CLIENT_HELLO )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unexpected legacy SSLv2 packet type %d, should be %d", 
				value, SSL_HAND_CLIENT_HELLO );
		}
	status = processVersionInfo( sessionInfoPtr, &stream, 
								 &handshakeInfo->clientOfferedVersion );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	length -= stell( &stream );
	sMemDisconnect( &stream );

	/* Read the packet payload */
	status = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < length )
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
				"Timeout during legacy SSLv2 hello packet read, only got "
				"%d of %d bytes", status, length );
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = length;
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	dualMacData( handshakeInfo, &stream, TRUE );
	sMemDisconnect( &stream );

	/* SSLv2 puts the version info in the header, so we set the SSLv2 flag 
	   in the handshake info to ensure that it doesn't get confused with a 
	   normal SSL packet type */
	handshakeInfo->isSSLv2 = TRUE;

	return( length );
	}

/****************************************************************************
*																			*
*							Read Packet Utility Functions					*
*																			*
****************************************************************************/

/* Process version information */

int processVersionInfo( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						int *clientVersion )
	{
	int version;

	/* Clear return value */
	if( clientVersion != NULL )
		*clientVersion = CRYPT_ERROR;

	/* Check the major version number */
	version = sgetc( stream );
	if( version != SSL_MAJOR_VERSION )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid major version number %d, should be 3", version );

	/* Check the minor version number.  If we've already got the version
	   established, make sure that it matches the existing one, otherwise
	   determine which version we'll be using */
	version = sgetc( stream );
	if( clientVersion == NULL )
		{
		if( version != sessionInfoPtr->version )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid version number 3.%d, should be 3.%d", 
					version, sessionInfoPtr->version );
		return( CRYPT_OK );
		}
	switch( version )
		{
		case SSL_MINOR_VERSION_SSL:
			/* If the other side can't do TLS, fall back to SSL */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
				sessionInfoPtr->version = SSL_MINOR_VERSION_SSL;
			break;

		case SSL_MINOR_VERSION_TLS:
			/* If the other side can't do TLS 1.1, fall back to TLS 1.0 */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS;
			break;

		case SSL_MINOR_VERSION_TLS11:
			/* If the other side can't do post-TLS 1.1, fall back to 
			   TLS 1.1 */
			if( sessionInfoPtr->version > SSL_MINOR_VERSION_TLS11 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS11;
			break;

		default:
			/* If we're the server and the client has offered a vaguely 
			   sensible version, fall back to the highest version that we
			   support */
			if( ( sessionInfoPtr->flags && SESSION_ISSERVER ) && \
				version <= 5 )
				{
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS11;
				break;
				}

			/* It's nothing that we can handle */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid protocol version 3.%d", version );
		}

	*clientVersion = version;
	return( CRYPT_OK );
	}

/* Check that the header of an SSL packet is in order:

	byte	type
	byte[2]	vers = { 0x03, 0x0n }
	uint16	length
  [ byte[]	iv	- TLS 1.1 ]

  If this is the initial hello packet we request a dummy version info read 
  since the peer's version isn't known yet at this point.  The actual 
  version info is taken from the hello packet data, not from the SSL 
  wrapper */

static int checkPacketHeader( SESSION_INFO *sessionInfoPtr, STREAM *stream,
							  const int packetType, const int minLength )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	const int expectedPacketType = \
					( packetType == SSL_MSG_FIRST_HANDSHAKE ) ? \
					SSL_MSG_HANDSHAKE : packetType;
	int value, status;

	/* Check the packet type */
	value = sgetc( stream );
	if( value != expectedPacketType )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unexpected packet type %d, expected %d", 
				value, expectedPacketType );
	status = processVersionInfo( sessionInfoPtr, stream, 
				( packetType == SSL_MSG_FIRST_HANDSHAKE ) ? &value : NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the packet length */
	value = readUint16( stream );
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		if( value < sslInfo->ivSize + minLength + \
					sessionInfoPtr->authBlocksize || \
			value > sslInfo->ivSize + MAX_PACKET_SIZE + \
					sessionInfoPtr->authBlocksize + 256 || \
			value > sessionInfoPtr->receiveBufSize )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		if( value < minLength || value > MAX_PACKET_SIZE || \
			value > sessionInfoPtr->receiveBufSize )
			status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length %d for packet type %d", 
				value, packetType );

	/* Load the TLS 1.1 explicit IV if necessary */
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_READ ) && \
		sslInfo->ivSize > 0 )
		{
		const int offset = stell( stream );

		status = loadExplicitIV( sessionInfoPtr, stream );
		value -= stell( stream ) - offset;
		}

	return( value );
	}

/* Check that the header of an SSL packet and SSL handshake packet is in 
   order */

int checkPacketHeaderSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	return( checkPacketHeader( sessionInfoPtr, stream, 
							   SSL_MSG_APPLICATION_DATA, 0 ) );
	}

int checkHSPacketHeader( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						 const int packetType, const int minSize )
	{
	int type, length;

	/*	byte		ID = type
		uint24		length */
	type = sgetc( stream );
	if( type != packetType )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid handshake packet type %d, expected %d", 
				type, packetType );
	length = readUint24( stream );
	if( length < minSize || length > MAX_PACKET_SIZE || \
		length > sMemDataLeft( stream ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid length %d for handshake packet type %d", 
				length, type );
	return( length );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Unwrap an SSL data packet:

				------				MAC'd
				==================  Encrypted
	[ hdr | IV | data | MAC | pad ]
			   +------------------+
			   |		|
			 buffer	 length 

   This decrypts and removes the padding, checks and removes the MAC, and
   returns the payload length.  Processing of the header and IV have already 
   been performed during the packet header read */

int unwrapPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
					 const int packetType )
	{
	const int totaLength = sMemDataLeft( stream );
	BYTE *bufPtr = sMemBufPtr( stream );
	BOOLEAN badDecrypt = FALSE;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( sessionInfoPtr->flags & SESSION_ISSECURE_READ );
	assert( stell( stream ) == 0 );
	assert( totaLength >= sessionInfoPtr->authBlocksize && \
			totaLength <= MAX_PACKET_SIZE + sessionInfoPtr->authBlocksize + \
						  256 );
	assert( isWritePtr( bufPtr, totaLength ) );

	/* Make sure that the length is a multiple of the block cipher size */
	if( sessionInfoPtr->cryptBlocksize > 1 && \
		( totaLength % sessionInfoPtr->cryptBlocksize ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid encrypted packet length %d relative to cipher "
				"block size %d for packet type %d", totaLength, 
				sessionInfoPtr->cryptBlocksize, packetType );

	/* Decrypt the packet in the buffer.  We allow zero-length blocks (once
	   the padding is stripped) because some versions of OpenSSL send these 
	   as a kludge to work around pre-TLS 1.1 chosen-IV attacks */
	length = decryptData( sessionInfoPtr, bufPtr, totaLength );
	if( cryptStatusError( length ) )
		{
		/* If there's a padding error, don't exit immediately but record 
		   that there was a problem for after we've done the MAC'ing.  
		   Delaying the error reporting until then helps prevent timing 
		   attacks of the kind described by Brice Canvel, Alain Hiltgen,
		   Serge Vaudenay, and Martin Vuagnoux in "Password Interception 
		   in a SSL/TLS Channel", Crypto'03, LNCS No.2729, p.583.  These 
		   are close to impossible in most cases because we delay sending 
		   the close notify over a much longer period than the MAC vs.non-
		   MAC time difference and because it requires repeatedly connecting
		   with a fixed-format secret such as a password at the same location
		   in the packet (which MS Outlook does however manage to do), but 
		   we take this step anyway just to be safe */
		if( length == CRYPT_ERROR_BADDATA )
			{
			badDecrypt = TRUE;
			length = totaLength;
			}
		else
			return( length );
		}
	length -= sessionInfoPtr->authBlocksize;
	if( length < 0 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet payload length %d for packet type %d", 
				length, packetType );

	/* MAC the decrypted data */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = macDataSSL( sessionInfoPtr, bufPtr, length, packetType, 
							 TRUE, badDecrypt );
	else
		status = macDataTLS( sessionInfoPtr, bufPtr, length, packetType, 
							 TRUE, badDecrypt );
	if( badDecrypt )
		/* Report the delayed decrypt error, held to this point to make 
		   timing attacks more difficult */
		return( CRYPT_ERROR_BADDATA );
	if( cryptStatusError( status ) )
		return( status );

	return( length );
	}

/* Read an SSL packet.  This function is only used during the handshake 
   phase (the data transfer phase has its own read/write code) so we can 
   perform some special-case handling based on this */

int readPacketSSL( SESSION_INFO *sessionInfoPtr,
				   SSL_HANDSHAKE_INFO *handshakeInfo, const int packetType )
	{
	STREAM stream;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	int length, status;

	/* Read and process the header.  We don't have to check for status == 0
	   (meaning no data was read) at this point since all reads during the
	   handshake phase are blocking reads */
	status = length = readFixedHeader( sessionInfoPtr, 
									   sessionInfoPtr->receiveBufStartOfs );
	if( status <= 0 )
		return( status );
	assert( status == sessionInfoPtr->receiveBufStartOfs );

	/* Check for an SSL alert message */
	if( bufPtr[ 0 ] == SSL_MSG_ALERT )
		return( processAlert( sessionInfoPtr, bufPtr, length ) );

	/* Decode and process the SSL packet header */
	if( packetType == SSL_MSG_FIRST_HANDSHAKE && \
		bufPtr[ 0 ] == SSL_MSG_V2HANDSHAKE )
		/* It's an SSLv2 handshake, handle it specially */
		return( handleSSLv2Header( sessionInfoPtr, handshakeInfo, bufPtr ) );
	sMemConnect( &stream, bufPtr, length );
	status = length = \
		checkPacketHeader( sessionInfoPtr, &stream, packetType, 
						   ( packetType == SSL_MSG_CHANGE_CIPHER_SPEC ) ? \
						   1 : MIN_PACKET_SIZE ); 
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the payload packet(s) */
	status = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < length )
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
				"Timed out reading packet data for packet type %d, only "
				"got %d of %d bytes", packetType, status, length );
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = length;
	if( handshakeInfo != NULL )
		{
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		dualMacData( handshakeInfo, &stream, TRUE );
		sMemDisconnect( &stream );
		}
	return( length );
	}

/* Read the next handshake stream packet */

int refreshHSStream( SESSION_INFO *sessionInfoPtr, 
					 SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	int length;

	/* If there's still data present in the stream, there's nothing left
	   to do */
	if( sMemDataLeft( stream ) > 0 )
		return( CRYPT_OK );

	/* Refill the stream */
	sMemDisconnect( stream );
	length = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_HANDSHAKE );
	if( cryptStatusError( length ) )
		return( length );
	assert( length > 0 );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );

	return( CRYPT_OK );
	}		

/****************************************************************************
*																			*
*							Write Packet Utility Functions					*
*																			*
****************************************************************************/

/* Open and complete an SSL packet */

static void openPacketStream( STREAM *stream, const SESSION_INFO *sessionInfoPtr, 
							  const int bufferSize, const BOOLEAN isNewStream, 
							  const int packetType )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isNewStream || stell( stream ) >= SSL_HEADER_SIZE );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Create the stream if necessary */
	if( isNewStream )
		{
		const int streamSize = ( bufferSize == CRYPT_USE_DEFAULT ) ? \
						sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE : \
						bufferSize + sessionInfoPtr->sendBufStartOfs;

		assert( isWritePtr( sessionInfoPtr->sendBuffer, streamSize ) );
		assert( streamSize >= sessionInfoPtr->sendBufStartOfs );

		sMemOpen( stream, sessionInfoPtr->sendBuffer, streamSize );
		}

	/* Write the packet header:

		byte		ID = packetType
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 0 (placeholder) 
	  [ byte[]		iv	- TLS 1.1 only ] */
	sputc( stream, packetType );
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	writeUint16( stream, 0 );		/* Placeholder */
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE ) && \
		sslInfo->ivSize > 0 )
		{
		RESOURCE_DATA msgData;
		BYTE iv[ CRYPT_MAX_IVSIZE ];

		setMessageData( &msgData, iv, sslInfo->ivSize );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		swrite( stream, iv, sslInfo->ivSize );
		}
	}

void openPacketStreamSSL( STREAM *stream, const SESSION_INFO *sessionInfoPtr, 
						  const int bufferSize, const int packetType )
	{
	openPacketStream( stream, sessionInfoPtr, bufferSize, TRUE, 
					  packetType );
	}

int continuePacketStreamSSL( STREAM *stream, 
							  const SESSION_INFO *sessionInfoPtr, 
							  const int packetType )
	{
	const int offset = stell( stream );

	openPacketStream( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, FALSE, 
					  packetType );
	return( offset );
	}

int completePacketStreamSSL( STREAM *stream, const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Update the length field at the start of the packet */
	sseek( stream, offset + ID_SIZE + VERSIONINFO_SIZE );
	status = writeUint16( stream, ( packetEndOffset - offset ) - \
								  SSL_HEADER_SIZE );
	sseek( stream, packetEndOffset );
	return( status );
	}

/* Start and complete a handshake packet within an SSL packet.  Since this
   continues an existing packet stream that's been opened using 
   openPacketStreamSSL(), it's denoted as continueXXX() rather than 
   openXXX() */

int continueHSPacketStream( STREAM *stream, const int packetType )
	{
	const int offset = stell( stream );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Write the handshake packet header:

		byte		ID = packetType
		uint24		len = 0 (placeholder) */
	sputc( stream, packetType );
	writeUint24( stream, 0 );
	return( offset );
	}

int completeHSPacketStream( STREAM *stream, const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( offset >= SSL_HEADER_SIZE );

	/* Update the length field at the start of the packet */
	sseek( stream, offset + ID_SIZE );
	status = writeUint24( stream, packetEndOffset - \
								  ( offset + ID_SIZE + LENGTH_SIZE ) );
	sseek( stream, packetEndOffset );
	return( status );
	}

/****************************************************************************
*																			*
*							Write/wrap a Packet								*
*																			*
****************************************************************************/

/* Wrap an SSL data packet:

				------				MAC'd
				==================  Encrypted

	[ hdr | IV | data | MAC | pad ]
	|		   +------+
	|			  |
   buffer		length 

   This MACs the data, adds the IV if necessary, pads and encrypts, and
   updates the header */

int wrapPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
				   const int offset )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	const int payloadLength = ( stell( stream ) - \
								sessionInfoPtr->sendBufStartOfs ) - offset;
	BYTE *bufPtr = sMemBufPtr( stream ) - payloadLength;
	BYTE *headerPtr = bufPtr - ( SSL_HEADER_SIZE + sslInfo->ivSize );
	int length;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE );
	assert( isWritePtr( bufPtr, payloadLength ) );
	assert( *headerPtr >= SSL_MSG_FIRST && *headerPtr <= SSL_MSG_LAST );

	/* Safety check to make sure that the stream is OK */
	if( !sStatusOK( stream ) )
		{
		assert( NOTREACHED );
		return( sGetStatus( stream ) );
		}

	/* MAC the payload */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		length = macDataSSL( sessionInfoPtr, bufPtr, payloadLength, 
							 *headerPtr, FALSE, FALSE );
	else
		length = macDataTLS( sessionInfoPtr, bufPtr, payloadLength, 
							 *headerPtr, FALSE, FALSE );
	if( cryptStatusError( length ) )
		return( length );

	/* If it's TLS 1.1 or newer and we're using a block cipher, adjust for 
	   the explicit IV that precedes the data */
	if( sslInfo->ivSize > 0 )
		{
		assert( sessionInfoPtr->sendBufStartOfs >= \
				SSL_HEADER_SIZE + sslInfo->ivSize ); 

		bufPtr -= sslInfo->ivSize;
		length += sslInfo->ivSize;
		}

	/* Encrypt the payload */
	length = encryptData( sessionInfoPtr, bufPtr, length );
	if( cryptStatusError( length ) )
		return( length );

	/* Insert the final packet payload length into the packet header.  We do
	   this both for convenience and because the stream may have been opened
	   in read-only mode if we're using it to write pre-assembled packet
	   data that's been passed in by the caller */
	headerPtr += ID_SIZE + VERSIONINFO_SIZE;
	mputWord( headerPtr, length );

	/* Sync the stream info to match the new payload size */
	return( sSkip( stream, length - ( sslInfo->ivSize + payloadLength ) ) );
	}

/* Wrap up and send an SSL packet */

int sendPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream,
				   const BOOLEAN sendOnly )
	{
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( stell( stream ) >= SSL_HEADER_SIZE );

	/* Safety check to make sure that the stream is OK */
	if( !sStatusOK( stream ) )
		{
		assert( NOTREACHED );
		return( sGetStatus( stream ) );
		}

	/* Update the length field at the start of the packet if necessary */
	if( !sendOnly )
		completePacketStreamSSL( stream, 0 );

	/* Send the packet to the peer */
	status = swrite( &sessionInfoPtr->stream, 
					 sMemBufPtr( stream ) - stell( stream ), 
					 stell( stream ) );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	return( CRYPT_OK );	/* swrite() returns a byte count */
	}

/****************************************************************************
*																			*
*							Send/Receive SSL Alerts							*
*																			*
****************************************************************************/

/* Process an alert packet.  IIS often just drops the connection rather than 
   sending an alert when it encounters a problem (although we try and work
   around some of the known problems, e.g. by sending a canary in the client
   hello to force IIS to at least send back something rather than just 
   dropping the connection, see ssl_cli.c), so when communicating with IIS 
   the only error indication we sometimes get will be a "Connection closed 
   by remote host" rather than an SSL-level error message.  In addition when 
   it encounters an unknown cert, MSIE will complete the handshake and then 
   close the connection (via a proper close alert in this case rather than 
   just closing the connection), wait while the user clicks OK several 
   times, and then restart the connection via an SSL resume.  Netscape in 
   contrast just hopes that the session won't time out while waiting for the 
   user to click OK.  As a result, cryptlib sees a closed connection and 
   aborts the session setup process, requiring a second call to the session 
   setup to continue with the resumed session */

int processAlert( SESSION_INFO *sessionInfoPtr, const void *header, 
				  const int headerLength )
	{
	const static struct {
		const int type;
		const char *message;
		const int cryptlibError;
		} alertInfo[] = {
		{ SSL_ALERT_CLOSE_NOTIFY, "Close notify", CRYPT_ERROR_COMPLETE },
		{ SSL_ALERT_UNEXPECTED_MESSAGE, "Unexpected message", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_BAD_RECORD_MAC, "Bad record MAC", CRYPT_ERROR_SIGNATURE },
		{ TLS_ALERT_DECRYPTION_FAILED, "Decryption failed", CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_RECORD_OVERFLOW, "Record overflow", CRYPT_ERROR_OVERFLOW },
		{ SSL_ALERT_DECOMPRESSION_FAILURE, "Decompression failure", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_HANDSHAKE_FAILURE, "Handshake failure", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_NO_CERTIFICATE, "No certificate", CRYPT_ERROR_PERMISSION },
		{ SSL_ALERT_BAD_CERTIFICATE, "Bad certificate", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_UNSUPPORTED_CERTIFICATE, "Unsupported certificate", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_REVOKED, "Certificate revoked", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_EXPIRED, "Certificate expired", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_UNKNOWN, "Certificate unknown", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_ILLEGAL_PARAMETER, "Illegal parameter", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNKNOWN_CA, "Unknown CA", CRYPT_ERROR_INVALID },
		{ TLS_ALERT_ACCESS_DENIED, "Access denied", CRYPT_ERROR_PERMISSION },
		{ TLS_ALERT_DECODE_ERROR, "Decode error", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_DECRYPT_ERROR, "Decrypt error", CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_EXPORT_RESTRICTION, "Export restriction", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_PROTOCOL_VERSION, "Protocol version", CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_INSUFFICIENT_SECURITY, "Insufficient security", CRYPT_ERROR_NOSECURE },
		{ TLS_ALERT_INTERNAL_ERROR, "Internal error", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_USER_CANCELLED, "User cancelled", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_NO_RENEGOTIATION, "No renegotiation", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNSUPPORTED_EXTENSION, "Unsupported extension", CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_CERTIFICATE_UNOBTAINABLE, "Certificate unobtainable", CRYPT_ERROR_NOTFOUND },
		{ TLS_ALERT_UNRECOGNIZED_NAME, "Unrecognized name", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, "Bad certificate status response", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE, "Bad certificate hash value", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNKNOWN_PSK_IDENTITY, "Unknown PSK identity", CRYPT_ERROR_NOTFOUND },
 		{ CRYPT_ERROR, NULL }
		};
	STREAM stream;
	BYTE buffer[ 256 + 8 ];
	int length, type, i, status;

	/* Process the alert packet header */
	sMemConnect( &stream, header, headerLength );
	status = length = checkPacketHeader( sessionInfoPtr, &stream, 
										 SSL_MSG_ALERT, ALERTINFO_SIZE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		if( length < ALERTINFO_SIZE || length > 256 )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		if( length != ALERTINFO_SIZE )
			status = CRYPT_ERROR_BADDATA;
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid alert message" );

	/* Read and process the alert packet */
	status = sread( &sessionInfoPtr->stream, buffer, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < length )
		{
		/* If we timed out before we could get all of the alert data, bail
		   out without trying to perform any further processing.  We're 
		   about to shut down the session anyway so there's no point in 
		   potentially stalling for ages trying to find a lost byte */
		sendCloseAlert( sessionInfoPtr, TRUE );
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT, 
				"Timed out reading alert message, only got %d of %d bytes", 
				status, length );
		}
	sessionInfoPtr->receiveBufEnd = length;
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_READ ) && \
		( length > ALERTINFO_SIZE || \
		  isStreamCipher( sessionInfoPtr->cryptAlgo ) ) )
		{
		/* We only try and decrypt if the alert info is big enough to be
		   encrypted, i.e. it contains the fixed-size data + padding.  This
		   situation can occur if there's an error moving from the non-
		   secure to the secure state.  However, if it's a stream cipher the 
		   ciphertext and plaintext are the same size so we always have to 
		   try the decryption */
		sMemConnect( &stream, buffer, length );
		status = unwrapPacketSSL( sessionInfoPtr, &stream, SSL_MSG_ALERT );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			{
			sendCloseAlert( sessionInfoPtr, TRUE );
			sessionInfoPtr->flags |= SESSION_SENDCLOSED;
			return( status );
			}
		}

	/* Tell the other side that we're going away */
	sendCloseAlert( sessionInfoPtr, TRUE );
	sessionInfoPtr->flags |= SESSION_SENDCLOSED;

	/* Process the alert info.  In theory we should also make the session 
	   non-resumable if the other side goes away without sending a close 
	   alert, but this leads to too many problems with non-resumable 
	   sessions if we do it.  For example many protocols do their own end-of-
	   data indication (e.g. "Connection: close" in HTTP and BYE in SMTP) 
	   and so don't bother with a close alert.  In other cases 
	   implementations just drop the connection without sending a close 
	   alert, carried over from many early Unix protocols that used a 
	   connection close to signify end-of-data, which has caused problems 
	   ever since for newer protocols that want to keep the connection open.  
	   Other implementations still send their alert but then immediately 
	   close the connection.  Because of this haphazard approach to closing 
	   connections, many implementations allow a session to be resumed even 
	   if no close alert is sent.  In order to be compatible with this 
	   behaviour, we do the same (thus perpetuating the problem).  If 
	   necessary this can be fixed by calling deleteSessionCacheEntry() if 
	   the connection is closed without a close alert having been sent */
	if( buffer[ 0 ] != SSL_ALERTLEVEL_WARNING && \
		buffer[ 0 ] != SSL_ALERTLEVEL_FATAL )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid alert message level %d", buffer[ 0 ] );
	sessionInfoPtr->errorCode = type = buffer[ 1 ];
	for( i = 0; alertInfo[ i ].type != CRYPT_ERROR && \
				alertInfo[ i ].type != type; i++ );
	if( alertInfo[ i ].type == CRYPT_ERROR )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unknown alert message type %d at alert level %d", 
				type, buffer[ 0 ] );
	strcpy( sessionInfoPtr->errorMessage,
			( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
				"Received SSL alert message: " : \
				"Received TLS alert message: " );
	strcat( sessionInfoPtr->errorMessage, alertInfo[ i ].message );
	return( alertInfo[ i ].cryptlibError );
	}

/* Send a close alert, with appropriate protection if necessary */

static void sendAlert( SESSION_INFO *sessionInfoPtr, 
					   const int alertLevel, const int alertType,
					   const BOOLEAN alertReceived )
	{
	STREAM stream;
	int length, status = CRYPT_OK;

	/* Make sure that we only send a single alert.  Normally we do this 
	   automatically on shutdown, but we may have already sent it earlier 
	   as part of an error-handler */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT )
		return;
	sessionInfoPtr->protocolFlags |= SSL_PFLAG_ALERTSENT;

	/* Create the alert.  We can't really do much with errors at this point, 
	   although we can throw an exception in the debug version to draw 
	   attention to the fact that there's a problem.  The one error type 
	   that we don't complain about is an access permission problem, which 
	   can occur when cryptlib is shutting down, for example when the 
	   current thread is blocked waiting for network traffic and another 
	   thread shuts cryptlib down */
	openPacketStreamSSL( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
						 SSL_MSG_ALERT );
	sputc( &stream, alertLevel );
	sputc( &stream, alertType );
	if( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE )
		{
		status = wrapPacketSSL( sessionInfoPtr, &stream, 0 );
		assert( status != CRYPT_ERROR_PERMISSION );
		}
	else
		completePacketStreamSSL( &stream, 0 );
	length = stell( &stream );
	sMemDisconnect( &stream );

	/* Send the alert */
	if( cryptStatusOK( status ) )
		status = sendCloseNotification( sessionInfoPtr, 
										sessionInfoPtr->sendBuffer, length );
	else
		status = sendCloseNotification( sessionInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) || alertReceived )
		return;

	/* Read back the other side's close alert acknowledgement */
	readPacketSSL( sessionInfoPtr, NULL, SSL_MSG_ALERT );
	}

void sendCloseAlert( SESSION_INFO *sessionInfoPtr, 
					 const BOOLEAN alertReceived )
	{
	sendAlert( sessionInfoPtr, SSL_ALERTLEVEL_WARNING, 
			   SSL_ALERT_CLOSE_NOTIFY, alertReceived );
	}

void sendHandshakeFailAlert( SESSION_INFO *sessionInfoPtr )
	{
	/* We set the alertReceived flag to true when sending a handshake
	   failure alert to avoid waiting to get back an ack, since this 
	   alert type isn't acknowledged by the other side */
	sendAlert( sessionInfoPtr, SSL_ALERTLEVEL_FATAL, 
			   SSL_ALERT_HANDSHAKE_FAILURE, TRUE );
	}
#endif /* USE_SSL */
