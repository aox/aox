/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Server Management					*
*					   Copyright Peter Gutmann 1998-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
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

/* Process an SSLv2 client hello:

	uint16		suiteLen
	uint16		sessIDlen
	uint16		nonceLen
	uint24[]	suites
	byte[]		sessID
	byte[]		nonce

   The v2 type and version have already been processed in readPacketSSL() 
   since this information, which is moved into the header in v3, is part of 
   the body in v2.  What's left for the v2 hello is the remainder of the 
   payload */

static int processHelloSSLv2( SESSION_INFO *sessionInfoPtr, 
							  SSL_HANDSHAKE_INFO *handshakeInfo, 
							  STREAM *stream, int *resumedSessionID )
	{
	int suiteLength, sessionIDlength, nonceLength, status;

	/* Clear return values */
	*resumedSessionID = 0;

	/* Read the SSLv2 hello */
	suiteLength = readUint16( stream );
	sessionIDlength = readUint16( stream );
	nonceLength = readUint16( stream );
	if( suiteLength < 3 || ( suiteLength % 3 ) != 0 || \
		sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE || \
		nonceLength < 16 || nonceLength > SSL_NONCE_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid legacy SSLv2 hello packet" );
	status = processCipherSuite( sessionInfoPtr, handshakeInfo, stream, 
								 suiteLength / 3 );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionIDlength > 0 )
		sSkip( stream, sessionIDlength );
	return( sread( stream, handshakeInfo->clientNonce + \
						   SSL_NONCE_SIZE - nonceLength, nonceLength ) );
	}

/****************************************************************************
*																			*
*							Server-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the client */

int beginServerHandshake( SESSION_INFO *sessionInfoPtr, 
						  SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	MESSAGE_DATA msgData;
	int length, resumedSessionID = 0, packetOffset, status;

	/* Read the hello packet from the client */
	length = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( length ) )
		return( length );

	/* Process the client hello.  Although this should be a v3 hello, 
	   Netscape always sends a v2 hello (even if SSLv2 is disabled) and
	   in any case both MSIE and Mozilla still have SSLv2 enabled by
	   default (!!) so we have to process both types */
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	if( handshakeInfo->isSSLv2 )
		status = processHelloSSLv2( sessionInfoPtr, handshakeInfo, 
									stream, &resumedSessionID );
	else
		status = processHelloSSL( sessionInfoPtr, handshakeInfo, stream, 
								  TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );

	/* Handle session resumption */
	if( status == OK_SPECIAL && \
		( resumedSessionID = \
			findScoreboardEntry( &sessionInfoPtr->sessionSSL->scoreboardInfo,
								 handshakeInfo->sessionID, 
								 handshakeInfo->sessionIDlength,
								 handshakeInfo->premasterSecret,
								 &handshakeInfo->premasterSecretSize ) ) != 0 )
		{
#if 0	/* Old PSK mechanism */
		/* It's a resumed session, if it's a fixed entry that was added 
		   manually store the session ID as the user name */
		if( resumedSessionID < 0 )
			{
			for( length = handshakeInfo->sessionIDlength; \
				 length > 0 && !handshakeInfo->sessionID[ length - 1 ];
				 length-- );	/* Strip zero-padding */
			updateSessionAttribute( &sessionInfoPtr->attributeList, 
									CRYPT_SESSINFO_USERNAME, 
									handshakeInfo->sessionID, length, 
									CRYPT_MAX_TEXTSIZE, ATTR_FLAG_NONE );
			resumedSessionID = -resumedSessionID;	/* Fix ID polarity */
			}
#endif /* 0 */
		}
	else
		{
		/* It's a new session or the session data has expired from the 
		   cache, generate a new session ID */
		setMessageData( &msgData, handshakeInfo->sessionID, SESSIONID_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->sessionIDlength = SESSIONID_SIZE;
		}

	/* Get the nonce that's used to randomise all crypto ops and set up the
	   server DH context if necessary */
	setMessageData( &msgData, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusOK( status ) && isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		status = initDHcontextSSL( &handshakeInfo->dhContext, NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the server hello, cert, optional cert request, and done packets:

		byte		ID = SSL_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Server nonce
		byte[28]	nonce			|
		byte		sessIDlen
		byte[]		sessID
		uint16		suite
		byte		copr = 0
		... */
	openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
						 SSL_MSG_HANDSHAKE );
	packetOffset = continueHSPacketStream( stream, SSL_HAND_SERVER_HELLO );
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	swrite( stream, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
	writeUint16( stream, handshakeInfo->cipherSuite ); 
	sputc( stream, 0 );	/* No compression */
#if 0	
	if( handshakeInfo->hasExtensions )
		{
		/* TLS extension code.  Since almost no clients/servers (except maybe 
		   some obscure bits of code embedded in cellphones) do this, we'll 
		   have to wait for something that implements it to come along so we 
		   can send back the appropriate response.  The RFC makes the rather 
		   optimistic assumption that implementations can handle the presence 
		   of unexpected data at the end of the hello packet, since  this is 
		   rarely the case we leave the following disabled by default so as 
		   not to confuse clients that leave some garbage at the end of their
		   client hello and suddenly get back an extension response from the
		   server */
		writeUint16( stream, ID_SIZE + UINT16_SIZE + 1 );
		writeUint16( stream, TLS_EXT_MAX_FRAGMENT_LENTH );
		writeUint16( stream, 1 );
		sputc( stream, 3 );
		}
#endif /* 0 */
	completeHSPacketStream( stream, packetOffset );

	/* If it's a resumed session, the server hello is followed immediately 
	   by the change cipherspec, which is sent by the shared handshake
	   completion code */
	if( resumedSessionID != 0 )
		{
		completePacketStreamSSL( stream, 0 );
		dualMacData( handshakeInfo, stream, FALSE );
		return( OK_SPECIAL );	/* Tell caller it's a resumed session */
		}

	/*	...
		(optional server cert chain)
		... */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		status = writeSSLCertChain( sessionInfoPtr, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/*	...			(optional server keyex)
		byte		ID = SSL_HAND_SERVER_KEYEXCHANGE
		uint24		len
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
		uint16		signatureLen
		byte[]		signature */
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;
		const void *keyData;
		int keyDataOffset;

		/* Perform phase 1 of the DH key agreement process */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}

		/* Write the DH key parameters and DH public value and sign them */
		packetOffset = \
			continueHSPacketStream( stream, SSL_HAND_SERVER_KEYEXCHANGE );
		keyData = sMemBufPtr( stream );
		keyDataOffset = stell( stream );
		status = exportAttributeToStream( stream, handshakeInfo->dhContext,
										  CRYPT_IATTRIBUTE_KEY_SSL );
		if( cryptStatusOK( status ) )
			{
			writeInteger16U( stream, keyAgreeParams.publicValue, 
							 keyAgreeParams.publicValueLen );
			status = createKeyexSignature( sessionInfoPtr, handshakeInfo,
										   stream, keyData, 
										   stell( stream ) - keyDataOffset );
			}
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		completeHSPacketStream( stream, packetOffset );
		}

	/*	...			(optional client cert request)
		byte		ID = SSL_HAND_SERVER_CERTREQUEST
		uint24		len
		byte		certTypeLen = 2
		byte[2]		certType = { 0x01, 0x02 } (RSA,DSA)
		uint16		caNameListLen = 4
		uint16		caNameLen = 2
		byte[]		caName = { 0x30, 0x00 }
		... */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		packetOffset = \
			continueHSPacketStream( stream, SSL_HAND_SERVER_CERTREQUEST );
		sputc( stream, 2 );	
		swrite( stream, "\x01\x02", 2 );
		writeUint16( stream, 4 );
		writeUint16( stream, 2 );
		swrite( stream, "\x30\x00", 2 );
		completeHSPacketStream( stream, packetOffset );
		}

	/*	...
		byte		ID = SSL_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	packetOffset = \
		continueHSPacketStream( stream, SSL_HAND_SERVER_HELLODONE );
	completeHSPacketStream( stream, packetOffset );

	/* Send the combined server packets to the client.  We perform the dual 
	   MAC'ing of the packets in between the network ops where it's 
	   effectively free */
	status = sendPacketSSL( sessionInfoPtr, stream, FALSE );
	dualMacData( handshakeInfo, stream, FALSE );
	sMemDisconnect( stream );
	return( status );
	}

/* Exchange keys with the client */

int exchangeServerKeys( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	int length, status;

	/* Read the response from the client and, if we're expecting a client 
	   cert, make sure that it's present */
	length = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_HANDSHAKE );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		MESSAGE_DATA msgData;
		BYTE certID[ KEYID_SIZE + 8 ];

		/* Process the client cert chain */
		status = readSSLCertChain( sessionInfoPtr, handshakeInfo,
								   stream, &sessionInfoPtr->iKeyexAuthContext, 
								   TRUE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Make sure that the client cert is present in our cert store.  
		   Since we've already got a copy of the cert, we only do a presence 
		   check rather than actually fetching the cert */
		setMessageData( &msgData, certID, KEYID_SIZE );
		status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( cryptStatusOK( status ) )
			{
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, certID, 
								   KEYID_SIZE, NULL, 0, 
								   KEYMGMT_FLAG_CHECK_ONLY );
			status = krnlSendMessage( sessionInfoPtr->cryptKeyset, 
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
										  KEYMGMT_ITEM_PUBLICKEY );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, CRYPT_ERROR_INVALID,
					"Client certificate is not trusted for client "
					"authentication" );
			}

		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the client key exchange packet:

		byte		ID = SSL_HAND_CLIENT_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		yLen
		byte[]		y
	   PSK:
		uint16		userIDLen
		byte[]		userID 
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */
	length = checkHSPacketHeader( sessionInfoPtr, stream, 
								  SSL_HAND_CLIENT_KEYEXCHANGE, 
								  UINT16_SIZE + 1 );
	if( cryptStatusError( length ) )
		{
		sMemDisconnect( stream );
		return( length );
		}
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;

		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = readInteger16U( stream, keyAgreeParams.publicValue,
								 &keyAgreeParams.publicValueLen,
								 bitsToBytes( MIN_PKCSIZE_BITS ),
								 CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid DH key agreement data" );
			}

		/* Perform phase 2 of the DH key agreement */
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}
	else
		if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
			{
			const ATTRIBUTE_LIST *attributeListPtr;
			BYTE userID[ CRYPT_MAX_TEXTSIZE + 8 ];

			/* Read the client user ID and make sure that it's a valid 
			   user.  Handling non-valid users is somewhat problematic,
			   we can either bail out immediately or invent a fake 
			   password for the (non-)user and continue with that.  The
			   problem with this is that it doesn't really help hide 
			   whether the user is valid or not because we're still 
			   vulnerable to a timing attack because it takes considerably 
			   longer to generate the fake password than it does to read a 
			   fixed password string from memory, so an attacker can tell 
			   from the timing whether the username is valid or not.  
			   Because of this we don't try and fake out the valid/invalid 
			   user name indication but just exit immediately if an invalid
			   name is found */
			length = readUint16( stream );
			if( length < 1 || length > CRYPT_MAX_TEXTSIZE || \
				cryptStatusError( sread( stream, userID, length ) ) )
				{
				sMemDisconnect( stream );
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid client user ID" );
				}
			attributeListPtr = \
				findSessionAttributeEx( sessionInfoPtr->attributeList,
										CRYPT_SESSINFO_USERNAME, userID, 
										length );
			if( attributeListPtr == NULL )
				{
				sMemDisconnect( stream );
				retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
						"Unknown user name '%s'", 
						sanitiseString( userID, length ) );
				}

			/* Select the attribute with the user ID and move on to the
			   associated password */
			sessionInfoPtr->attributeListCurrent = \
								( ATTRIBUTE_LIST * ) attributeListPtr;
			attributeListPtr = attributeListPtr->next;
			assert( attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );

			/* Create the shared premaster secret from the user password */
			status = createSharedPremasterSecret( \
									handshakeInfo->premasterSecret,
									&handshakeInfo->premasterSecretSize, 
									attributeListPtr );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				retExt( sessionInfoPtr, status, 
						"Couldn't create SSL master secret from shared "
						"secret/password value" );
				}
			}
		else
			{
			BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];

			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				{
				/* The original Netscape SSL implementation didn't provide a 
				   length for the encrypted key and everyone copied that so 
				   it became the de facto standard way to do it (Sic faciunt 
				   omnes.  The spec itself is ambiguous on the topic).  This 
				   was fixed in TLS (although the spec is still ambigous) so 
				   the encoding differs slightly between SSL and TLS */
				if( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
					length > CRYPT_MAX_PKCSIZE || \
					cryptStatusError( sread( stream, wrappedKey, length ) ) )
					status = CRYPT_ERROR_BADDATA;
				}
			else
				status = readInteger16U( stream, wrappedKey, &length, 
										 bitsToBytes( MIN_PKCSIZE_BITS ),
										 CRYPT_MAX_PKCSIZE );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid RSA encrypted key data" );
				}

			/* Decrypt the pre-master secret */
			status = unwrapPremasterSecret( sessionInfoPtr, handshakeInfo,
											wrappedKey, length );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			}

	/* If we're expecting a client cert, process the client cert verify */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Process the client cert verify packet:

			byte		ID = SSL_HAND_CLIENT_CERTVERIFY
			uint24		len
			byte[]		signature */
		length = checkHSPacketHeader( sessionInfoPtr, stream,
									  SSL_HAND_CLIENT_CERTVERIFY, 
									  bitsToBytes( MIN_PKCSIZE_BITS ) );
		if( cryptStatusError( length ) )
			{
			sMemDisconnect( stream );
			return( length );
			}
		status = checkCertVerify( sessionInfoPtr, handshakeInfo, stream, 
								  length );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	sMemDisconnect( stream );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSLserverProcessing( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	handshakeInfo->beginHandshake = beginServerHandshake;
	handshakeInfo->exchangeKeys = exchangeServerKeys;
	}
#endif /* USE_SSL */
