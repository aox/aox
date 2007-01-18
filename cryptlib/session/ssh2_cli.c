/****************************************************************************
*																			*
*						cryptlib SSHv2 Session Management					*
*						Copyright Peter Gutmann 1998-2004					*
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

/* Tables mapping SSHv2 algorithm names to cryptlib algorithm IDs, in
   preferred algorithm order.  There are two of these, one that favours
   password-based authentication and one that favours PKC-based
   authentication, depending on whether the user has specified a password
   or PKC as their authentication choice */

static const ALGO_STRING_INFO FAR_BSS algoStringUserauthentPWTbl[] = {
	{ "password", CRYPT_PSEUDOALGO_PASSWORD },
	{ "keyboard-interactive", CRYPT_PSEUDOALGO_PAM },
	{ "publickey", CRYPT_ALGO_RSA },
	{ NULL, CRYPT_ALGO_NONE }
	};
static const ALGO_STRING_INFO FAR_BSS algoStringUserauthentPKCTbl[] = {
	{ "publickey", CRYPT_ALGO_RSA },
	{ "password", CRYPT_PSEUDOALGO_PASSWORD },
	{ "keyboard-interactive", CRYPT_PSEUDOALGO_PAM },
	{ NULL, CRYPT_ALGO_NONE }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Generate/check an SSHv2 key fingerprint.  This is simply an MD5 hash of
   the server's key/certificate data */

static int processKeyFingerprint( SESSION_INFO *sessionInfoPtr,
								  const void *keyData,
								  const int keyDataLength )
	{
	HASHFUNCTION hashFunction;
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_FINGERPRINT );
	BYTE fingerPrint[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashSize;

	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
	hashFunction( NULL, fingerPrint, CRYPT_MAX_HASHSIZE, 
				  keyData, keyDataLength, HASH_ALL );
	if( attributeListPtr == NULL )
		/* Remember the value for the caller */
		return( addSessionAttribute( &sessionInfoPtr->attributeList,
									 CRYPT_SESSINFO_SERVER_FINGERPRINT,
									 fingerPrint, hashSize ) );

	/* In the unlikely event that the user has passed us a SHA-1 fingerprint
	   (which isn't allowed by the spec, but no doubt someone out there's
	   using it based on the fact that the SSH architecture draft suggests
	   an SHA-1 fingerprint while the SSH fingerprint draft requires an MD5
	   fingerprint), calculate that instead */
	if( attributeListPtr->valueLength == 20 )
		{
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( NULL, fingerPrint, CRYPT_MAX_HASHSIZE, 
					  keyData, keyDataLength, HASH_ALL );
		}

	/* There's an existing fingerprint value, make sure that it matches what
	   we just calculated */
	if( attributeListPtr->valueLength != hashSize || \
		memcmp( attributeListPtr->value, fingerPrint, hashSize ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
				"Server key fingerprint doesn't match requested "
				"fingerprint" );

	return( CRYPT_OK );
	}

/* Report specific details on an authentication failure to the caller */

static int processPamAuthentication( SESSION_INFO *sessionInfoPtr );	/* Fwd.dec for fn.*/

static int reportAuthFailure( SESSION_INFO *sessionInfoPtr,
							  const int length, const BOOLEAN isPamAuth )
	{
	STREAM stream;
	CRYPT_ALGO_TYPE authentAlgo;
	const BOOLEAN hasPassword = \
			( findSessionAttribute( sessionInfoPtr->attributeList,
								    CRYPT_SESSINFO_PASSWORD ) != NULL ) ? \
			TRUE : FALSE;
	int status;

	/* The authentication failed, pick apart the response to see if we can
	   return more meaningful error info:

		byte	type = SSH2_MSG_USERAUTH_FAILURE
		string	available_auth_types
		boolean	partial_success

	  We decode the response to favour password- or PKC-based
	  authentication depending on whether the user specified a password
	  or PKC as their authentication choice.

	  God knows how the partial_success flag is really meant to be applied
	  (there are a whole pile of odd conditions surrounding changed
	  passwords and similar issues), according to the spec it means that the
	  authentication was successful, however the packet type indicates that
	  the authentication failed and something else is needed.  This whole
	  section of the protocol winds up in an extremely complex state machine
	  with all sorts of special-case conditions, several of which require
	  manual intervention by the user.  It's easiest to not even try and
	  handle this stuff */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( &stream );		/* Skip packet type */
	status = readAlgoString( &stream, hasPassword ? \
								algoStringUserauthentPWTbl : \
								algoStringUserauthentPKCTbl,
							  &authentAlgo, FALSE, sessionInfoPtr );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		/* If the problem is due to lack of a compatible algorithm, make the
		   error message a bit more specific to tell the user that we got
		   through most of the handshake but failed at the authentication
		   stage */
		if( status == CRYPT_ERROR_NOTAVAIL )
			retExt( sessionInfoPtr, CRYPT_ERROR_NOTAVAIL,
					"Remote system supports neither password nor "
					"public-key authentication" );

		/* There was some other problem with the returned information, we
		   still report it as a failed-authentication error but leave the
		   extended error info in place to let the caller see what the
		   underlying cause was */
		return( CRYPT_ERROR_WRONGKEY );
		}

	/* SSH reports authentication failures in a somewhat bizarre way,
	   instead of saying "authentication failed" it returns a list of
	   allowed authentication methods, one of which may be the one that we
	   just used.  To figure out whether we used the wrong auth method or
	   the wrong auth value, we have to perform a complex decode and match
	   of the info in the returned packet with what we sent */
	if( !hasPassword )
		{
		/* If we used a PKC and the server wants a password, report the
		   error as a missing password */
		if( authentAlgo == CRYPT_PSEUDOALGO_PASSWORD || \
			authentAlgo == CRYPT_PSEUDOALGO_PAM )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
					"Server requested password authentication but only a "
					"public/private key was available" );
			}

		retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
				"Server reported: Invalid public-key authentication" );
		}

	/* If the server requested keyboard-interactive (== misnamed PAM)
	   authentication, try again using PAM authentication unless we've
	   already been called as a result of failed PAM authentication */
	if( authentAlgo == CRYPT_PSEUDOALGO_PAM && !isPamAuth )
		return( processPamAuthentication( sessionInfoPtr ) );

	/* If we used a password and the server wants a PKC, report the error
	   as a missing private key.  RSA in this case is a placeholder that
	   means "any public-key algorithm", it could just as well have been
	   DSA */
	if( authentAlgo == CRYPT_ALGO_RSA )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
				"Server requested public-key authentication but only a "
				"password was available" );
		}

	retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
			"Server reported: Invalid password" );
	}

/* Handle an ephemeral DH key exchange */

static int processDHE( SESSION_INFO *sessionInfoPtr,
					   SSH_HANDSHAKE_INFO *handshakeInfo,
					   STREAM *stream, KEYAGREE_PARAMS *keyAgreeParams )
	{
	const int offset = LENGTH_SIZE + sizeofString32( "ssh-dh", 6 );
	BYTE *keyexInfoPtr;
	int keyexInfoLength, length, packetOffset, status;

	/*	...
		byte	type = SSH2_MSG_KEXDH_GEX_REQUEST_OLD
		uint32	n = 1024 bits

	   There's an alternative format that allows the client to specify a
	   range of key sizes:

		byte	type = SSH2_MSG_KEXDH_GEX_REQUEST_NEW
		uint32	min = 1024 bits
		uint32	n = SSH2_DEFAULT_KEYSIZE (as bits)
		uint32	max = CRYPT_MAX_PKCSIZE (as bits)

	   but a number of implementations don't support this yet, with some
	   servers just dropping the connection without any error response if
	   they encounter the newer packet type */
#if 1
	packetOffset = continuePacketStreamSSH( stream,
											SSH2_MSG_KEXDH_GEX_REQUEST_OLD );
	streamBookmarkSet( stream, keyexInfoPtr, keyexInfoLength );
	writeUint32( stream, bytesToBits( SSH2_DEFAULT_KEYSIZE ) );
#else
	packetOffset = continuePacketStreamSSH( stream,
											SSH2_MSG_KEXDH_GEX_REQUEST_NEW );
	streamBookmarkSet( stream, keyexInfoPtr, keyexInfoLength );
	writeUint32( stream, 1024 );
	writeUint32( stream, bytesToBits( SSH2_DEFAULT_KEYSIZE ) );
	writeUint32( stream, bytesToBits( CRYPT_MAX_PKCSIZE ) );
#endif /* 1 */
	streamBookmarkComplete( stream, keyexInfoLength );
	status = wrapPacketSSH2( sessionInfoPtr, stream, packetOffset );
	if( cryptStatusOK( status ) )
		status = sendPacketSSH2( sessionInfoPtr, stream, TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Remember the encoded key size info for later when we generate the
	   exchange hash */
	memcpy( handshakeInfo->encodedReqKeySizes, keyexInfoPtr,
			keyexInfoLength );
	handshakeInfo->encodedReqKeySizesLength = keyexInfoLength;

	/* Process the ephemeral DH key:

		byte	type = SSH2_MSG_KEXDH_GEX_GROUP
		mpint	p
		mpint	g */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_KEXDH_GEX_GROUP,
					ID_SIZE + \
					sizeofString32( "", bitsToBytes( MIN_PKCSIZE_BITS ) ) + \
					sizeofString32( "", 1 ) );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( stream );		/* Skip packet type */
	streamBookmarkSet( stream, keyexInfoPtr, keyexInfoLength );
	readInteger32( stream, NULL, NULL, bitsToBytes( MIN_PKCSIZE_BITS ),
				   CRYPT_MAX_PKCSIZE );
	status = readInteger32( stream, NULL, NULL, 1, CRYPT_MAX_PKCSIZE );
	streamBookmarkComplete( stream, keyexInfoLength );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH ephemeral key data packet" );

	/* Since this phase of the key negotiation exchanges raw key components
	   rather than the standard SSH public-key format, we have to rewrite
	   the raw key components into a standard SSH key so that we can import
	   it:

			From:					To:

								string		[ key/certificate ]
									string	"ssh-dh"
			mpint	p				mpint	p
			mpint	g				mpint	g */
	memmove( keyexInfoPtr + offset, keyexInfoPtr, keyexInfoLength );
	sMemOpen( stream, keyexInfoPtr, offset );
	writeUint32( stream, ( offset - LENGTH_SIZE ) + keyexInfoLength );
	writeString32( stream, "ssh-dh", 0 );
	sMemDisconnect( stream );

	/* Destroy the existing static DH key, load the new one, and re-perform
	   phase 1 of the DH key agreement process */
	krnlSendNotifier( handshakeInfo->iServerCryptContext,
					  IMESSAGE_DECREFCOUNT );
	status = initDHcontextSSH( &handshakeInfo->iServerCryptContext,
							   &handshakeInfo->serverKeySize, keyexInfoPtr,
							   offset + keyexInfoLength,
							   CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		memset( keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_CTX_ENCRYPT, keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've already sent the client hello as part of the keyex negotiation
	   so there's no need to bundle it with the client keyex, reset the
	   start position in the send buffer */
	sMemOpen( stream, sessionInfoPtr->sendBuffer,
			  sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE );

	return( CRYPT_OK );
	}

/* Handle PAM authentication */

static int processPamAuthentication( SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	STREAM stream;
	int length, pamIteration, status;

	/* Send a user-auth request asking for PAM authentication:

		byte	type = SSH2_MSG_USERAUTH_REQUEST
		string	user_name
		string	service_name = "ssh-connection"
		string	method_name = "keyboard-interactive"
		string	language = ""
		string	sub_methods = "password"

	   The sub-methods are implementation-dependent and the spec suggests an
	   implementation strategy in which the server ignores them so
	   specifying anything here is mostly wishful thinking, but we ask for
	   password auth. anyway in case it helps */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_USERAUTH_REQUEST );
	writeString32( &stream, userNamePtr->value, userNamePtr->valueLength );
	writeString32( &stream, "ssh-connection", 0 );
	writeString32( &stream, "keyboard-interactive", 0 );
	writeUint32( &stream, 0 );		/* No language tag */
	if( sessionInfoPtr->protocolFlags & SSH_PFLAG_PAMPW )
		/* Some servers choke if we supply a sub-method hint for the
		   authentication */
		writeUint32( &stream, 0 );
	else
		writeString32( &stream, "password", 0 );
	status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Handle the PAM negotiation.  This can (in theory) go on indefinitely,
	   to avoid potential DoS problems we limit it to five iterations.  In
	   general we'll go for two iterations (or three for OpenSSH's empty-
	   message bug), so we shouldn't ever get to five */
	for( pamIteration = 0; pamIteration < 5; pamIteration++ )
		{
		BYTE nameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		BYTE promptBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		int nameLength, promptLength, noPrompts = -1, type;

		/* Read back the response to our last message.  Although the spec
		   requires that the server not respond with a SSH2_MSG_USERAUTH_-
		   FAILURE message if the request fails because of an invalid user
		   name (to prevent an attacker from being able to determine valid
		   user names by checking for error responses), some servers can
		   return a failure indication at this point so we have to allow for
		   a failure response as well as the expected SSH2_MSG_USERAUTH_-
		   INFO_REQUEST */
		status = length = readPacketSSH2( sessionInfoPtr,
										  SSH2_MSG_SPECIAL_USERAUTH_PAM,
										  ID_SIZE );
		if( cryptStatusError( status ) )
			return( status );

		/* See what we got.  If it's not a PAM info request, we're done */
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		type = sgetc( &stream );
		if( type != SSH2_MSG_USERAUTH_INFO_REQUEST )
			sMemDisconnect( &stream );

		/* If it's a success status, we're done */
		if( type == SSH2_MSG_USERAUTH_SUCCESS )
			return( CRYPT_OK );

		/* If the authentication failed, provide more specific details to
		   the caller */
		if( type == SSH2_MSG_USERAUTH_FAILURE )
			{
			/* If we failed on the first attempt (before we even tried to
			   send a password), it's probably because the user name is
			   invalid (or the server has the SSH_PFLAG_PAMPW bug).  Having
			   the server return a failure due to an invalid user name
			   shouldn't happen (see the comment above), but we handle it
			   just in case */
			if( pamIteration == 0 )
				{
				char userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];

				memcpy( userNameBuffer, userNamePtr->value,
						userNamePtr->valueLength );
				userNameBuffer[ userNamePtr->valueLength ] = '\0';
				retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
						"Server reported: Invalid user name '%s'",
						sanitiseString( userNameBuffer,
									    userNamePtr->valueLength ) );
				}

			/* It's a failure after we've tried to authenticate ourselves,
			   report the details to the caller */
			return( reportAuthFailure( sessionInfoPtr, length, TRUE ) );
			}

		/* Process the PAM user-auth request:

			byte	type = SSH2_MSG_USERAUTH_INFO_REQUEST
			string	name
			string	instruction
			string	language = {}
			int		num_prompts
				string	prompt[ n ]
				boolean	echo[ n ]

		   Exactly whose name is supplied or what the instruction field is
		   for is left unspecified by the RFC (and they may indeed be left
		   empty), so we just skip it.  Many implementations feel similarly
		   about this and leave the fields empty.

		   If the PAM authentication (from a previous iteration) fails or
		   succeeds, the server is supposed to send back a standard user-
		   auth success or failure status, but could also send another
		   SSH2_MSG_USERAUTH_INFO_REQUEST even if it contains no payload (an
		   OpenSSH bug), so we have to handle this as a special case */
		status = readString32( &stream, nameBuffer, &nameLength,
							   CRYPT_MAX_TEXTSIZE );	/* Name */
		if( cryptStatusOK( status ) )
			{
			nameBuffer[ nameLength ] = '\0';
			status = readUniversal32( &stream );		/* Instruction */
			}
		if( cryptStatusOK( status ) )
			status = readUniversal32( &stream );		/* Language */
		if( cryptStatusOK( status ) )
			{
			status = noPrompts = readUint32( &stream );	/* No.prompts */
			if( !cryptStatusError( status ) && noPrompts > 8 )
				/* Requesting more than a small number of prompts is 
				   suspicious */
				status = CRYPT_ERROR_BADDATA;
			}
		if( !cryptStatusError( status ) && noPrompts > 0 )
			{
			status = readString32( &stream, promptBuffer, &promptLength,
								   CRYPT_MAX_TEXTSIZE );
			if( cryptStatusOK( status ) )
				promptBuffer[ promptLength ] = '\0';
			}
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status,
					"Invalid PAM authentication request packet" );

		/* If we got a prompt, make sure that we're being asked for some
		   form of password authentication.  This assumes that the prompt
		   string begins with the word "password" (which always seems to be
		   the case), if this isn't the case then it may be necessary to do
		   a substring search */
		if( noPrompts > 0 && \
			( promptLength < 8 || \
			  strCompare( promptBuffer, "Password", 8 ) ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Server requested unknown PAM authentication type "
					"'%s'", ( nameLength > 0 ) ? \
						sanitiseString( nameBuffer, nameLength ) : \
						sanitiseString( promptBuffer, promptLength ) );

		/* Send back the PAM user-auth response:

			byte	type = SSH2_MSG_USERAUTH_INFO_RESPONSE
			int		num_responses = num_prompts
			string	response

		   What to do if there's more than one prompt is a bit tricky,
		   usually PAM is used as a form of (awkward) password
		   authentication and there's only a single prompt, if we ever
		   encounter a situation where there's more than one prompt, it's
		   probably a request to confirm the password, so we just send it
		   again for successive prompts */
		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
							 SSH2_MSG_USERAUTH_INFO_RESPONSE );
		writeUint32( &stream, noPrompts );
		while( noPrompts-- > 0 )
			writeString32( &stream, passwordPtr->value,
						   passwordPtr->valueLength );
		status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
			"Too many iterations of negotiation during PAM authentication" );
	}

/****************************************************************************
*																			*
*						Client-side Connect Functions						*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

static int beginClientHandshake( SESSION_INFO *sessionInfoPtr,
								 SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	KEYAGREE_PARAMS keyAgreeParams;
	STREAM stream;
	void *clientHelloPtr, *keyexPtr;
	int serverHelloLength, clientHelloLength, keyexLength;
	int packetOffset, status;

	/* The higher-level code has already read the server version info, send
	   back our own version info (SSHv2 sends a CR and LF as terminator,
	   but this isn't hashed) */
	status = swrite( &sessionInfoPtr->stream, SSH2_ID_STRING "\r\n",
					 strlen( SSH2_ID_STRING ) + 2 );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes, so we hash the ID strings (first our client string, then the
	   server string that we read previously) encoded as SSH string values */
	hashAsString( handshakeInfo->iExchangeHashcontext, SSH2_ID_STRING,
				  strlen( SSH2_ID_STRING ) );
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->receiveBuffer,
				  strlen( sessionInfoPtr->receiveBuffer ) );

	/* While we wait for the server to digest our version info and send
	   back its response, we can create the context with the DH key and
	   perform phase 1 of the DH key agreement process */
	status = initDHcontextSSH( &handshakeInfo->iServerCryptContext,
							   &handshakeInfo->serverKeySize, NULL, 0,
							   CRYPT_USE_DEFAULT );
	if( cryptStatusOK( status ) )
		{
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello */
	status = processHelloSSH( sessionInfoPtr, handshakeInfo,
							  &serverHelloLength, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the client hello and DH phase 1 keyex packet:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms = DH
		string		pubkey algorithms
		string		client_crypto algorithms
		string		server_crypto algorithms
		string		client_mac algorithms
		string		server_mac algorithms
		string		client_compression algorithms = "none"
		string		server_compression algorithms = "none"
		string		client_language = ""
		string		server_language = ""
		boolean		first_keyex_packet_follows = FALSE
		uint32		reserved = 0
		...

	   The SSH spec leaves the order in which things happen ambiguous, in
	   order to save a whole round trip it has provisions for both sides
	   shouting at each other and then a complex interlock process where
	   bits of the initial exchange can be discarded and retried if necessary.
	   This is ugly and error-prone, so what we do is wait for the server
	   hello (already done earlier), choose known-good algorithms, and then
	   send the client hello immediately followed by the client keyex.
	   Since we wait for the server to speak first, we can choose parameters
	   that are accepted the first time.  In theory this means that we can
	   set keyex_follows to true (since a correct keyex packet always
	   follows the hello), however because of the nondeterministic initial
	   exchange the spec requires that a (guessed) keyex be discarded by the
	   server if the hello doesn't match (even if the keyex does):

		svr: hello
		client: matched hello, keyex
		svr: (discard keyex)

	   To avoid this problem, we set keyex_follows to false to make it clear
	   to the server that the keyex is the real thing and shouldn't be
	   discarded */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_KEXINIT );
	streamBookmarkSetFullPacket( &stream, clientHelloPtr, clientHelloLength );
	exportVarsizeAttributeToStream( &stream, SYSTEM_OBJECT_HANDLE,
									CRYPT_IATTRIBUTE_RANDOM_NONCE,
									SSH2_COOKIE_SIZE );
	writeAlgoString( &stream,  ( handshakeInfo->requestedServerKeySize > 0 ) ? \
					 CRYPT_PSEUDOALGO_DHE : CRYPT_ALGO_DH );
	writeAlgoString( &stream, handshakeInfo->pubkeyAlgo );
	writeAlgoString( &stream, sessionInfoPtr->cryptAlgo );
	writeAlgoString( &stream, sessionInfoPtr->cryptAlgo );
	writeAlgoString( &stream, sessionInfoPtr->integrityAlgo );
	writeAlgoString( &stream, sessionInfoPtr->integrityAlgo );
	writeAlgoString( &stream, CRYPT_PSEUDOALGO_COPR );
	writeAlgoString( &stream, CRYPT_PSEUDOALGO_COPR );
	writeUint32( &stream, 0 );	/* No language tag */
	writeUint32( &stream, 0 );
	sputc( &stream, 0 );		/* Tell the server not to discard the packet */
	writeUint32( &stream, 0 );	/* Reserved */
	streamBookmarkComplete( &stream, clientHelloLength );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the client and server hello messages.  We have to do this now
	   (rather than deferring it until we're waiting on network traffic from
	   the server) because they may get overwritten by the keyex negotiation
	   data if we're using a non-builtin DH key value */
	hashAsString( handshakeInfo->iExchangeHashcontext, clientHelloPtr,
				  clientHelloLength );
	status = hashAsString( handshakeInfo->iExchangeHashcontext,
						   sessionInfoPtr->receiveBuffer, serverHelloLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using a non-builtin DH key value, request the keyex key from
	   the server.  This requires disconnecting and re-connecting the stream
	   since it exchanges further data with the server, so if there's an
	   error return we don't disconnect the stream before we exit */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		status = processDHE( sessionInfoPtr, handshakeInfo, &stream,
							 &keyAgreeParams );
		if( cryptStatusError( status ) )
			return( status );
		}

	/*	...
		byte	type = SSH2_MSG_KEXDH_INIT / SSH2_MSG_KEXDH_GEX_INIT
		mpint	y */
	packetOffset = continuePacketStreamSSH( &stream, \
						( handshakeInfo->requestedServerKeySize > 0 ) ? \
							SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT );
	streamBookmarkSet( &stream, keyexPtr, keyexLength );
	writeInteger32( &stream, keyAgreeParams.publicValue,
							 keyAgreeParams.publicValueLen );
	streamBookmarkComplete( &stream, keyexLength );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, packetOffset );
	if( cryptStatusOK( status ) )
		/* Send the whole mess to the server.  Since SSH, unlike SSL,
		   requires that each packet in a multi-packet group be wrapped as a
		   separate packet, we have to first assemble the packets via
		   wrapPacket() and then send them in a group via sendPacket() with
		   the send-only flag set */
		status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Save the MPI-encoded client DH keyex value for later, when we need to
	   hash it */
	memcpy( handshakeInfo->clientKeyexValue, keyexPtr, keyexLength );
	handshakeInfo->clientKeyexValueLength = keyexLength;

	/* Set up PKC info while we wait for the server to process our
	   response */
	setMessageCreateObjectInfo( &createInfo, handshakeInfo->pubkeyAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		sessionInfoPtr->iKeyexAuthContext = createInfo.cryptHandle;
	return( status );
	}

/* Exchange keys with the server */

static int exchangeClientKeys( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_ALGO_TYPE pubkeyAlgo;
	STREAM stream;
	MESSAGE_DATA msgData;
	void *keyPtr, *keyBlobPtr, *sigPtr;
	int keyLength, keyBlobLength, sigLength, length, status;

	/* Process the DH phase 2 keyex packet:

		byte		type = SSH2_MSG_KEXDH_REPLY / SSH2_MSG_KEXDH_GEX_REPLY
		string		[ server key/certificate ]
			string	"ssh-rsa"	"ssh-dss"
			mpint	e			p
			mpint	n			q
			mpint				g
			mpint				y
		mpint		y'
		string		[ signature of handshake data ]
			string	"ssh-rsa"	"ssh-dss"
			string	signature	signature

	   First, we read and hash the server key/certificate.  Since this is
	   already encoded as an SSH string, we can hash it directly */
	length = readPacketSSH2( sessionInfoPtr,
					( handshakeInfo->requestedServerKeySize > 0 ) ? \
					SSH2_MSG_KEXDH_GEX_REPLY : SSH2_MSG_KEXDH_REPLY,
					ID_SIZE + LENGTH_SIZE + sizeofString32( "", 6 ) + \
					sizeofString32( "", 1 ) + \
					sizeofString32( "", bitsToBytes( MIN_PKCSIZE_BITS ) ) + \
					sizeofString32( "", bitsToBytes( MIN_PKCSIZE_BITS ) ) + \
					LENGTH_SIZE + sizeofString32( "", 6 ) + 40 );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( &stream );		/* Skip packet type */
	streamBookmarkSet( &stream, keyPtr, keyLength );
	readUint32( &stream );	/* Server key data size */
	status = readAlgoString( &stream, handshakeInfo->algoStringPubkeyTbl,
							 &pubkeyAlgo, TRUE, sessionInfoPtr );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( pubkeyAlgo != handshakeInfo->pubkeyAlgo )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 public key algorithm %d, expected %d",
				pubkeyAlgo, handshakeInfo->pubkeyAlgo );
		}
	streamBookmarkSet( &stream, keyBlobPtr, keyBlobLength );
	if( pubkeyAlgo == CRYPT_ALGO_RSA )
		{
		/* RSA e, n */
		readInteger32( &stream, NULL, NULL, 1, CRYPT_MAX_PKCSIZE );
		status = readInteger32( &stream, NULL, NULL,
								bitsToBytes( MIN_PKCSIZE_BITS ),
								CRYPT_MAX_PKCSIZE );
		}
	else
		{
		/* DSA p, q, g, y */
		readInteger32( &stream, NULL, NULL, bitsToBytes( MIN_PKCSIZE_BITS ),
					   CRYPT_MAX_PKCSIZE );
		readInteger32( &stream, NULL, NULL, 1, CRYPT_MAX_PKCSIZE );
		readInteger32( &stream, NULL, NULL, 1, CRYPT_MAX_PKCSIZE );
		status = readInteger32( &stream, NULL, NULL,
								bitsToBytes( MIN_PKCSIZE_BITS ),
								CRYPT_MAX_PKCSIZE );
		}
	streamBookmarkComplete( &stream, keyBlobLength );
	streamBookmarkComplete( &stream, keyLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 packet" );
		}
	setMessageData( &msgData, keyPtr, keyLength );
	status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_SSH );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, cryptArgError( status ) ? \
				CRYPT_ERROR_BADDATA : status,
				"Invalid server key/certificate" );
		}
	status = krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							  IMESSAGE_CTX_HASH, keyPtr, keyLength );
	if( cryptStatusOK( status ) )
		/* The fingerprint is computed from the "key blob", which is
		   different from the server key.  The server key is the full key,
		   while the "key blob" is only the raw key components (e, n for
		   RSA, p, q, g, y for DSA).  Note that, as with the old PGP 2.x key
		   hash mechanism, this allows key spoofing (although it isn't quite
		   as bad as the PGP 2.x key fingerprint mechanism) since it doesn't
		   hash an indication of the key type or format */
		status = processKeyFingerprint( sessionInfoPtr,
										keyBlobPtr, keyBlobLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the server DH keyex value and complete the DH key agreement */
	status = readRawObject32( &stream, handshakeInfo->serverKeyexValue,
							  &handshakeInfo->serverKeyexValueLength,
							  sizeof( handshakeInfo->serverKeyexValue ) );
	if( cryptStatusError( status ) || \
		!isValidDHsize( handshakeInfo->clientKeyexValueLength,
						handshakeInfo->serverKeySize, LENGTH_SIZE ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 keyex value" );
		}
	status = completeKeyex( sessionInfoPtr, handshakeInfo, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Prepare to process the handshake packet signature */
	streamBookmarkSet( &stream, sigPtr, sigLength );
	status = readUint32( &stream );
	if( !cryptStatusError( status ) )
		status = sSkip( &stream, status );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 packet signature data" );
		}
	streamBookmarkComplete( &stream, sigLength );
	sMemDisconnect( &stream );

	/* Some implementations incorrectly format the signature packet,
	   omitting the algorithm name and signature blob length for DSA sigs
	   (that is, they just encode two 20-byte values instead of a properly-
	   formatted signature):

				Right							Wrong
		string		[ signature data ]		string	[ nothing ]
			string	"ssh-dss"
			string	signature						signature

	   If we're talking to one of these versions, we check to see whether
	   the packet is correctly formatted (that is, that it has the
	   algorithm-type string present as required) and if it isn't present
	   rewrite it into the correct form so that we can verify the signature.
	   This check requires that the signature format be one of the SSHv2
	   standard types, but since we can't (by definition) handle proprietary
	   formats this isn't a problem */
	if( ( sessionInfoPtr->protocolFlags & SSH_PFLAG_SIGFORMAT ) && \
		( pubkeyAlgo == CRYPT_ALGO_DSA ) && \
		( memcmp( ( BYTE * ) sigPtr + LENGTH_SIZE + LENGTH_SIZE,
				  "ssh-dss", 7 ) && \
		  memcmp( ( BYTE * ) sigPtr + LENGTH_SIZE + LENGTH_SIZE,
				  "x509v3-sign-dss", 15 ) && \
		  memcmp( ( BYTE * ) sigPtr + LENGTH_SIZE + LENGTH_SIZE,
				  "spki-sign-dss", 13 ) && \
		  memcmp( ( BYTE * ) sigPtr + LENGTH_SIZE + LENGTH_SIZE,
				  "pgp-sign-dss", 12 ) ) )
		{
		void *headerEndPtr;
		int headerSize;

		/* Rewrite the signature to fix up the overall length at the start and
		   insert the algorithm name and signature length */
		sMemOpen( &stream, sessionInfoPtr->receiveBuffer,
				  LENGTH_SIZE + sizeofString32( "ssh-dsa", 6 ) );
		writeUint32( &stream, sizeofString32( "ssh-dsa", 6 ) );
		writeAlgoString( &stream, CRYPT_ALGO_DSA );
		headerSize = stell( &stream );
		headerEndPtr = sMemBufPtr( &stream );
		sMemDisconnect( &stream );

		/* Move the signature data down so that it follows the newly-created
		   header */
		memmove( headerEndPtr, sigPtr, sigLength );

		/* The rewritten signature is now at the start of the buffer, update
		   the sig. pointer and size to accomodate the added header */
		sigPtr = sessionInfoPtr->receiveBuffer;
		sigLength += headerSize;
		}

	/* Finally, verify the server's signature on the exchange hash */
	status = iCryptCheckSignatureEx( sigPtr, sigLength, CRYPT_IFORMAT_SSH,
							sessionInfoPtr->iKeyexAuthContext,
							handshakeInfo->iExchangeHashcontext, NULL );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Bad handshake data signature" );

	/* We don't need the hash context any more, get rid of it */
	krnlSendNotifier( handshakeInfo->iExchangeHashcontext,
					  IMESSAGE_DECREFCOUNT );
	handshakeInfo->iExchangeHashcontext = CRYPT_ERROR;

	return( CRYPT_OK );
	}

/* Complete the handshake with the server */

static int completeClientHandshake( SESSION_INFO *sessionInfoPtr,
									SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	STREAM stream;
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	void *signedDataPtr;
	int signedDataLength, stringLength, length, packetOffset, status;

	/* Set up the security information required for the session */
	status = initSecurityInfo( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the server's change cipherspec message.  From this point
	   on the read channel is in the secure state */
	status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_NEWKEYS, ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->flags |= SESSION_ISSECURE_READ;

	/* Build our change cipherspec message and request authentication with
	   the server:

		byte	type = SSH2_MSG_NEWKEYS
		...

	   After this point the write channel is also in the secure state */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_NEWKEYS );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	sessionInfoPtr->flags |= SESSION_ISSECURE_WRITE;

	/*	...
		byte	type = SSH2_MSG_SERVICE_REQUEST
		string	service_name = "ssh-userauth" */
	packetOffset = continuePacketStreamSSH( &stream,
											SSH2_MSG_SERVICE_REQUEST );
	writeString32( &stream, "ssh-userauth", 0 );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Send the whole mess to the server.  For some reason SSHv2 requires
	   the use of two authentication messages, an "I'm about to
	   authenticate" packet and an "I'm authenticating" packet, so we have
	   to perform the authentication in two parts.  SSL at this point uses a
	   Finished message in which the client and server do a mutual proof-of-
	   possession of encryption and MAC keys via a pipeline-stalling message
	   that prevents any further (sensitive) data from being exchanged until
	   the PoP has concluded (the SSL Finished also authenticates the
	   handshake messages).  The signed exchange hash from the server proves
	   to the client that the server knows the master secret, but not
	   necessarily that the client and server share encryption and MAC keys.
	   Without this mutual PoP, the client could potentially end up sending
	   passwords to the server using an incorrect (and potentially weak) key
	   if it's messed up and derived the key incorrectly.  Although mutual
	   PoP isn't a design goal of the SSH handshake, we do it anyway (as far
	   as we can without a proper Finished message), although this introduces
	   a pipeline stall at this point

	   The spec in fact says that after a key exchange with implicit server
	   authentication the client has to wait for the server to send a
	   service-accept packet before continuing, however it never explains
	   what implicit (and, by extension, explicit) server authentication
	   actually are.  This text is a leftover from an extremely early SSH
	   draft in which the only keyex mechanism was "double-encrypting-sha",
	   a mechanism that required a pipeline stall at this point because the
	   client wasn't able to authenticate the server until it received the
	   first encrypted/MAC'ed message from it.  To extricate ourselves from
	   the confusion due to the missing definition we could define "implicit
	   authentication" to be "Something completely different from what we're
	   doing here", which means that we could send the two packets together
	   without having to wait for the server, but it's probably better to
	   use SSL-tyle Finished semantics at this point even if it adds an
	   extra RTT delay */
	status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		status = length = readPacketSSH2( sessionInfoPtr,
									SSH2_MSG_SERVICE_ACCEPT,
									ID_SIZE + sizeofString32( "", 8 ) );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( &stream );		/* Skip packet type */
	status = readString32( &stream, stringBuffer, &stringLength,
						   CRYPT_MAX_TEXTSIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) || \
		stringLength != 12 || memcmp( stringBuffer, "ssh-userauth", 12 ) )
		/* More of a sanity check than anything else, the MAC should have
		   caught any keying problems */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid service accept packet" );

	/* The buggy Tectia (ssh.com) server requires a dummy request for
	   authentication methods, otherwise it rejects any method other than
	   'password' as invalid, with the error "Client requested non-existing
	   method 'publickey'".  To work around this we submit a dummy auth.
	   request using the method 'none' */
	if( sessionInfoPtr->protocolFlags & SSH_PFLAG_TECTIA )
		{
		/* Send the dummy auth request */
		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
							 SSH2_MSG_USERAUTH_REQUEST );
		writeString32( &stream, userNamePtr->value, userNamePtr->valueLength );
		writeString32( &stream, "ssh-connection", 0 );
		writeString32( &stream, "none", 0 );
		status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
		if( cryptStatusOK( status ) )
			status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* Wait for the server's ack of the authentication.  Since this is
		   just something used to de-confuse the buggy Tectia server, we
		   ignore the content (as long as the packet's valid), any auth.
		   problems will be resolved by the real auth below */
		status = length = readPacketSSH2( sessionInfoPtr,
										  SSH2_MSG_SPECIAL_USERAUTH, ID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/*	byte	type = SSH2_MSG_USERAUTH_REQUEST
		string	user_name
		string	service_name = "ssh-connection"
		...

	   The way in which we handle authentication here isn't totally
	   appropriate since we assume that the user knows the appropriate form
	   of authentication to use.  If they're ambiguous and supply both a
	   password and a private key and the server only accepts PKC-based
	   authentication, we'll always preferentially choose password-based
	   authentication.  The way around this is to send an auth-request with
	   a method-type of "none" to see what the server wants, but the only
	   thing cryptlib can do (since it's non-interactive during the
	   handshake phase) is disconnect, tell the user what went wrong, and try
	   again.  The current mechanism does this anyway, so we don't gain much
	   except extra RTT delays by adding this question-and-answer facility */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_USERAUTH_REQUEST );
	streamBookmarkSetFullPacket( &stream, signedDataPtr, signedDataLength );
	writeString32( &stream, userNamePtr->value, userNamePtr->valueLength );
	writeString32( &stream, "ssh-connection", 0 );
	if( passwordPtr != NULL )
		{
		/*	...
			string	method-name = "password"
			boolean	FALSE
			string	password */
		writeString32( &stream, "password", 0 );
		sputc( &stream, 0 );
		status = writeString32( &stream, passwordPtr->value,
								passwordPtr->valueLength );
		}
	else
		{
		CRYPT_ALGO_TYPE pkcAlgo;
		MESSAGE_CREATEOBJECT_INFO createInfo;
		int sigLength;

		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_GETATTRIBUTE,
						 &pkcAlgo, CRYPT_CTXINFO_ALGO );

		/*	...
			string	method-name = "publickey"
			boolean	TRUE
			string		"ssh-rsa"	"ssh-dss"
			string		[ client key/certificate ]
				string	"ssh-rsa"	"ssh-dss"
				mpint	e			p
				mpint	n			q
				mpint				g
				mpint				y
			string		[ client signature ]
				string	"ssh-rsa"	"ssh-dss"
				string	signature	signature.

		   Note the doubled-up algorithm name, the spec first requires that
		   the public-key auth packet send the algorithm name and then
		   includes it a second time as part of the client key info */
		writeString32( &stream, "publickey", 0 );
		sputc( &stream, 1 );
		writeAlgoString( &stream, pkcAlgo );
		status = exportAttributeToStream( &stream,
										  sessionInfoPtr->privateKey,
										  CRYPT_IATTRIBUTE_KEY_SSH );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		streamBookmarkComplete( &stream, signedDataLength );

		/* Hash the authentication request data:

			string		exchange hash
			[ user_auth_request packet payload up to signature start ] */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		if( sessionInfoPtr->protocolFlags & SSH_PFLAG_NOHASHLENGTH )
			/* Some implementations erroneously omit the length when hashing
			    the exchange hash */
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							 handshakeInfo->sessionID,
							 handshakeInfo->sessionIDlength );
		else
			hashAsString( createInfo.cryptHandle, handshakeInfo->sessionID,
						  handshakeInfo->sessionIDlength );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 signedDataPtr, signedDataLength );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  "", 0 );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}

		/* Sign the hash.  The reason for the min() part of the expression
		   is that iCryptCreateSignatureEx() gets suspicious of very large
		   buffer sizes, for example when the user has specified the use of
		   a 1MB send buffer */
		status = iCryptCreateSignatureEx( sMemBufPtr( &stream ), &sigLength,
						min( sMemDataLeft( &stream ), 16384 ),
						CRYPT_IFORMAT_SSH, sessionInfoPtr->privateKey,
						createInfo.cryptHandle, CRYPT_UNUSED, CRYPT_UNUSED );
		if( cryptStatusOK( status ) )
			status = sSkip( &stream, sigLength );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Send the authentication info to the server */
	status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	if( cryptStatusOK( status ) )
		status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the server's ack of the authentication */
	status = length = readPacketSSH2( sessionInfoPtr,
									  SSH2_MSG_SPECIAL_USERAUTH, ID_SIZE );
	if( !cryptStatusError( status ) )
		{
		int type;

		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		type = sgetc( &stream );
		sMemDisconnect( &stream );
		if( type == SSH2_MSG_USERAUTH_FAILURE )
			/* The authentication failed, provide more specific details for
			   the caller, with an optional fallback to PAM authentication
			   if the server requested it */
			status = reportAuthFailure( sessionInfoPtr, length, FALSE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've finally made it through all of the formalities (post proelia
	   praemia), create (if necessary) and open a channel */
	if( getCurrentChannelNo( sessionInfoPtr, \
							 CHANNEL_READ ) == UNUSED_CHANNEL_NO )
		{
		/* The user hasn't specified any channel details, create a
		   channel of the default type */
		status = createChannel( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( sendChannelOpen( sessionInfoPtr ) );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2clientProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	UNUSED( sessionInfoPtr );

	handshakeInfo->beginHandshake = beginClientHandshake;
	handshakeInfo->exchangeKeys = exchangeClientKeys;
	handshakeInfo->completeHandshake = completeClientHandshake;
	}
#endif /* USE_SSH */
