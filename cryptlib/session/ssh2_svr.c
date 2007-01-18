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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* SSHv2 algorithm names sent to the client, in preferred algorithm order.
   Since we have a fixed algorithm for our public key (determined by the key
   type), we only send a single value for this that's evaluated at runtime,
   so there's no list for this defined.

   Note that these lists must match the algoStringXXXTbl values in ssh2.c */

static const CRYPT_ALGO_TYPE FAR_BSS algoKeyexList[] = {
	CRYPT_PSEUDOALGO_DHE, CRYPT_ALGO_DH, 
	CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
static const CRYPT_ALGO_TYPE FAR_BSS algoEncrList[] = {
	/* We can't list AES as an option because the peer can pick up anything
	   it wants from the list as its preferred choice, which means that if
	   we're talking to any non-cryptlib implementation they always go for
	   AES even though it doesn't yet have the full provenance of 3DES.  
	   Once AES passes the five-year test this option can be enabled */
	CRYPT_ALGO_3DES, /*CRYPT_ALGO_AES,*/ CRYPT_ALGO_BLOWFISH,
	CRYPT_ALGO_CAST, CRYPT_ALGO_IDEA, CRYPT_ALGO_RC4, 
	CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
static const CRYPT_ALGO_TYPE FAR_BSS algoMACList[] = {
	CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_MD5, 
	CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
static const CRYPT_ALGO_TYPE FAR_BSS algoStringUserauthentList[] = {
	CRYPT_PSEUDOALGO_PASSWORD, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };

/* Encode a list of available algorithms */

static int writeAlgoList( STREAM *stream, const CRYPT_ALGO_TYPE *algoList )
	{
	static const ALGO_STRING_INFO FAR_BSS algoStringMapTbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ "3des-cbc", CRYPT_ALGO_3DES },
		{ "aes128-cbc", CRYPT_ALGO_AES },
		{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
		{ "cast128-cbc", CRYPT_ALGO_CAST },
		{ "idea-cbc", CRYPT_ALGO_IDEA },
		{ "arcfour", CRYPT_ALGO_RC4 },
		{ "diffie-hellman-group-exchange-sha1", CRYPT_PSEUDOALGO_DHE },
		{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
		{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
		{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
		{ "password", CRYPT_PSEUDOALGO_PASSWORD },
		{ "none", CRYPT_ALGO_NONE },
		{ "none", CRYPT_ALGO_NONE }
		};
	const char *availableAlgos[ 16 + 8 ];
	int noAlgos = 0, length = 0, algoIndex, status;

	/* Walk down the list of algorithms remembering the encoded name of each
	   one that's available for use */
	for( algoIndex = 0; \
		 algoList[ algoIndex ] != CRYPT_ALGO_NONE && \
			algoIndex < FAILSAFE_ITERATIONS_SMALL; 
		 algoIndex++ )
		{
		if( algoAvailable( algoList[ algoIndex ] ) || \
			isPseudoAlgo( algoList[ algoIndex ] ) )
			{
			int i;

			for( i = 0; 
				 algoStringMapTbl[ i ].algo != CRYPT_ALGO_NONE && \
					algoStringMapTbl[ i ].algo != algoList[ algoIndex ] && \
					i < FAILSAFE_ARRAYSIZE( algoStringMapTbl, ALGO_STRING_INFO ); 
				 i++ );
			if( i >= FAILSAFE_ARRAYSIZE( algoStringMapTbl, ALGO_STRING_INFO ) )
				retIntError();
			assert( algoStringMapTbl[ i ].algo != CRYPT_ALGO_NONE );
			assert( noAlgos < 16 );
			availableAlgos[ noAlgos++ ] = algoStringMapTbl[ i ].name;
			length += strlen( algoStringMapTbl[ i ].name );
			if( noAlgos > 1 )
				length++;			/* Room for comma delimiter */
			}
		}
	if( algoIndex >= FAILSAFE_ITERATIONS_SMALL )
		retIntError();

	/* Encode the list of available algorithms into a comma-separated string */
	status = writeUint32( stream, length );
	for( algoIndex = 0; cryptStatusOK( status ) && algoIndex < noAlgos; 
		 algoIndex++ )
		{
		if( algoIndex > 0 )
			sputc( stream, ',' );	/* Add comma delimiter */
		status = swrite( stream, availableAlgos[ algoIndex ],
						 strlen( availableAlgos[ algoIndex ] ) );
		}
	return( status );
	}

/* Handle an ephemeral DH key exchange */

static int processDHE( SESSION_INFO *sessionInfoPtr,
					   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM stream;
	BYTE *keyPtr;
	void *keyexInfoPtr;
	const int offset = LENGTH_SIZE + sizeofString32( "ssh-dh", 6 );
	int keyPos, keyLength, keyexInfoLength, length, type, status;

	/* Get the keyex key request from the client:

		byte	type = SSH2_MSG_KEXDH_GEX_REQUEST_OLD
		uint32	n (bits)

	   or:

		byte	type = SSH2_MSG_KEXDH_GEX_REQUEST_NEW
		uint32	min (bits)
		uint32	n (bits)
		uint32	max (bits)

	   Portions of the the request info are hashed later as part of the
	   exchange hash, so we have to save a copy for then.  We save the
	   original encoded form, because some clients send non-integral lengths
	   that don't survive the conversion from bits to bytes */
	length = readPacketSSH2( sessionInfoPtr,
							 SSH2_MSG_KEXDH_GEX_REQUEST_OLD,
							 ID_SIZE + UINT32_SIZE );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	type = sgetc( &stream );
	streamBookmarkSet( &stream, keyexInfoPtr, keyexInfoLength );
	if( type == SSH2_MSG_KEXDH_GEX_REQUEST_NEW )
		{
		/* It's a { min_length, length, max_length } sequence, save a copy
		   and get the length value */
		readUint32( &stream );
		keyLength = readUint32( &stream );
		status = readUint32( &stream );
		}
	else
		/* It's a straight length, save a copy and get the length value */
		status = keyLength = readUint32( &stream );
	streamBookmarkComplete( &stream, keyexInfoLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Invalid ephemeral DH key data request packet" );
	if( keyLength < MIN_PKCSIZE_BITS || \
		keyLength > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Client requested invalid ephemeral DH key size %d bits",
				keyLength );
	memcpy( handshakeInfo->encodedReqKeySizes, keyexInfoPtr,
			keyexInfoLength );
	handshakeInfo->encodedReqKeySizesLength = keyexInfoLength;
	handshakeInfo->requestedServerKeySize = bitsToBytes( keyLength );

	/* If the requested key size differs too much from the built-in default
	   one, destroy the existing default DH key and load a new one of the
	   appropriate size.  Things get quite confusing here because the spec
	   is a schizophrenic mix of two different documents, one that specifies
	   the behaviour for the original message format which uses a single
	   length value and a second one that specifies the behaviour for the
	   { min, n, max } combination.  The range option was added as an
	   attempted fix for implementations that couldn't handle the single
	   size option, but the real problem is that the server knows what key
	   sizes are appropriate but the client has to make the choice, without
	   any knowledge of what the server can actually handle.  Because of
	   this the spec (in its n-only mindset, which also applies to the
	   min/n/max version since it's the same document) contains assorted
	   weasel-words that allow the server to choose any key size it feels
	   like if the client sends a range indication that's inappropriate.
	   Although the spec ends up saying that the server can do anything it
	   feels like ("The server should return the smallest group it knows
	   that is larger than the size the client requested.  If the server
	   does not know a group that is larger than the client request, then it
	   SHOULD return the largest group it knows"), we use a least-upper-
	   bound interpretation of the above, mostly because we store a range of
	   fixed keys of different sizes and can always find something
	   reasonably close to any (sensible) requested length */
	if( handshakeInfo->requestedServerKeySize < \
										SSH2_DEFAULT_KEYSIZE - 16 || \
		handshakeInfo->requestedServerKeySize > \
										SSH2_DEFAULT_KEYSIZE + 16 )
		{
		krnlSendNotifier( handshakeInfo->iServerCryptContext,
						  IMESSAGE_DECREFCOUNT );
		status = initDHcontextSSH( &handshakeInfo->iServerCryptContext,
								   &handshakeInfo->serverKeySize, NULL, 0,
								   handshakeInfo->requestedServerKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Send the DH key values to the client:

		byte	type = SSH2_MSG_KEXDH_GEX_GROUP
		mpint	p
		mpint	g

	   Since this phase of the key negotiation exchanges raw key components
	   rather than the standard SSH public-key format, we have to rewrite
	   the public key before we can send it to the client.  What this 
	   involves is stripping the:

		uint32	length
		string	"ssh-dh"

	   header from the start of the key, which is accomplished by moving the
	   key data down offset (= LENGTH_SIZE + sizeofString32( "ssh-dh", 6 ))
	   bytes */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_KEXDH_GEX_GROUP );
	streamBookmarkSet( &stream, keyPtr, keyPos );
	status = exportAttributeToStream( &stream,
									  handshakeInfo->iServerCryptContext,
									  CRYPT_IATTRIBUTE_KEY_SSH );
	if( cryptStatusOK( status ) )
		{
		keyLength = keyPos;
		streamBookmarkComplete( &stream, keyLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	memmove( keyPtr, keyPtr + offset, keyLength - offset );
	sseek( &stream, keyPos + keyLength - offset );
	status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
	sMemDisconnect( &stream );
	return( status );
	}

/* Handle user authentication:

	byte	type = SSH2_MSG_USERAUTH_REQUEST
	string	user_name
	string	service_name = "ssh-connection"
	string	method_name = "none" | "password"
	[ boolean	FALSE ]
	[ string	password ]

   The client can send a method-type of "none" to indicate that it'd like
   the server to return a list of allowed authentication types, if we get a
   packet of this kind we return our allowed types list.

   This can get a bit complicated because of the way the multi-pass user
   auth affects the handling of username and password information.  If 
   there's no caller-supplied list of { username, password } pairs present
   then the first time around we remember the user name but then get an 
   auth.type of "none", which means we have to go for a second iteration to 
   get the password.  On the second iteration we have a remembered user name 
   present, but no password yet.  In addition we have to be careful about
   potential attacks, e.g. the client entering a privileged user name the
   first time around and then authenticating the second time round as an
   unprivileged user.  If the calling app just grabs the first username it
   finds, it'll treat the client as being an authenticated privileged user.

   The handling of authentication information is as follows:

	Client		| Caller-supplied	| No caller-supplied
	  sends...	|	list			|	list
	------------+-------------------+-------------------
	Name, pw	| Match name, pw	| Add name, pw
	------------+-------------------+-------------------
	Name, none	| Match	name		| Add name
	Name, pw	| Match	name, pw	| Match name
				|					| Add pw
	------------+-------------------+-------------------
	Name, none	| Match	name		| Add name
	Name2, pw	| Match name2, fail	| Match name2, fail
	------------+-------------------+-------------------
	Retry		| Match name		| (As for caller-supplied 
	 Name, pw2	| Match pw2			| list, since this is present
				|					| from previous round).

   Unlike SSHv1, SSHv2 properly identifies public keys, however because of
   its complexity (several more states added to the state machine because of
   SSHv2's propensity for carrying out any negotiation it performs in lots
   of little bits and pieces) we don't support this form of authentication
   until someone specifically requests it */

static int processUserAuth( SESSION_INFO *sessionInfoPtr,
							SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM stream;
	const ATTRIBUTE_LIST *attributeListPtr;
	BYTE userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	BOOLEAN userNamePresent = FALSE;
	int length, userNameLength, stringLength, status;

	/* Get the userAuth packet from the client */
	length = readPacketSSH2( sessionInfoPtr,
							 SSH2_MSG_USERAUTH_REQUEST,
							 ID_SIZE + sizeofString32( "", 1 ) + \
							 sizeofString32( "", 8 ) + \
							 sizeofString32( "", 4 ) );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( &stream );		/* Skip packet type */

	/* Process the user name */
	status = readString32( &stream, userNameBuffer, &userNameLength,
						   CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) || \
		userNameLength <= 0 || userNameLength > CRYPT_MAX_TEXTSIZE )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid user auth user name" );
		}
	if( findSessionAttribute( sessionInfoPtr->attributeList,
							  CRYPT_SESSINFO_USERNAME ) != NULL )
		{
		/* There's user name info present, make sure that the newly-
		   submitted one matches one of the existing ones */
		attributeListPtr = \
					findSessionAttributeEx( sessionInfoPtr->attributeList,
											CRYPT_SESSINFO_USERNAME,
											userNameBuffer, userNameLength );
		if( attributeListPtr == NULL )
			{
			sMemDisconnect( &stream );
			if( attributeListPtr == NULL )
				retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
						"Unknown user name '%s'", 
						sanitiseString( userNameBuffer, userNameLength ) );
			}

		/* We've matched an existing user name, select the attribute that
		   contains it */
		sessionInfoPtr->attributeListCurrent = \
								( ATTRIBUTE_LIST * ) attributeListPtr;

		/* If it's just a saved name that was entered during a previous 
		   round of the authentication process (so there's no associated
		   password) then we treat it as a newly-entered name.  Otherwise, 
		   it's a match to a caller-supplied list of allowed { username, 
		   password } pairs, and we move on to the corresponding password */
		if( attributeListPtr->next != NULL )
			{
			userNamePresent = TRUE;

			/* Move on to the associated password */
			attributeListPtr = attributeListPtr->next;
			if( attributeListPtr->attributeID != CRYPT_SESSINFO_PASSWORD )
				retIntError();
			}
		}
	else
		{
		status = addSessionAttribute( &sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME,
									  userNameBuffer, userNameLength );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			retExt( sessionInfoPtr, status,
					"Error recording user name '%s'", 
					sanitiseString( userNameBuffer, userNameLength ) );
			}
		}

	/* Get the service name and authentication method name, either
	   "password" or "none" */
	status = readString32( &stream, stringBuffer, &stringLength,
						   CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) || \
		stringLength != 14 || memcmp( stringBuffer, "ssh-connection", 14 ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid user auth service name" );
		}
	status = readString32( &stream, stringBuffer, &stringLength,
						   CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) || \
		stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid user auth method name" );
		}
	if( !( ( stringLength == 4 && \
			 !memcmp( stringBuffer, "none", 4 ) ) || \
		   ( stringLength == 8 && \
			 !memcmp( stringBuffer, "password", 8 ) ) ) )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unknown user auth method name '%s'",
				sanitiseString( stringBuffer, stringLength ) );
		}
	sgetc( &stream );	/* Skip boolean flag */

	/* If the client wants a list of supported authentication mechanisms
	   (indicated by sending the method name "none" of length 4), tell them
	   what we allow and await further input:

		byte	type = SSH2_MSG_USERAUTH_FAILURE
		string	allowed_authent
		boolean	partial_success = FALSE */
	if( stringLength == 4 )
		{
		sMemDisconnect( &stream );
		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
							 SSH2_MSG_USERAUTH_FAILURE );
		writeAlgoList( &stream, algoStringUserauthentList );
		sputc( &stream, 0 );
		status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
		sMemDisconnect( &stream );

		return( CRYPT_OK );
		}

	/* The client has asked for password auth, either check the password
	   against the one we have for this user or save the info for the caller
	   to check */
	status = readString32( &stream, stringBuffer, &stringLength,
						   CRYPT_MAX_TEXTSIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) || \
		stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid user auth payload" );
	if( userNamePresent )
		{
		if( stringLength != attributeListPtr->valueLength || \
			memcmp( stringBuffer, attributeListPtr->value, stringLength ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid password for user '%s'", 
					sanitiseString( userNameBuffer, userNameLength ) );
		}
	else
		{
		status = addSessionAttribute( &sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD,
									  stringBuffer, stringLength );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status,
					"Error recording password for user '%s'",
					sanitiseString( userNameBuffer, userNameLength ) );
		}

	return( OK_SPECIAL );
	}

/****************************************************************************
*																			*
*							Server-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the client */

static int beginServerHandshake( SESSION_INFO *sessionInfoPtr,
								 SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	static const ALGO_STRING_INFO FAR_BSS algoStringPubkeyRSATbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ NULL, CRYPT_ALGO_NONE }
		};
	static const ALGO_STRING_INFO FAR_BSS algoStringPubkeyDSATbl[] = {
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ NULL, CRYPT_ALGO_NONE }
		};
	STREAM stream;
	void *serverHelloPtr;
	int length, serverHelloLength, clientHelloLength, status;

	/* Get the public-key algorithm that we'll be advertising to the client
	   and set the algorithm table used for processing the client hello to
	   only match the one that we're offering */
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE,
							  &handshakeInfo->pubkeyAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( handshakeInfo->pubkeyAlgo )
		{
		case CRYPT_ALGO_RSA:
			handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyRSATbl;
			break;

		case CRYPT_ALGO_DSA:
			handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyDSATbl;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes, so before we start we hash the ID strings (first the client
	   string that we read previously, then our server string) encoded as SSH
	   string values */
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->receiveBuffer,
				  strlen( sessionInfoPtr->receiveBuffer ) );
	hashAsString( handshakeInfo->iExchangeHashcontext, SSH2_ID_STRING,
				  strlen( SSH2_ID_STRING ) );

	/* Send the server hello packet:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms
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

	   The SSH spec leaves the order in which things happen ambiguous, in
	   order to save a while round trip it has provisions for both sides
	   shouting at each other and then a complex interlock process where
	   bits of the initial exchange can be discarded and retried if necessary.
	   This is ugly and error-prone.  The client code solves this by waiting
	   for the server hello, choosing known-good algorithms, and then sending
	   the client hello immediately followed by the client key exchange data.
	   Since it waits for the server to speak first, it can choose parameters
	   that are accepted the first time.

	   Unfortunately, this doesn't work if we're the server, since we'd end
	   up waiting for the client to speak first while it waits for us to
	   speak first, so we have to send the server hello in order to prevent
	   deadlock.  This works fine with most clients, which take the same
	   approach and wait for the server to speak first.  The message flow is
	   then:

		server hello;
		client hello;
		client keyex;
		server keyex;

	   There are one or two exceptions to this, the worst of which is the
	   F-Secure client, which has the client speak first choosing as its
	   preference the incompletely specified "x509v3-sign-dss" format (see
	   the comment in exchangeServerKeys() below) that we can't use since no-
	   one's quite sure what the format is (this was fixed in mid-2004 when
	   the x509v3-* schemes were removed from the spec, since no-one could
	   figure out what they were.  F-Secure still specifies them, but after
	   the standard ssh-* schemes).  In this case the message flow is:

		server hello;
		client hello;
		client keyex1;
		client keyex2;
		server keyex;

	   This is handled by having the code that reads the client hello return
	   OK_SPECIAL to indicate that the next packet should be skipped.  An
	   alternative (and simpler) strategy would be to always throw away the
	   F-Secure client's first keyex, since it's using an algorithm choice
	   that's impossible to use */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 SSH2_MSG_KEXINIT );
	streamBookmarkSetFullPacket( &stream, serverHelloPtr,
								 serverHelloLength );
	exportVarsizeAttributeToStream( &stream, SYSTEM_OBJECT_HANDLE,
									CRYPT_IATTRIBUTE_RANDOM_NONCE,
									SSH2_COOKIE_SIZE );
	writeAlgoList( &stream, algoKeyexList );
	writeAlgoString( &stream, handshakeInfo->pubkeyAlgo );
	writeAlgoList( &stream, algoEncrList );
	writeAlgoList( &stream, algoEncrList );
	writeAlgoList( &stream, algoMACList );
	writeAlgoList( &stream, algoMACList );
	writeAlgoString( &stream, CRYPT_PSEUDOALGO_COPR );
	writeAlgoString( &stream, CRYPT_PSEUDOALGO_COPR );
	writeUint32( &stream, 0 );			/* No language tag */
	writeUint32( &stream, 0 );
	sputc( &stream, 0 );				/* Don't try and guess the keyex */
	writeUint32( &stream, 0 );			/* Reserved */
	streamBookmarkComplete( &stream, serverHelloLength );
	status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* While we wait for the client to digest our hello and send back its
	   response, create the context with the DH key */
	status = initDHcontextSSH( &handshakeInfo->iServerCryptContext,
							   &handshakeInfo->serverKeySize, NULL, 0,
							   CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the client hello packet and hash the client and server
	   hello */
	status = processHelloSSH( sessionInfoPtr, handshakeInfo,
							  &clientHelloLength, TRUE );
	if( cryptStatusOK( status ) )
		status = hashAsString( handshakeInfo->iExchangeHashcontext,
							   sessionInfoPtr->receiveBuffer,
							   clientHelloLength );
	else
		if( status == OK_SPECIAL )
			{
			/* There's an incorrectly-guessed keyex following the client
			   hello, skip it */
			hashAsString( handshakeInfo->iExchangeHashcontext,
						  sessionInfoPtr->receiveBuffer, clientHelloLength );
			status = readPacketSSH2( sessionInfoPtr,
						( handshakeInfo->requestedServerKeySize > 0 ) ? \
							SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT,
						ID_SIZE + sizeofString32( "", bitsToBytes( MIN_PKCSIZE_BITS ) ) );
			}
	if( !cryptStatusError( status ) )	/* rPSSH2() returns a byte count */
		status = hashAsString( handshakeInfo->iExchangeHashcontext,
							   serverHelloPtr, serverHelloLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using a nonstandard DH key value, negotiate a new key with
	   the client */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		status = processDHE( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the client keyex:

		byte	type = SSH2_MSG_KEXDH_INIT / SSH2_MSG_KEXDH_GEX_INIT
		mpint	y */
	length = readPacketSSH2( sessionInfoPtr,
					( handshakeInfo->requestedServerKeySize > 0 ) ? \
					  SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT,
					ID_SIZE + sizeofString32( "", bitsToBytes( MIN_PKCSIZE_BITS ) ) );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sgetc( &stream );		/* Skip packet type */
	status = readRawObject32( &stream, handshakeInfo->clientKeyexValue,
							  &handshakeInfo->clientKeyexValueLength,
							  sizeof( handshakeInfo->clientKeyexValue ) );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) || \
		!isValidDHsize( handshakeInfo->clientKeyexValueLength,
						handshakeInfo->serverKeySize, LENGTH_SIZE ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 1 keyex value" );
	return( CRYPT_OK );
	}

/* Exchange keys with the client */

static int exchangeServerKeys( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	STREAM stream;
	void *keyPtr;
	int keyLength, sigLength, packetOffset, status;

	/* Create the server DH value */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( handshakeInfo->iServerCryptContext,
							  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	sMemOpen( &stream, handshakeInfo->serverKeyexValue,
			  sizeof( handshakeInfo->serverKeyexValue ) );
	status = writeInteger32( &stream, keyAgreeParams.publicValue,
							 keyAgreeParams.publicValueLen );
	if( cryptStatusOK( status ) )
		handshakeInfo->serverKeyexValueLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the DH phase 2 keyex packet:

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
		...

	   The specification also makes provision for using X.509 and PGP keys,
	   but only so far as to say that keys and signatures are in "X.509 DER"
	   and "PGP" formats, neither of which actually explain what it is
	   that's sent or signed (and no-one on the SSH list can agree on what
	   they're supposed to look like), so we can't use either of them */
	openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
						 handshakeInfo->requestedServerKeySize ? \
							SSH2_MSG_KEXDH_GEX_REPLY : SSH2_MSG_KEXDH_REPLY );
	streamBookmarkSet( &stream, keyPtr, keyLength );
	status = exportAttributeToStream( &stream, sessionInfoPtr->privateKey,
									  CRYPT_IATTRIBUTE_KEY_SSH );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	streamBookmarkComplete( &stream, keyLength );
	status = krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							  IMESSAGE_CTX_HASH, keyPtr, keyLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	swrite( &stream, handshakeInfo->serverKeyexValue,
			handshakeInfo->serverKeyexValueLength );

	/* Complete phase 2 of the DH key agreement process to obtain the shared
	   secret value */
	status = completeKeyex( sessionInfoPtr, handshakeInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Sign the hash.  The reason for the min() part of the expression is
	   that iCryptCreateSignatureEx() gets suspicious of very large buffer
	   sizes, for example when the user has specified the use of a 1MB send
	   buffer */
	status = iCryptCreateSignatureEx( sMemBufPtr( &stream ), &sigLength,
						min( sMemDataLeft( &stream ), 16384 ),
						CRYPT_IFORMAT_SSH, sessionInfoPtr->privateKey,
						handshakeInfo->iExchangeHashcontext,
						CRYPT_UNUSED, CRYPT_UNUSED );
	krnlSendNotifier( handshakeInfo->iExchangeHashcontext,
					  IMESSAGE_DECREFCOUNT );
	handshakeInfo->iExchangeHashcontext = CRYPT_ERROR;
	if( cryptStatusOK( status ) )
		status = sSkip( &stream, sigLength );
	if( cryptStatusOK( status ) )
		status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Build our change cipherspec message and send the whole mess through
	   to the client:
		...
		byte	type = SSH2_MSG_NEWKEYS.

	   After this point the write channel is in the secure state */
	packetOffset = continuePacketStreamSSH( &stream, SSH2_MSG_NEWKEYS );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, packetOffset );
	if( cryptStatusOK( status ) )
		status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->flags |= SESSION_ISSECURE_WRITE;
	return( CRYPT_OK );
	}

/* Complete the handshake with the client */

static int completeServerHandshake( SESSION_INFO *sessionInfoPtr,
									SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM stream;
	int length, iterationCount = 0, status;

	/* If this is the first time through, set up the security info and wait
	   for the first part of the authentication */
	if( !( sessionInfoPtr->flags & SESSION_PARTIALOPEN ) )
		{
		BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		int stringLength;

		/* Set up the security information required for the session */
		status = initSecurityInfo( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Wait for the client's change cipherspec message.  From this point
		   on the read channel is in the secure state */
		status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_NEWKEYS, ID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		sessionInfoPtr->flags |= SESSION_ISSECURE_READ;

		/* Wait for the client's authentication packets.  For some reason
		   SSHv2 requires the use of two authentication messages, an "I'm
		   about to authenticate" packet and an "I'm authenticating" packet.
		   First we  handle the "I'm about to authenticate":

			byte	type = SSH2_MSG_SERVICE_REQUEST
			string	service_name = "ssh-userauth"

			byte	type = SSH2_MSG_SERVICE_ACCEPT
			string	service_name = "ssh-userauth" */
		length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_SERVICE_REQUEST,
								 ID_SIZE + sizeofString32( "", 8 ) );
		if( cryptStatusError( length ) )
			return( length );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		sgetc( &stream );		/* Skip packet type */
		status = readString32( &stream, stringBuffer, &stringLength,
							   CRYPT_MAX_TEXTSIZE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) || \
			stringLength != 12 || memcmp( stringBuffer, "ssh-userauth", 12 ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid service request packet" );
		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
							 SSH2_MSG_SERVICE_ACCEPT );
		writeString32( &stream, "ssh-userauth", 0 );
		status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Wait for the second part of the authentication, optionally letting the
	   caller determine whether to allow the authentication or not */
	do
		{
		SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;

		/* If we don't have authentication info ready to act upon,
		   read it now */
		if( !sshInfo->authRead )
			{
			int retryCount;

			/* Since the userAuth negotiation can (in theory) go on
			   indefinitely, we limit it to three iterations to avoid
			   potential DoS problems */
			for( retryCount = 0; status != OK_SPECIAL && retryCount < 3; 
				 retryCount++ )
				{
				status = processUserAuth( sessionInfoPtr, handshakeInfo );
				if( cryptStatusError( status ) && status != OK_SPECIAL )
					return( status );
				}
			if( retryCount >= 3 )
				retExt( sessionInfoPtr, CRYPT_ERROR_PERMISSION,
						"Too many iterations of negotiation during user "
						"auth request processing" );

			/* We got a userAuth request, if the caller will handle it, let
			   them know that they have to react on it */
			sshInfo->authRead = TRUE;
			if( sessionInfoPtr->authResponse == CRYPT_UNUSED )
				return( CRYPT_ENVELOPE_RESOURCE );
			}

		/* Acknowledge the authentication:

			byte	type = SSH2_MSG_USERAUTH_SUCCESS /
						   SSH2_MSG_USERAUTH_FAILURE */
		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
							 sessionInfoPtr->authResponse ? \
								SSH2_MSG_USERAUTH_SUCCESS : \
								SSH2_MSG_USERAUTH_FAILURE );
		status = sendPacketSSH2( sessionInfoPtr, &stream, FALSE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* If the caller denied the authentication, go back to asking what
		   to do on the next authentication attempt */
		if( sessionInfoPtr->authResponse == FALSE )
			sessionInfoPtr->authResponse = CRYPT_UNUSED;
		sshInfo->authRead = FALSE;
		}
	while( sessionInfoPtr->authResponse != TRUE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	/* Handle the channel open */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_CHANNEL_OPEN,
							 ID_SIZE + sizeofString32( "", 4 ) + \
							 UINT32_SIZE + UINT32_SIZE + UINT32_SIZE );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	assert( sPeek( &stream ) == SSH2_MSG_CHANNEL_OPEN );
	sgetc( &stream );		/* Skip packet type */
	status = processChannelOpen( sessionInfoPtr, &stream );
	sMemDisconnect( &stream );
#if 1
	return( status );
#else	/* If we handle the following inline as part of the general read code
		   it requires that the user try and read some data (with a non-zero
		   timeout) right after the connect completes.  Because it's awkward
		   to have to rely on this, we provide optional code to explicitly
		   clear the pipe here.  This code stops as soon as the first data
		   channel-opening request is received, with further requests being
		   handled inline as part of the standard data-read handling.  The
		   reason why this isn't enabled by default is that it's possible to
		   encounter a client that doesn't send anything beyond the initial
		   channel open, which means that we'd hang around waiting for a
		   control message until we time out */
	if( cryptStatusError( status ) )
		return( status );

	/* Process any further junk that the caller may throw at us until we get
	   a request that we can handle, indicated by an OK_SPECIAL response */
	do
		{
		status = length = readPacketSSH2( sessionInfoPtr,
										  SSH2_MSG_SPECIAL_REQUEST, 8 );
		if( !cryptStatusError( status ) )
			{
			sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
			sgetc( &stream );
			status = processChannelControlMessage( sessionInfoPtr, &stream );
			sMemDisconnect( &stream );
			}
		}
	while( cryptStatusOK( status ) );
	return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
#endif /* 1 */
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2serverProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	UNUSED( sessionInfoPtr );

	handshakeInfo->beginHandshake = beginServerHandshake;
	handshakeInfo->exchangeKeys = exchangeServerKeys;
	handshakeInfo->completeHandshake = completeServerHandshake;
	}
#endif /* USE_SSH */
