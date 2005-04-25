/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Session Management					*
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
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise and destroy the handshake state information */

static void destroyHandshakeInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	destroyHandshakeCryptInfo( handshakeInfo );

	zeroise( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) );
	}

static int initHandshakeInfo( SESSION_INFO *sessionInfoPtr,
							  SSL_HANDSHAKE_INFO *handshakeInfo,
							  const BOOLEAN isServer )
	{
	memset( handshakeInfo, 0, sizeof( SSL_HANDSHAKE_INFO ) );
	if( isServer )
		{
		initSSLserverProcessing( handshakeInfo );

		/* Check whether the server key is signature-capable.  If it is,
		   it can be used to authenticate a DH key exchange (the default
		   server key encryption capability only handles RSA key 
		   exchange) */
		if( cryptStatusOK( \
				krnlSendMessage( sessionInfoPtr->privateKey, 
								 IMESSAGE_CHECK, NULL, 
								 MESSAGE_CHECK_PKC_SIGN ) ) )
			handshakeInfo->serverSigKey = TRUE;
		}
	else
		initSSLclientProcessing( handshakeInfo );
	return( initHandshakeCryptInfo( handshakeInfo ) );
	}

/* SSL uses 24-bit lengths in some places even though the maximum packet 
   length is only 16 bits (actually it's limited even further by the spec
   to 14 bits).  To handle this odd length, we define our own read/
   writeUint24() functions that always set the high byte to zero */

int readUint24( STREAM *stream )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( status != 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint16( stream ) );
	}

int writeUint24( STREAM *stream, const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( length >= 0 && length < CRYPT_MAX_IVSIZE + MAX_PACKET_SIZE + \
									CRYPT_MAX_HASHSIZE + CRYPT_MAX_IVSIZE );

	sputc( stream, 0 );
	return( writeUint16( stream, length ) );
	}

/* Choose the best cipher suite from a list of suites.  There are a pile of
   DH cipher suites, in practice only DHE is used, DH requires the use of
   X9.42 DH certs (there aren't any) and DH_anon uses unauthenticated DH 
   which implementers seem to have an objection to even though it's not much
   different in effect from the way RSA cipher suites are used in practice.
   
   To keep things simple for the caller, we only allow RSA auth for DH key
   agreement and not DSA, since the former also automatically works for the
   far more common RSA key exchange that's usually used for key setup */

int processCipherSuite( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo, 
						STREAM *stream, const int noSuites )
	{
	const static struct {
		const int cipherSuite;
		const CRYPT_ALGO_TYPE keyexAlgo, authAlgo, cryptAlgo, macAlgo;
		const int cryptKeySize, macBlockSize;
		} cipherSuiteInfo[] = {
		/* PSK suites */
		{ TLS_PSK_WITH_3DES_EDE_CBC_SHA,
		  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_3DES,
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE },
		{ TLS_PSK_WITH_AES_256_CBC_SHA,
		  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE },
		{ TLS_PSK_WITH_AES_128_CBC_SHA,
		  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
		{ TLS_PSK_WITH_RC4_128_SHA,
		  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_RC4,
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
#ifdef PREFER_DH_SUITES
		/* 3DES with DH */
		{ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
		  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE }, */

		/* AES with DH */
		{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
		  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE }, */
		{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		  CRYPT_ALGO_RSA, CRYPT_ALGO_DSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE }, */

		/* 3DES with RSA */
		{ SSL_RSA_WITH_3DES_EDE_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE },

		/* AES with RSA */
		{ TLS_RSA_WITH_AES_256_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE },
		{ TLS_RSA_WITH_AES_128_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
#else
		/* 3DES with RSA */
		{ SSL_RSA_WITH_3DES_EDE_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE },

		/* AES with RSA */
		{ TLS_RSA_WITH_AES_256_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE },
		{ TLS_RSA_WITH_AES_128_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },

		/* 3DES with DH */
		{ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
		  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_3DES, 
		  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE }, */

		/* AES with DH */
		{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
		  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE }, */
		{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		  CRYPT_ALGO_RSA, CRYPT_ALGO_DSA, CRYPT_ALGO_AES, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE }, */
#endif /* PREFER_DH_SUITES */

		/* IDEA + RSA */
		{ SSL_RSA_WITH_IDEA_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_IDEA, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },

		/* RC4 + RSA */
		{ SSL_RSA_WITH_RC4_128_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4, 
		  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE },
		{ SSL_RSA_WITH_RC4_128_MD5, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4, 
		  CRYPT_ALGO_HMAC_MD5, 16, MD5MAC_SIZE },

		/* DES + RSA */
		{ SSL_RSA_WITH_DES_CBC_SHA, 
		  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_DES, 
		  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE },
		{ TLS_DHE_RSA_WITH_DES_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_DES, 
		  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE },
/*		{ TLS_DHE_DSS_WITH_DES_CBC_SHA, 
		  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_DES, 
		  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE }, */

		/* End-of-list marker */
		{ SSL_NULL_WITH_NULL, 
		  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0, 0 }
		};
	CRYPT_QUERY_INFO queryInfo;
	const BOOLEAN isServer = ( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
							 TRUE : FALSE;
	int currentSuiteIndex = 999, i, status;

	for( i = 0; i < noSuites; i++ )
		{
		int currentSuite, suiteInfoIndex;

		/* If we're reading an SSLv2 hello and it's an SSLv2 suite (the high 
		   byte is nonzero), skip it and continue */
		if( handshakeInfo->isSSLv2 )
			{
			currentSuite = sgetc( stream );
			if( cryptStatusError( currentSuite ) )
				retExt( sessionInfoPtr, currentSuite,
						"Invalid cipher suite information" );
			if( currentSuite != 0 )
				{
				readUint16( stream );
				continue;
				}
			}

		/* Get the cipher suite info */
		currentSuite = readUint16( stream );
		if( cryptStatusError( currentSuite ) )
			retExt( sessionInfoPtr, currentSuite,
					"Invalid cipher suite information" );

#if 0	/* When resuming a cached session, the client is required to offer 
		   as one of its suites the original suite that was used.  There is 
		   no good reason for this requirement (it's probable that the spec 
		   is intending that there be at least one cipher suite, and that if 
		   there's only one it should really be the one originally 
		   negotiated) and it complicates implementation of shared-secret 
		   key sessions, so we don't perform this check */
		/* If we have to match a specific suite and this isn't it, 
		   continue */
		if( requiredSuite > 0 && requiredSuite != currentSuite )
			continue;
#endif /* 0 */

		/* If we're the client and we got back our canary method-of-last-
		   resort suite from the server, the server is incapable of handling 
		   non-crippled crypto.  Veni, vidi, volo in domum redire */
		if( !isServer && currentSuite == SSL_RSA_EXPORT_WITH_RC4_40_MD5 )
			retExt( sessionInfoPtr, CRYPT_ERROR_NOSECURE,
					"Server rejected attempt to connect using non-crippled "
					"encryption" );

		/* Try and find the info for the proposed cipher suite */
		for( suiteInfoIndex = 0; \
			 cipherSuiteInfo[ suiteInfoIndex ].cipherSuite != SSL_NULL_WITH_NULL && \
			 cipherSuiteInfo[ suiteInfoIndex ].cipherSuite != currentSuite; \
			 suiteInfoIndex++ );
		if( cipherSuiteInfo[ suiteInfoIndex ].cipherSuite == SSL_NULL_WITH_NULL )
			continue;

		/* If the new suite is less preferred than the existing one, don't 
		   try and work with it */
		if( suiteInfoIndex >= currentSuiteIndex )
			continue;

		/* Make sure that the required algorithms are available.  We don't 
		   have to check the MAC algorithms since MD5 and SHA-1 are always
		   available as they're required for the handshake */
		if( !algoAvailable( cipherSuiteInfo[ suiteInfoIndex ].cryptAlgo ) )
			continue;
		if( ( cipherSuiteInfo[ suiteInfoIndex ].keyexAlgo != \
			  cipherSuiteInfo[ suiteInfoIndex ].authAlgo ) && \
			!algoAvailable( cipherSuiteInfo[ suiteInfoIndex ].keyexAlgo ) )
			continue;

		/* If it's a DH suite and the server key can't be used for signing 
		   (needed to authenticate the DH exchange), we can't use the DH
		   suite */
		if( isServer && !handshakeInfo->serverSigKey && \
			cipherSuiteInfo[ suiteInfoIndex ].keyexAlgo == CRYPT_ALGO_DH )
			continue;

		/* We've found a more-preferred available suite, go with that */
		currentSuiteIndex = suiteInfoIndex;
		}
	if( currentSuiteIndex > 50 )
		/* We couldn't find anything to use, exit */
		retExt( sessionInfoPtr, CRYPT_ERROR_NOTAVAIL,
				"No encryption algorithm compatible with the remote system "
				"could be found" );

	/* We got a cipher suite that we can handle, set up the crypto info */
	handshakeInfo->cipherSuite = cipherSuiteInfo[ currentSuiteIndex ].cipherSuite;
	handshakeInfo->keyexAlgo = cipherSuiteInfo[ currentSuiteIndex ].keyexAlgo;
	handshakeInfo->authAlgo = cipherSuiteInfo[ currentSuiteIndex ].authAlgo;
	handshakeInfo->cryptKeysize = cipherSuiteInfo[ currentSuiteIndex ].cryptKeySize;
	sessionInfoPtr->cryptAlgo = cipherSuiteInfo[ currentSuiteIndex ].cryptAlgo;
	sessionInfoPtr->integrityAlgo = cipherSuiteInfo[ currentSuiteIndex ].macAlgo;
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		/* SSL uses a proto-HMAC which requires that we synthesize it from
		   raw hash functionality */
		sessionInfoPtr->integrityAlgo = \
			( sessionInfoPtr->integrityAlgo == CRYPT_ALGO_HMAC_MD5 ) ? \
			CRYPT_ALGO_MD5 : CRYPT_ALGO_SHA;
	sessionInfoPtr->authBlocksize = cipherSuiteInfo[ currentSuiteIndex ].macBlockSize;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
							  sessionInfoPtr->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->cryptBlocksize = queryInfo.blockSize;

	return( CRYPT_OK );
	}

/* Process RFC 3546 TLS extensions:

	uint16		extListLen		| RFC 3546
		uint16	extType
		uint16	extLen
		byte[]	extData */

static int processExtensions( SESSION_INFO *sessionInfoPtr, STREAM *stream,
							  const int length )
	{
	int endPos = stell( stream ) + length, extListLen;

	/* Read the extension header and make sure that it's valid */
	if( length < UINT16_SIZE + UINT16_SIZE + UINT16_SIZE + 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"TLS hello contains %d bytes extraneous data", length );
	extListLen = readUint16( stream );
	if( cryptStatusError( extListLen ) || \
		extListLen != length - UINT16_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid TLS extension data length %d, should be %d", 
				extListLen, length - UINT16_SIZE );

	/* Process the extensions */
	while( stell( stream ) < endPos )
		{
		int type, extLen, value;

		/* Get the next extension */
		type = readUint16( stream );
		extLen = readUint16( stream );
		if( cryptStatusError( extLen ) || extLen < 1 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid TLS extension list item header" );

		/* Process the extension data.  The internal structure of some of 
		   these things shows that they were created by ASN.1 people... */
		switch( type )
			{
			case TLS_EXT_SERVER_NAME:
				{
				int listLen;

				/* Response: Send zero-length reply to peer:
				
					uint16		listLen
						byte	nameType
						uint16	nameLen 
						byte[]	name */
				listLen = readUint16( stream );
				if( cryptStatusError( listLen ) || \
					listLen != extLen - UINT16_SIZE || \
					listLen < 1 + UINT16_SIZE || \
					cryptStatusError( sSkip( stream, listLen ) ) )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS host name extension" );
				/* Parsing of further SEQUENCE OF SEQUENCE data omitted */
				break;
				}

			case TLS_EXT_MAX_FRAGMENT_LENTH:
				{
				static const int fragmentTbl[] = \
						{ 0, 512, 1024, 2048, 4096, 8192, 16384 };

				/* Response: If frag-size == 3...5, send same to peer.  
				   Note that we also allow a frag-size value of 5, which 
				   isn't specified in the standard but should probably be 
				   present since it would otherwise result in a missing 
				   value between 4096 and the default of 16384:
				   
					byte		fragmentLength */
				value = sgetc( stream );
				if( cryptStatusError( value ) || \
					extLen != 1 || value < 1 || value > 5 )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS fragment length extension" );
/*				sessionInfoPtr->maxPacketSize = fragmentTbl[ value ]; */
				break;
				}

			case TLS_EXT_CLIENT_CERTIFICATE_URL:
				/* Response: Ignore.  This dangerous extension allows a 
				   client to direct a server to grope around in arbitrary 
				   external (and untrusted) URLs trying to locate certs,
				   provinding a convenient mechanism for bounce attacks
				   and all manner of similar firewall/trusted-host 
				   subversion problems:

					byte		chainType
					uint16		urlAndHashList
						uint16	urlLen
						byte[]	url
						byte	hashPresent
						byte[20] hash	- If hashPresent flag set */
				if( extLen < 1 + UINT16_SIZE + \
							 UINT16_SIZE + MIN_URL_SIZE + 1 || \
					cryptStatusError( sSkip( stream, extLen ) ) )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS client certificate URL extension" );
				break;

			case TLS_EXT_TRUSTED_CA_KEYS:
				/* Response: Ignore.  This allows a client to specify which
				   CA certs it trusts, and by extension which server certs
				   it trusts.  God knows what actual problem this is 
				   intended to solve:

					uint16		caList
						byte	idType
						... */
				if( extLen < UINT16_SIZE + 1 || \
					cryptStatusError( sSkip( stream, extLen ) ) )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS trusted CA extension" );
				break;

			case TLS_EXT_TRUNCATED_HMAC:
				/* Truncate the HMAC to a nonstandard 80 bits (rather than 
				   the de facto IPsec cargo-cult standard of 96 bits) */
				if( extLen != 0 )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS truncated HMAC extension" );
				break;

			case TLS_EXT_STATUS_REQUEST:
				/* Response: Ignore - another bounce-attack enabler, this 
				   time on both the server and an OCSP responder:

					byte	statusType
					... */
				if( extLen < 1 || \
					cryptStatusError( sSkip( stream, extLen ) ) )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS status request extension" );
				break;

			default:
				/* Default: Ignore the extension */
				if( cryptStatusError( sSkip( stream, extLen ) ) )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid TLS extension data for extension "
							"type %d", type );
			}
		}

	return( CRYPT_OK );
	}

/* Process a session ID */

static int processSessionID( SESSION_INFO *sessionInfoPtr, 
							 SSL_HANDSHAKE_INFO *handshakeInfo, 
							 STREAM *stream )
	{
	BYTE sessionID[ SESSIONID_SIZE + 8 ];
	const int sessionIDlength = sgetc( stream );
	int status;

	/* Get the session ID info and if it's not one of ours, skip it */
	if( cryptStatusError( sessionIDlength ) || \
		sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, "Invalid session ID" );
	if( sessionIDlength != SESSIONID_SIZE )
		{
		if( sessionIDlength > 0 )
			{
			status = sSkip( stream, sessionIDlength );
			if( cryptStatusError( status ) )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid session ID" );
			}
		return( CRYPT_OK );
		}

	/* There's a session ID present, check to make sure that it matches our 
	   expectations.  If we're the server the the size is right for it to
	   (potentially) be one of ours, if we're the client we check to see 
	   whether it matches what we sent */
	status = sread( stream, sessionID, SESSIONID_SIZE );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, "Invalid session ID" );
	if( !( sessionInfoPtr->flags & SESSION_ISSERVER ) )
		{
		const ATTRIBUTE_LIST *userNamePtr;
		BYTE formattedSessionID[ SESSIONID_SIZE + 8 ];

		/* If the returned session ID matches the one that we sent,
		   it's a resumed session */
		if( ( userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME ) ) == NULL )
			/* There's no user name present, it can't be a resumed 
			   session */
			return( CRYPT_OK );
		memset( formattedSessionID, 0, SESSIONID_SIZE );
		memcpy( formattedSessionID, userNamePtr->value, 
				min( userNamePtr->valueLength, SESSIONID_SIZE ) );
		if( memcmp( formattedSessionID, sessionID, SESSIONID_SIZE ) )
			/* The user name doesn't match the returned ID, it's not a 
			   resumed session */
			return( CRYPT_OK );
		}

	/* It's a resumed session, remember the details and let the caller 
	   know */
	memcpy( handshakeInfo->sessionID, sessionID, SESSIONID_SIZE );
	handshakeInfo->sessionIDlength = SESSIONID_SIZE;
	return( OK_SPECIAL );
	}

/* Process the client/server hello:

	byte		ID = SSL_HAND_CLIENT_HELLO / SSL_HAND_SERVER_HELLO
	uint24		len
	byte[2]		version = { 0x03, 0x0n }
	uint32		time		| Client/server nonce
	byte[28]	nonce		|
	byte		sessIDlen	| May receive nonzero len +
	byte[]		sessID		|	<len> bytes data

		Client						Server
	uint16		suiteLen		-
	uint16[]	suites			uint16		suite
	byte		coprLen = 1		-
	byte		copr = 0		byte		copr = 0 */

int processHelloSSL( SESSION_INFO *sessionInfoPtr, 
					 SSL_HANDSHAKE_INFO *handshakeInfo, 
					 STREAM *stream, const BOOLEAN isServer )
	{
	BOOLEAN resumedSession = FALSE;
	int endPos, length, suiteLength = 1, i, status;

	/* Check the header and version info */
	if( isServer )
		length = checkHSPacketHeader( sessionInfoPtr, stream,
									  SSL_HAND_CLIENT_HELLO,
									  VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
										1 + ( UINT16_SIZE * 2 ) + 1 + 1 );
	else
		length = checkHSPacketHeader( sessionInfoPtr, stream,
									  SSL_HAND_SERVER_HELLO,
									  VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
										1 + UINT16_SIZE + 1 );
	if( cryptStatusError( length ) )
		return( length );
	endPos = stell( stream ) + length;
	status = processVersionInfo( sessionInfoPtr, stream, 
								 isServer ? \
									&handshakeInfo->clientOfferedVersion : \
									NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the nonce and session ID */
	sread( stream, isServer ? handshakeInfo->clientNonce : \
							  handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	status = processSessionID( sessionInfoPtr, handshakeInfo, stream );
	if( status == OK_SPECIAL )
		resumedSession = TRUE;
	else
		if( cryptStatusError( status ) )
			return( status );

	/* Process the cipher suite information */
	if( isServer )
		{
		/* If we're reading the client hello, the packet contains a 
		   selection of suites preceded by a suite count */
		suiteLength = readUint16( stream );
		if( cryptStatusError( suiteLength ) || \
			suiteLength < UINT16_SIZE || ( suiteLength % UINT16_SIZE ) != 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid cipher suite information" );
		suiteLength /= UINT16_SIZE;
		}
	status = processCipherSuite( sessionInfoPtr, handshakeInfo, stream, 
								 suiteLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the compression suite information */
	if( isServer )
		{
		/* If we're reading the client hello, the packet contains a 
		   selection of suites preceded by a suite count */
		suiteLength = sgetc( stream );
		if( cryptStatusError( suiteLength ) || suiteLength < 1 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid compression suite information" );
		}
	for( i = 0; i < suiteLength; i++ )
		{
		if( sgetc( stream ) != 0 )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid compression algorithm information" );

	/* If there's extra data present at the end of the packet, check for TLS 
	   extension data */
	if( endPos - stell( stream ) > 0 )
		{
		status = processExtensions( sessionInfoPtr, stream, 
									endPos - stell( stream ) );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->hasExtensions = TRUE;
		}

	return( resumedSession ? OK_SPECIAL : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Certificate-handling Functions					*
*																			*
****************************************************************************/

/* Read/write an SSL cert chain:

	byte		ID = SSL_HAND_CERTIFICATE
	uint24		len
	uint24		certListLen
	uint24		certLen			| 1...n certs ordered
	byte[]		cert			|   leaf -> root */

int readSSLCertChain( SESSION_INFO *sessionInfoPtr, 
					  SSL_HANDSHAKE_INFO *handshakeInfo, STREAM *stream,
					  CRYPT_CERTIFICATE *iCertChain, 
					  const BOOLEAN isServer )
	{
	CRYPT_ALGO_TYPE algorithm;
	const ATTRIBUTE_LIST *fingerprintPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_FINGERPRINT );
	RESOURCE_DATA msgData;
	BYTE certFingerprint[ CRYPT_MAX_HASHSIZE ];
	const char *peerTypeName = isServer ? "Client" : "Server";
	int chainLength, length, status;

	/* Clear return value */
	*iCertChain = CRYPT_ERROR;

	/* Make sure that the packet header is in order */
	length = checkHSPacketHeader( sessionInfoPtr, stream,
								  SSL_HAND_CERTIFICATE, isServer ? \
									0 : LENGTH_SIZE + MIN_CERTSIZE );
	if( cryptStatusError( length ) )
		return( length );
	if( isServer && length < LENGTH_SIZE + MIN_CERTSIZE )
		{
		/* There is a special case in which a too-short cert packet is valid
		   and that's where it constitutes the TLS equivalent of an SSL
		   no-certs alert.  SSLv3 sent an SSL_ALERT_NO_CERTIFICATE alert to 
		   indicate that the client doesn't have a cert, which is handled by 
		   the readPacketSSL() call.  TLS changed this to send an empty cert 
		   packet instead, supposedly because it lead to implementation 
		   problems (presumably it's necessary to create a state machine-
		   based implementation to reproduce these problems, whatever they 
		   are).  The TLS 1.0 spec is ambiguous as to what constitutes an 
		   empty packet, it could be either a packet with a length of zero 
		   or a packet containing a zero-length cert list so we check for 
		   both.  TLS 1.1 fixed this to say that that certListLen entry has
		   a length of zero.  To report this condition we fake the error 
		   indicators for consistency with the status obtained from an SSLv3 
		   no-cert alert */
		if( length == 0 || length == LENGTH_SIZE )
			{
			sessionInfoPtr->errorCode = SSL_ALERT_NO_CERTIFICATE;
			retExt( sessionInfoPtr, CRYPT_ERROR_PERMISSION,
					"Received TLS alert message: No certificate" );
			}
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, 
				"Invalid certificate chain" );
		}
	chainLength = readUint24( stream );
	if( cryptStatusError( chainLength ) || \
		chainLength < MIN_CERTSIZE || chainLength != length - LENGTH_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid cert chain length %d, should be %d", 
				chainLength, length - LENGTH_SIZE );

	/* Import the cert chain and get information on it.  This isn't a true 
	   cert chain (in the sense of being degenerate PKCS #7 SignedData) but 
	   a special-case SSL-encoded cert chain */
	status = importCertFromStream( stream, iCertChain, chainLength,
								   CRYPT_ICERTTYPE_SSL_CERTCHAIN );
	if( cryptStatusError( status ) )
		{
		/* There are sufficient numbers of broken certs around that if we 
		   run into a problem importing one we provide a custom error 
		   message telling the user to try again with a reduced compliance 
		   level */
		if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_INVALID )
			retExt( sessionInfoPtr, status, 
					"%s provided a broken/invalid certificate, try again "
					"with a reduced level of certificate compliance "
					"checking", peerTypeName );
		retExt( sessionInfoPtr, status, "Invalid certificate chain" );
		}
	status = krnlSendMessage( *iCertChain, IMESSAGE_GETATTRIBUTE, 
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( *iCertChain, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, 
								  ( fingerprintPtr != NULL && \
									fingerprintPtr->valueLength == 16 ) ? \
									CRYPT_CERTINFO_FINGERPRINT_MD5 : \
									CRYPT_CERTINFO_FINGERPRINT_SHA );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *iCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	if( !isServer && algorithm != handshakeInfo->authAlgo )
		{
		krnlSendNotifier( *iCertChain, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
				"%s key algorithm %d doesn't match negotiated algorithm %d", 
				peerTypeName, algorithm, handshakeInfo->authAlgo );
		}

	/* Either compare the cert fingerprint to a supplied one or save it for 
	   the caller to examine */
	if( fingerprintPtr != NULL )
		{
		/* The caller has supplied a cert fingerprint, compare it to the
		   received cert's fingerprint to make sure that we're talking to 
		   the right system */
		if( fingerprintPtr->valueLength != msgData.length || \
			memcmp( fingerprintPtr->value, certFingerprint, msgData.length ) )
			{
			krnlSendNotifier( *iCertChain, IMESSAGE_DECREFCOUNT );
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"%s key didn't match key fingerprint", peerTypeName );
			}
		}
	else
		/* Remember the cert fingerprint in case the caller wants to check 
		   it.  We don't worry if the add fails, it's a minor thing and not
		   worth aborting the handshake for */
		addSessionAttribute( &sessionInfoPtr->attributeList,
							 CRYPT_SESSINFO_SERVER_FINGERPRINT, 
							 certFingerprint, msgData.length );

	/* Make sure that we can perform the required operation using the key 
	   that we've been given.  For a client key we need signing capability,
	   for a server key using DH key agreement we also need signing 
	   capability to authenticate the DH parameters, and for a server key
	   using RSA key transport we need encryption capability.  This 
	   operation also performs a variety of additional checks alongside the 
	   obvious one, so it's a good general health check before we go any 
	   further */
	status = krnlSendMessage( *iCertChain, IMESSAGE_CHECK, NULL,
							  isServer || isKeyxAlgo( algorithm ) ? \
								MESSAGE_CHECK_PKC_SIGCHECK : \
								MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *iCertChain, IMESSAGE_DECREFCOUNT );
		retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
				"%s provided a key incapable of being used for %s",
				peerTypeName, 
				isServer ? "client authentication" : \
				isKeyxAlgo( algorithm ) ? "key exchange authentication" : \
										  "key transport" );
		}

	return( CRYPT_OK );
	}

int writeSSLCertChain( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	int packetOffset, certListOffset, certListEndPos, status;

	packetOffset = continueHSPacketStream( stream, SSL_HAND_CERTIFICATE );
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		/* If there's no private key available, write an empty cert chain */
		writeUint24( stream, 0 );
		return( completeHSPacketStream( stream, packetOffset ) );
		}
	
	/* Write a dummy length and export the cert list to the stream */
	writeUint24( stream, 0 );
	certListOffset = stell( stream );
	status = exportCertToStream( stream, sessionInfoPtr->privateKey, 
								 CRYPT_ICERTFORMAT_SSL_CERTCHAIN );
	if( cryptStatusError( status ) )
		return( status );
	certListEndPos = stell( stream );

	/* Go back and insert the length, then wrap up the packet */
	sseek( stream, certListOffset - LENGTH_SIZE );
	writeUint24( stream, certListEndPos - certListOffset );
	sseek( stream, certListEndPos );
	return( completeHSPacketStream( stream, packetOffset ) );
	}

/****************************************************************************
*																			*
*								Shared Connect Functions					*
*																			*
****************************************************************************/

/* Pre-encoded finished message templates that we can hash when we're 
   creating our own finished message */

#define FINISHED_TEMPLATE_SIZE				4

static const FAR_BSS SSL_MESSAGE_TEMPLATE finishedTemplate[] = {
	/*	byte		ID = SSL_HAND_FINISHED
		uint24		len = 16 + 20 (SSL), 12 (TLS) */
	{ SSL_HAND_FINISHED, 0, 0, MD5MAC_SIZE + SHA1MAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	};

/* Read/write the handshake completion data (change cipherspec + finised) */

static int readHandshakeCompletionData( SESSION_INFO *sessionInfoPtr,
										const BYTE *hashValues )
	{
	STREAM stream;
	BYTE macBuffer[ MD5MAC_SIZE + SHA1MAC_SIZE + 8 ];
	const int macValueLength = \
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					MD5MAC_SIZE + SHA1MAC_SIZE : TLS_HASHEDMAC_SIZE;
	int length, value, status;

	/* Process the other side's change cipher spec:

		byte		type = SSL_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1 */
	status = length = readPacketSSL( sessionInfoPtr, NULL,
									 SSL_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	value = sgetc( &stream );
	sMemDisconnect( &stream );
	if( value != 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid change cipher spec packet payload, expected 0x01, "
				"got 0x%02X", value );

	/* Change cipher spec was the last message not subject to security 
	   encapsulation so we turn on security for the read channel after 
	   seeing it.  In addition if we're using TLS 1.1 explicit IVs the 
	   effective header size changes because of the extra IV data, so we 
	   record the size of the additional IV data and update the receive 
	   buffer start offset to accomodate it */
	sessionInfoPtr->flags |= SESSION_ISSECURE_READ;
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionSSL->ivSize = sessionInfoPtr->cryptBlocksize;
		sessionInfoPtr->receiveBufStartOfs += sessionInfoPtr->cryptBlocksize;
		}

	/* Process the other side's finished.  Since this is the first chance that 
	   we have to test whether our crypto keys are set up correctly, we 
	   report problems with decryption or MAC'ing or a failure to find any 
	   recognisable header as a wrong key rather than a bad data error:

		byte		ID = SSL_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = length = readPacketSSL( sessionInfoPtr, NULL, 
									 SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = unwrapPacketSSL( sessionInfoPtr, &stream, SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		if( status == CRYPT_ERROR_BADDATA || \
			status == CRYPT_ERROR_SIGNATURE )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Decrypted data was corrupt, probably due to incorrect "
					"encryption keys being negotiated during the handshake" );
		return( status );
		}
	status = length = checkHSPacketHeader( sessionInfoPtr, &stream, 
										   SSL_HAND_FINISHED, 
										   macValueLength );
	if( !cryptStatusError( status ) )
		{
		if( length != macValueLength )
			/* A length mis-match can only be an overflow, since an 
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
		else
			status = sread( &stream, macBuffer, macValueLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Invalid handshake finished packet, probably due to "
					"incorrect encryption keys being negotiated during the "
					"handshake" );
		return( status );
		}

	/* Make sure that the dual MAC/hashed MAC of all preceding messages is 
	   valid */
	if( memcmp( hashValues, macBuffer, macValueLength ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
				"Bad MAC for handshake messages, handshake messages were "
				"corrupted/modified" );

	return( CRYPT_OK );
	}

static int writeHandshakeCompletionData( SESSION_INFO *sessionInfoPtr,
										 SSL_HANDSHAKE_INFO *handshakeInfo,
										 const BYTE *hashValues,
										 const BOOLEAN continuedStream )
	{
	STREAM *stream = &handshakeInfo->stream;
	int offset = 0, ccsEndPos, status;

	/* Build the change cipher spec packet:

		byte		type = SSL_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1

	   Since change cipher spec is its own protocol, we use SSL-level packet 
	   encoding rather than handshake protocol-level encoding */
	if( continuedStream )
		offset = continuePacketStreamSSL( stream, sessionInfoPtr, 
										  SSL_MSG_CHANGE_CIPHER_SPEC );
	else
		openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
							 SSL_MSG_CHANGE_CIPHER_SPEC );
	sputc( stream, 1 );
	completePacketStreamSSL( stream, offset );
	ccsEndPos = stell( stream );

	/* Change cipher spec was the last message not subject to security 
	   encapsulation so we turn on security for the write channel after 
	   seeing it.  In addition if we're using TLS 1.1 explicit IVs the 
	   effective header size changes because of the extra IV data, so we 
	   record the size of the additional IV data and update the receive 
	   buffer start offset to accomodate it */
	sessionInfoPtr->flags |= SESSION_ISSECURE_WRITE;
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionSSL->ivSize = sessionInfoPtr->cryptBlocksize;
		sessionInfoPtr->sendBufStartOfs += sessionInfoPtr->cryptBlocksize;
		}

	/* Build the finished packet.  The initiator sends the MAC of the
	   contents of every handshake packet before the finished packet, the
	   responder sends the MAC of the contents of every packet before its own
	   finished packet but including the MAC of the initiator's packet
	   contents:

		byte		ID = SSL_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	continuePacketStreamSSL( stream, sessionInfoPtr, 
							 SSL_MSG_HANDSHAKE );
	offset = continueHSPacketStream( stream, SSL_HAND_FINISHED );
	swrite( stream, hashValues,
			( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
				MD5MAC_SIZE + SHA1MAC_SIZE : TLS_HASHEDMAC_SIZE );
	completeHSPacketStream( stream, offset );
	status = wrapPacketSSL( sessionInfoPtr, stream, ccsEndPos );
	if( cryptStatusOK( status ) )
		status = sendPacketSSL( sessionInfoPtr, stream,
								TRUE );
	sMemDisconnect( stream  );

	return( status );
	}

/* Complete the handshake with the client or server.  The logic gets a bit
   complex here because the roles of the client and server are reversed if
   we're resuming a session:

		Normal					Resumed
	Client		Server		Client		Server
	------		------		------		------
		   <--- ...			Hello  --->
	KeyEx  --->					   <---	Hello
	CCS	   --->					   <--- CCS
	Fin	   --->					   <--- Fin
		   <---	CCS			CCS	   --->
		   <---	Fin			Fin	   --->

   Because of this the handshake-completion step treats the two sides as
   initiator and responder rather than client and server.  The overall flow
   is then:

	dualMAC( initiator );
	if( !initiator )
		read initiator CCS + Fin;
	dualMAC( responder );
	send initiator/responder CCS + Fin;
	if( initiator )
		read responder CCS + Fin; */

static int completeHandshake( SESSION_INFO *sessionInfoPtr,
							  SSL_HANDSHAKE_INFO *handshakeInfo,
							  const BOOLEAN isClient,
							  const BOOLEAN isResumedSession )
	{
	CRYPT_CONTEXT initiatorMD5context, initiatorSHA1context;
	CRYPT_CONTEXT responderMD5context, responderSHA1context;
	BYTE masterSecret[ SSL_SECRET_SIZE + 8 ];
	BYTE keyBlock[ MAX_KEYBLOCK_SIZE + 8 ];
	BYTE initiatorHashes[ CRYPT_MAX_HASHSIZE * 2 ];
	BYTE responderHashes[ CRYPT_MAX_HASHSIZE * 2 ];
	const void *sslInitiatorString, *sslResponderString;
	const void *tlsInitiatorString, *tlsResponderString;
	const BOOLEAN isInitiator = isResumedSession ? !isClient : isClient;
	int status;

	assert( MAX_KEYBLOCK_SIZE >= ( sessionInfoPtr->authBlocksize + \
								   handshakeInfo->cryptKeysize + 
								   sessionInfoPtr->cryptBlocksize ) * 2 );
	assert( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
			handshakeInfo->premasterSecretSize >= SSL_SECRET_SIZE );

	/* Perform the necessary juggling of values for the reversed message
	   flow of resumed sessions */
	if( isResumedSession )
		{
		/* Resumed session, initiator = server, responder = client */
		initiatorMD5context = handshakeInfo->serverMD5context;
		initiatorSHA1context = handshakeInfo->serverSHA1context;
		responderMD5context = handshakeInfo->clientMD5context;
		responderSHA1context = handshakeInfo->clientSHA1context;
		sslInitiatorString = SSL_SENDER_SERVERLABEL;
		sslResponderString = SSL_SENDER_CLIENTLABEL;
		tlsInitiatorString = "server finished";
		tlsResponderString = "client finished";
		}
	else
		{
		/* Normal session, initiator = client, responder = server */
		initiatorMD5context = handshakeInfo->clientMD5context;
		initiatorSHA1context = handshakeInfo->clientSHA1context;
		responderMD5context = handshakeInfo->serverMD5context;
		responderSHA1context = handshakeInfo->serverSHA1context;
		sslInitiatorString = SSL_SENDER_CLIENTLABEL;
		sslResponderString = SSL_SENDER_SERVERLABEL;
		tlsInitiatorString = "client finished";
		tlsResponderString = "server finished";
		}

	/* Create the security contexts required for the session */
	status = initSecurityContextsSSL( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the premaster secret into the master secret */
	if( !isResumedSession )
		{
		status = premasterToMaster( sessionInfoPtr, handshakeInfo, 
									masterSecret, SSL_SECRET_SIZE );
		if( cryptStatusError( status ) )
			return( status );

		/* Everything is OK so far, add the master secret to the session
		   cache */
		sessionInfoPtr->sessionSSL->sessionCacheID = \
					addSessionCacheEntry( handshakeInfo->sessionID, 
										  handshakeInfo->sessionIDlength, 
										  masterSecret, SSL_SECRET_SIZE, 
										  FALSE );
		}
	else
		/* We've already got the master secret present from the session that 
		   we're resuming from, reuse that */
		memcpy( masterSecret, handshakeInfo->premasterSecret,
				handshakeInfo->premasterSecretSize );

	/* Convert the master secret into keying material.  Unfortunately we
	   can't delete it yet because it's still needed to calculate the MAC 
	   for the handshake messages */
	status = masterToKeys( sessionInfoPtr, handshakeInfo, masterSecret, 
						   SSL_SECRET_SIZE, keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Load the keys and secrets */
	status = loadKeys( sessionInfoPtr, handshakeInfo, isClient, keyBlock );
	zeroise( keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Complete the dual-MAC hashing of the initiator-side messages and, if
	   we're the responder, check that the MACs match the ones supplied by
	   the initiator */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = completeSSLDualMAC( initiatorMD5context, initiatorSHA1context,
									 initiatorHashes, sslInitiatorString,
									 masterSecret );
	else
		status = completeTLSHashedMAC( initiatorMD5context, initiatorSHA1context,
									   initiatorHashes, tlsInitiatorString,
									   masterSecret );
	if( cryptStatusOK( status ) && !isInitiator )
		status = readHandshakeCompletionData( sessionInfoPtr, initiatorHashes );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Now that we have the initiator MACs, complete the dual-MAC hashing of
	   the responder-side messages and destroy the master secret.  We haven't
	   created the full message yet at this point so we manually hash the
	   individual pieces so that we can get rid of the master secret */
	krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
					 ( void * ) finishedTemplate[ sessionInfoPtr->version ],
					 FINISHED_TEMPLATE_SIZE );
	krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
					 ( void * ) finishedTemplate[ sessionInfoPtr->version ],
					 FINISHED_TEMPLATE_SIZE );
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
						 initiatorHashes, MD5MAC_SIZE + SHA1MAC_SIZE );
		krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
						 initiatorHashes, MD5MAC_SIZE + SHA1MAC_SIZE );
		status = completeSSLDualMAC( responderMD5context, responderSHA1context,
									 responderHashes, sslResponderString,
									 masterSecret );
		}
	else
		{
		krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
						 initiatorHashes, TLS_HASHEDMAC_SIZE );
		krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
						 initiatorHashes, TLS_HASHEDMAC_SIZE );
		status = completeTLSHashedMAC( responderMD5context, responderSHA1context,
									   responderHashes, tlsResponderString,
									   masterSecret );
		}
	zeroise( masterSecret, SSL_SECRET_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Send our MACs to the other side and read back their response if 
	   necessary */
	status = writeHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
										   isInitiator ? initiatorHashes : \
														 responderHashes,
										   ( isClient && !isResumedSession ) || \
										   ( !isClient && isResumedSession ) );
	if( cryptStatusError( status ) || !isInitiator )
		return( status );
	return( readHandshakeCompletionData( sessionInfoPtr, responderHashes ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Close a previously-opened SSL session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	sendCloseAlert( sessionInfoPtr, FALSE );
	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Connect to an SSL server/client */

static int abortStartup( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN cleanupSecurityContexts,
						 const int status )
	{
	sendHandshakeFailAlert( sessionInfoPtr );
	if( cleanupSecurityContexts )
		destroySecurityContextsSSL( sessionInfoPtr );
	if( handshakeInfo != NULL )
		destroyHandshakeInfo( handshakeInfo );
	sNetDisconnect( &sessionInfoPtr->stream );
	return( status );
	}

static int commonStartup( SESSION_INFO *sessionInfoPtr,
						  const BOOLEAN isServer )
	{
	SSL_HANDSHAKE_INFO handshakeInfo;
	BOOLEAN resumedSession = FALSE;
	int status;

	/* Initialise the handshake info and begin the handshake */
	status = initHandshakeInfo( sessionInfoPtr, &handshakeInfo, isServer );
	if( cryptStatusOK( status ) )
		status = handshakeInfo.beginHandshake( sessionInfoPtr, 
											   &handshakeInfo );
	if( status == OK_SPECIAL )
		resumedSession = TRUE;
	else
		if( cryptStatusError( status ) )
			return( abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
								  status ) );

	/* Exchange keys with the server */
	if( !resumedSession )
		{
		status = handshakeInfo.exchangeKeys( sessionInfoPtr, 
											 &handshakeInfo );
		if( cryptStatusError( status ) )
			return( abortStartup( sessionInfoPtr, &handshakeInfo, TRUE, 
								  status ) );
		}

	/* Complete the handshake */
	status = completeHandshake( sessionInfoPtr, &handshakeInfo, !isServer, 
								resumedSession );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		return( abortStartup( sessionInfoPtr, NULL, TRUE, status ) );

	return( CRYPT_OK );
	}

static int clientStartup( SESSION_INFO *sessionInfoPtr )
	{
	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, FALSE ) );
	}

static int serverStartup( SESSION_INFO *sessionInfoPtr )
	{
#if 0	/* Old PSK mechanism */
	/* Clear any user name/password information that may be present from
	   a previous session or from the manual addition of keys to the session
	   cache */
	resetSessionAttribute( sessionInfoPtr->attributeList, 
						   CRYPT_SESSINFO_USERNAME );
	resetSessionAttribute( sessionInfoPtr->attributeList, 
						   CRYPT_SESSINFO_PASSWORD );
#endif /* 0 */

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, TRUE ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

static int getAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 void *data, const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *certPtr = ( CRYPT_CERTIFICATE * ) data;
	CRYPT_CERTIFICATE iCryptCert = \
		( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
		sessionInfoPtr->iKeyexAuthContext : sessionInfoPtr->iKeyexCryptContext;

	assert( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a client/server cert there's nothing to return */
	if( iCryptCert == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( iCryptCert, IMESSAGE_INCREFCOUNT );
	*certPtr = iCryptCert;
	return( CRYPT_OK );
	}

#if 0	/* Old PSK mechanism */

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	BYTE premasterSecret[ ( UINT16_SIZE + CRYPT_MAX_TEXTSIZE ) * 2 + 8 ];
	BYTE sessionID[ SESSIONID_SIZE + 8 ];
	int uniqueID, premasterSecretLength, status;

	assert( type == CRYPT_SESSINFO_USERNAME || \
			type == CRYPT_SESSINFO_PASSWORD );

	/* At the moment only the server maintains a true session cache, so if 
	   it's a client session we return without any further checking, there
	   can never be a duplicate entry in this case */
	if( !( sessionInfoPtr->flags & SESSION_ISSERVER ) )
		return( CRYPT_OK );

	/* If we're setting the password, we have to have a session ID present to
	   set it for */
	if( type == CRYPT_SESSINFO_PASSWORD && userNamePtr == NULL )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Wait for any async network driver binding to complete.  This is 
	   required because the session cache is initialised as part of the 
	   asynchronous startup (since it's tied to the session object class
	   rather than a particular session object), so we have to wait until 
	   this has completed before we can access it */
	krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Format the session ID in the appropriate manner and check whether it's
	   present in the cache */
	memset( sessionID, 0, SESSIONID_SIZE );
	memcpy( sessionID, userNamePtr->value, 
			min( userNamePtr->valueLength, SESSIONID_SIZE ) );
	uniqueID = findSessionCacheEntryID( sessionID, SESSIONID_SIZE );

	/* If we're adding or deleting a user name, check whether something
	   identified by the name is present in the cache */
	if( type == CRYPT_SESSINFO_USERNAME )
		{
		if( data != NULL )
			{
			/* User name add, presence is an error */
			if( uniqueID )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			}
		else
			{
			/* User name delete, absence is an error */
			if( !uniqueID )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			deleteSessionCacheEntry( uniqueID );
			}
		return( CRYPT_OK );
		}

	/* Create the premaster secret from the user-supplied password */
	status = createSharedPremasterSecret( premasterSecret, 
										  &premasterSecretLength, 
										  sessionInfoPtr );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't create SSL master secret from shared "
				"secret/password value" );

	/* Add the entry to the session cache */
	addSessionCacheEntry( sessionID, SESSIONID_SIZE, premasterSecret, 
						  premasterSecretLength, TRUE );
	zeroise( premasterSecret, SSL_SECRET_SIZE );
	return( CRYPT_OK );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read/write data over the SSL link */

static int readHeaderFunction( SESSION_INFO *sessionInfoPtr, 
							   READSTATE_INFO *readInfo )
	{
	STREAM stream;
	const BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
						 sessionInfoPtr->receiveBufEnd;
	int length, status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Read the SSL packet header data */
	status = length = readFixedHeader( sessionInfoPtr, 
									   sessionInfoPtr->receiveBufStartOfs );
	if( status <= 0 )
		return( status );
	assert( status == sessionInfoPtr->receiveBufStartOfs );

	/* Since data errors are always fatal, we make all errors fatal until 
	   we've finished handling the header */
	*readInfo = READINFO_FATAL;

	/* Check for an SSL alert message */
	if( bufPtr[ 0 ] == SSL_MSG_ALERT )
		{
		*readInfo = READINFO_FATAL;
		return( processAlert( sessionInfoPtr, bufPtr, length ) );
		}

	/* Process the header data */
	sMemConnect( &stream, bufPtr, length );
	status = length = checkPacketHeaderSSL( sessionInfoPtr, &stream );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Determine how much data we'll be expecting */
	sessionInfoPtr->pendingPacketLength = \
		sessionInfoPtr->pendingPacketRemaining = length;

	/* Indicate that we got the header */
	*readInfo = READINFO_NOOP;
	return( OK_SPECIAL );
	}

static int processBodyFunction( SESSION_INFO *sessionInfoPtr,
								READSTATE_INFO *readInfo )
	{
	STREAM stream;
	int length;

	assert( sessionInfoPtr->pendingPacketLength > 0 );
	assert( sessionInfoPtr->receiveBufPos + \
				sessionInfoPtr->pendingPacketLength <= \
			sessionInfoPtr->receiveBufEnd );
	assert( sessionInfoPtr->receiveBufEnd <= sessionInfoPtr->receiveBufSize );

	/* All errors processing the payload are fatal */
	*readInfo = READINFO_FATAL;

	/* Unwrap the payload */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer + \
						  sessionInfoPtr->receiveBufPos, 
				 sessionInfoPtr->pendingPacketLength );
	length = unwrapPacketSSL( sessionInfoPtr, &stream, 
							  SSL_MSG_APPLICATION_DATA );
	sMemDisconnect( &stream );
	if( cryptStatusError( length ) )
		return( length );

	/* Adjust the data size indicators to account for the stripped padding
	   and MAC info */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos + length;
	sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd;
	sessionInfoPtr->pendingPacketLength = 0;
	assert( sessionInfoPtr->receiveBufEnd <= sessionInfoPtr->receiveBufSize );

	/* If we only got a partial packet, let the caller know that they should 
	   try again */
	if( length < 1 )
		{
		*readInfo = READINFO_PARTIAL;
		return( OK_SPECIAL );
		}
	*readInfo = READINFO_NONE;
	return( length );
	}

static int preparePacketFunction( SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( sessionInfoPtr->sendBufPos - \
			sessionInfoPtr->sendBufStartOfs > 0 && \
			sessionInfoPtr->sendBufPos - \
			sessionInfoPtr->sendBufStartOfs <= MAX_PACKET_SIZE );
	assert( !( sessionInfoPtr->flags & SESSION_SENDCLOSED ) );
	assert( !( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT ) );

	/* Wrap up the payload ready for sending.  Since this is wrapping in-
	   place data we first open a write stream to add the header, then open 
	   a read stream covering the full buffer in preparation for wrapping 
	   the packet.  Note that we connect the stream to the full send buffer
	   (bufSize) even though we only advance the current stream position to 
	   the end of the stream contents (bufPos), since the packet-wrapping 
	   process adds further data to the stream that exceeds the current 
	   stream position */
	openPacketStreamSSL( &stream, sessionInfoPtr, 0, 
						 SSL_MSG_APPLICATION_DATA );
	sMemDisconnect( &stream );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer, 
				 sessionInfoPtr->sendBufSize );
	sSkip( &stream, sessionInfoPtr->sendBufPos );
	status = wrapPacketSSL( sessionInfoPtr, &stream, 0 );
	if( cryptStatusOK( status ) )
		status = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodSSL( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_NONE,				/* Flags */
		SSL_PORT,					/* SSL port */
		SESSION_NEEDS_PRIVKEYSIGN,	/* Client attributes */
			/* The client private key is optional but if present, it has to 
			   be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYORPASSWORD,
		SSL_MINOR_VERSION_TLS,		/* TLS 1.0 */
			SSL_MINOR_VERSION_SSL, SSL_MINOR_VERSION_TLS11,
			/* We default to TLS 1.0 rather than TLS 1.1 because it's likely
			   that support for the latter will be hit-and-miss for some 
			   time */
		NULL, NULL,					/* Content-type */
	
		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			MAX_PACKET_SIZE,		/* Send/receive buffer size */
		SSL_HEADER_SIZE,			/* Payload data start */
			/* This may be adjusted during the handshake if we're talking 
			   TLS 1.1, which prepends extra data in the form of an IV to
			   the payload */
		MAX_PACKET_SIZE				/* (Default) maximum packet size */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->transactFunction = \
			( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
			serverStartup : clientStartup;
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->readHeaderFunction = readHeaderFunction;
	sessionInfoPtr->processBodyFunction = processBodyFunction;
	sessionInfoPtr->preparePacketFunction = preparePacketFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SSL */
