/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Server Management					*
*					   Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssl.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
  #include "../session/ssl.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Many of the SSL packets have fixed formats, so we can construct them by
   copying in a constant template and setting up the variable fields.  The
   following templates are for various packet types */

#define SERVERHELLODONE_TEMPLATE_SIZE		4
#define SERVERCERTREQUEST_TEMPLATE_SIZE		13

static const FAR_BSS BYTE serverHelloDoneTemplate[] = {
	SSL_HAND_SERVER_HELLODONE,				/* ID */
	0, 0, 0									/* Length */
	};
static const FAR_BSS BYTE serverCertRequestTemplate[] = {
	SSL_HAND_SERVER_CERTREQUEST,			/* ID */
	0, 0, 9,								/* Length */
	2,										/* Cert type length */
	1, 2,									/* RSA, DSA */
	0, 4,									/* CA name list length */
	0, 2,									/* CA name length */
	0x30, 0x00								/* CA name */
	};

/* Choose the best cipher suite from a list of suites */

static int chooseCipherSuite( const BYTE *suitePtr, const int noSuites, 
							  const BOOLEAN isV2 )
	{
	int suite = SSL_NULL_WITH_NULL, i;

	for( i = 0; i < noSuites; i++ )
		{
		int ch, currentSuite;

		/* Get the cipher suite info.  If it's a v2 suite (the high byte is 
		   nonzero), skip it and continue */
		if( isV2 )
			ch = *suitePtr++;
		currentSuite = mgetWord( suitePtr );
		if( isV2 && ch )
			continue;

#if 0	/* When resuming a cached session, the client is required to offer 
		   as one of its suites the original suite that was used.  There is 
		   no good reason for this requirement (it's probable that the spec 
		   is intending that there be at least one cipher suite, and that if 
		   there's only one it should really be the one originally 
		   negotiated), and it complicates implementation of shared-secret 
		   key sessions, so we don't perform this check */
		/* If we have to match a specific suite and this isn't it, 
		   continue */
		if( requiredSuite > 0 && requiredSuite != currentSuite )
			continue;
#endif /* 0 */

		/* Pick out the best suite available.  The order is 3DES, AES, IDEA, 
		   RC4/128, DES */
		switch( currentSuite )
			{
			case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
				if( algoAvailable( CRYPT_ALGO_3DES ) )
					suite = currentSuite;
				break;

			case TLS_RSA_WITH_AES_128_CBC_SHA:
			case TLS_RSA_WITH_AES_256_CBC_SHA:
				if( suite != SSL_RSA_WITH_3DES_EDE_CBC_SHA && \
					algoAvailable( CRYPT_ALGO_AES ) )
					suite = currentSuite;
				break;

			case SSL_RSA_WITH_IDEA_CBC_SHA:
				if( suite != SSL_RSA_WITH_3DES_EDE_CBC_SHA && \
					suite != TLS_RSA_WITH_AES_128_CBC_SHA && \
					suite != TLS_RSA_WITH_AES_256_CBC_SHA && \
					algoAvailable( CRYPT_ALGO_IDEA ) )
					suite = currentSuite;
				break;

			case SSL_RSA_WITH_RC4_128_MD5:
			case SSL_RSA_WITH_RC4_128_SHA:
				if( ( suite == SSL_NULL_WITH_NULL || \
					  suite == SSL_RSA_WITH_DES_CBC_SHA ) && \
					algoAvailable( CRYPT_ALGO_RC4 ) )
					suite = currentSuite;
				break;

			case SSL_RSA_WITH_DES_CBC_SHA:
				if( suite == SSL_NULL_WITH_NULL && \
					algoAvailable( CRYPT_ALGO_DES ) )
					suite = currentSuite;
				break;
			}
		}

	return( suite );
	}

/* Process TLS extensions */

static int processExtensions( SESSION_INFO *sessionInfoPtr, 
							  const BYTE *extListPtr, const int extListLen )
	{
	int length = extListLen;

	/* Process the extensions */
	while( length > ID_SIZE + UINT16_SIZE )
		{
		int type, extLen, value;

		/* Get the next extension */
		type = *extListPtr++;
		extLen = mgetWord( extListPtr );
		if( length < ID_SIZE + UINT16_SIZE + extLen || extLen < 1 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid TLS extension length %d, total length %d", 
					extLen, length );
		length -= ID_SIZE + UINT16_SIZE;

		/* Process the extension data.  The internal structure of some of 
		   these things shows that they were created by ASN.1 people... */
		switch( type )
			{
			case TLS_EXT_SERVER_NAME:
				{
				int listLen;

				/* Response: Send zero-length reply to client */
				listLen = mgetWord( extListPtr );
				if( extLen != listLen + UINT16_SIZE )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid host name TLS extension data "
							"length %d", listLen );
				/* Parsing of further SEQUENCE OF SEQUENCE data omitted */
				break;
				}

			case TLS_EXT_MAX_FRAGMENT_LENTH:
				/* Response: If frag-size == 3 or 4, send same to client */
				value = *extListPtr++;
				if( extLen != 1 || value < 1 || value > 4 )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid fragment length TLS extension data "
							"%02X, length %d", value, extLen );
				break;

			case TLS_EXT_TRUNCATED_HMAC:
				break;

			/* Default: Ignore the extension */
			}

		/* Move on to the next extension */
		extListPtr += extLen;
		length -= extLen;
		}

	/* Make sure that we consumed all of the data */
	if( length != 0 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Extraneous TLS extension data %d bytes", length );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Session Cache							*
*																			*
****************************************************************************/

/* Session cache data and index information */

typedef BYTE SESSIONCACHE_DATA[ SSL_SECRET_SIZE ];
typedef struct {
	/* Identification information: The checksum and hash of the session ID */
	int checkValue;
	BYTE hashValue[ 20 ];

	/* Misc info */
	time_t expiryTime;		/* Time entry expires from the cache */
	int uniqueID;			/* Unique ID for this entry */
	BOOLEAN fixedEntry;		/* Whether entry was added manually */
	} SESSIONCACHE_INDEX;

/* A template used to initialise session cache entries */

static const SESSIONCACHE_INDEX SESSIONCACHE_INDEX_TEMPLATE = \
								{ 0, { 0 }, 0, 0, 0 };

/* The action to perform on the cache */

typedef enum { CACHE_ACTION_NONE, CACHE_ACTION_PRESENCECHECK, 
			   CACHE_ACTION_LOOKUP, CACHE_ACTION_ADD, 
			   CACHE_ACTION_LAST } CACHE_ACTION;

/* Session cache information */

static SESSIONCACHE_INDEX *sessionCacheIndex;
static SESSIONCACHE_DATA *sessionCacheData;
static int sessionCacheLastEntry;
static int sesionCacheUniqueID;

/* Hash data */

static void hashData( BYTE *hash, const void *data, const int dataLength )
	{
	static HASHFUNCTION hashFunction = NULL;

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	/* Hash the data */
	hashFunction( NULL, hash, ( BYTE * ) data, dataLength, HASH_ALL );
	}

/* Handle the session cache.  This function currently uses a straightforward 
   linear search with entries clustered towards the start of the cache.  
   Although this may seem somewhat suboptimal, since cryptlib isn't a high-
   performance server the cache will rarely contain more than a handful of 
   entries (if any).  In any case a quick scan through a small number of 
   integers is probably still faster than the complex in-memory database 
   lookup schemes used by many servers, and is also required to handle things 
   like cache LRU management */

static int handleSessionCache( const void *sessionID, 
							   const int sessionIDlength, void *masterKey, 
							   const BOOLEAN isFixedEntry,
							   const CACHE_ACTION cacheAction )
	{
	BYTE hashValue[ 20 ];
	BOOLEAN dataHashed = FALSE;
	const time_t currentTime = getTime();
	time_t oldestTime = currentTime;
	const int checkValue = checksumData( sessionID, sessionIDlength );
	int nextFreeEntry = CRYPT_ERROR, lastUsedEntry = 0, oldestEntry;
	int cachePos, uniqueID = 0, i;

	assert( sessionID != NULL && sessionIDlength >= 8 );
	assert( ( cacheAction == CACHE_ACTION_PRESENCECHECK && masterKey == NULL ) || \
			( cacheAction == CACHE_ACTION_LOOKUP && masterKey != NULL ) || \
			( cacheAction == CACHE_ACTION_ADD && masterKey != NULL ) );
	assert( isWritePtr( sessionCacheIndex, 
						SESSIONCACHE_SIZE * sizeof( SESSIONCACHE_INDEX ) ) );
	assert( isWritePtr( sessionCacheData, 
						SESSIONCACHE_SIZE * sizeof( SESSIONCACHE_DATA ) ) );

	/* If there's something wrong with the time, we can't perform (time-
	   based) cache management */
	if( currentTime < MIN_TIME_VALUE )
		return( 0 );

	enterMutex( MUTEX_SESSIONCACHE );

	for( i = 0; i < sessionCacheLastEntry; i++ )
		{
		SESSIONCACHE_INDEX *sessionCacheInfo = &sessionCacheIndex[ i ];

		/* If this entry has expired, delete it */
		if( sessionCacheInfo->expiryTime < currentTime )
			{
			sessionCacheIndex[ i ] = SESSIONCACHE_INDEX_TEMPLATE;
			zeroise( sessionCacheData[ i ], sizeof( SESSIONCACHE_DATA ) );
			}

		/* Check for a free entry and the oldest non-free entry.  We could
		   perform an early-out once we find a free entry, but this would
		   prevent any following expired entries from being deleted */
		if( sessionCacheInfo->expiryTime <= 0 )
			{
			if( nextFreeEntry == CRYPT_ERROR )
				nextFreeEntry = i;
			continue;
			}
		lastUsedEntry = i;
		if( sessionCacheInfo->expiryTime < oldestTime )
			{
			oldestTime = sessionCacheInfo->expiryTime;
			oldestEntry = i;
			}

		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( sessionCacheInfo->checkValue == checkValue )
			{
			if( !dataHashed )	
				{
				hashData( hashValue, sessionID, sessionIDlength );
				dataHashed = TRUE;
				}
			if( !memcmp( sessionCacheInfo->hashValue, hashValue, 20 ) )
				{
				uniqueID = sessionCacheInfo->uniqueID;

				/* We've found a matching entry in the cache, if we're
				   looking for an existing entry return its data */
				if( cacheAction == CACHE_ACTION_LOOKUP )
					{
					memcpy( masterKey, sessionCacheData[ i ], SSL_SECRET_SIZE );
					sessionCacheInfo->expiryTime = \
										currentTime + SESSIONCACHE_TIMEOUT;
					if( sessionCacheInfo->fixedEntry )
						/* Indicate that this entry corresponds to a fixed 
						   entry that was added manually rather than a true 
						   resumed session */
						uniqueID = -uniqueID;
					}

				exitMutex( MUTEX_SESSIONCACHE );
				return( uniqueID );
				}
			}
		}

	/* If the total number of entries has shrunk due to old entries expiring, 
	   reduce the overall cache size */
	if( lastUsedEntry + 1 < sessionCacheLastEntry )
		sessionCacheLastEntry = lastUsedEntry + 1;

	/* No match found, if we're adding a new entry, add it at the 
	   appropriate location */
	if( cacheAction == CACHE_ACTION_ADD )
		{
		if( !dataHashed )
			hashData( hashValue, sessionID, sessionIDlength );
		cachePos = ( nextFreeEntry != CRYPT_ERROR ) ? nextFreeEntry : \
				   ( sessionCacheLastEntry >= SESSIONCACHE_SIZE ) ? \
				   oldestEntry : sessionCacheLastEntry++;
		sessionCacheIndex[ cachePos ].checkValue = checkValue;
		memcpy( sessionCacheIndex[ cachePos ].hashValue, hashValue, 20 );
		sessionCacheIndex[ cachePos ].expiryTime = \
										currentTime + SESSIONCACHE_TIMEOUT;
		sessionCacheIndex[ cachePos ].uniqueID = uniqueID = \
													sesionCacheUniqueID++;
		sessionCacheIndex[ cachePos ].fixedEntry = isFixedEntry;
		memcpy( sessionCacheData[ cachePos ], masterKey, SSL_SECRET_SIZE );
		}

	exitMutex( MUTEX_SESSIONCACHE );
	return( uniqueID );
	}

/* Add and delete entries to/from the session cache.  These are just wrappers 
   for the local cache-access function, for use by external code */

int findSessionCacheEntryID( const void *sessionID, 
							 const int sessionIDlength )
	{
	return( handleSessionCache( sessionID, sessionIDlength, NULL,
								FALSE, CACHE_ACTION_PRESENCECHECK ) );
	}

static int findSessionCacheEntry( const void *sessionID, 
								  const int sessionIDlength, 
								  void *masterSecret )
	{
	return( handleSessionCache( sessionID, sessionIDlength, masterSecret,
								FALSE, CACHE_ACTION_LOOKUP ) );
	}

int addSessionCacheEntry( const void *sessionID, const int sessionIDlength, 
						  const void *masterSecret, 
						  const BOOLEAN isFixedEntry )
	{
	assert( masterSecret != NULL );

	/* If we're not doing resumes (or the ID is suspiciously short), don't 
	   try and update the session cache */
	if( sessionIDlength < 8 )
		return( 0 );

	/* Add the entry to the cache */
	return( handleSessionCache( sessionID, sessionIDlength,
								( void * ) masterSecret, isFixedEntry,
								CACHE_ACTION_ADD ) );
	}

void deleteSessionCacheEntry( const int uniqueID )
	{
	int i;

	enterMutex( MUTEX_SESSIONCACHE );

	/* Search the cache for the entry with the given ID */
	for( i = 0; i < sessionCacheLastEntry; i++ )
		{
		SESSIONCACHE_INDEX *sessionCacheInfo = &sessionCacheIndex[ i ];

		/* If we've found the entry we're after, clear it and exit */
		if( sessionCacheInfo->uniqueID == uniqueID )
			{
			sessionCacheIndex[ i ] = SESSIONCACHE_INDEX_TEMPLATE;
			zeroise( sessionCacheData[ i ], sizeof( SESSIONCACHE_DATA ) );
			break;
			}
		}
	exitMutex( MUTEX_SESSIONCACHE );
	}

/* Initialise and shut down the session cache */

int initSessionCache( void )
	{
	int i, status;

	enterMutex( MUTEX_SESSIONCACHE );

	/* Initialise the session cache */
	if( ( sessionCacheIndex = clAlloc( "initSessionCache", \
				SESSIONCACHE_SIZE * sizeof( SESSIONCACHE_INDEX ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	status = krnlMemalloc( ( void ** ) &sessionCacheData, 
						   SESSIONCACHE_SIZE * sizeof( SESSIONCACHE_DATA ) );
	if( cryptStatusError( status ) )
		{
		clFree( "initSessionCache", sessionCacheIndex );
		return( status );
		}
	for( i = 0; i < SESSIONCACHE_SIZE; i++ )
		sessionCacheIndex[ i ] = SESSIONCACHE_INDEX_TEMPLATE;
	memset( sessionCacheData, 0, SESSIONCACHE_SIZE * \
								 sizeof( SESSIONCACHE_DATA ) );
	sessionCacheLastEntry = 0;
	sesionCacheUniqueID = 1;

	exitMutex( MUTEX_SESSIONCACHE );
	return( CRYPT_OK );
	}

void endSessionCache( void )
	{
	int i;

	enterMutex( MUTEX_SESSIONCACHE );

	/* Clear and free the session cache */
	krnlMemfree( ( void ** ) &sessionCacheData );
	for( i = 0; i < SESSIONCACHE_SIZE; i++ )
		sessionCacheIndex[ i ] = SESSIONCACHE_INDEX_TEMPLATE;
	clFree( "endSessionCache", sessionCacheIndex );

	exitMutex( MUTEX_SESSIONCACHE );
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
	RESOURCE_DATA msgData;
	BYTE *bufPtr, *lengthPtr;
	const void *sessionIDptr, *suitePtr;
	int length, suiteLength, sessionIDlength, resumedSessionID = 0, status;
	BOOLEAN isV2handshake = FALSE, isExtendedHello = FALSE;

	/* Wait for the hello packet from the client */
	status = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_SPECIAL_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the client hello.  Although this should be a v3 hello, 
	   Netscape always sends a v2 hello (even if SSLv2 is disabled) so we
	   have to process both types.  The v2 type and version have already 
	   been processed in readPacketSSL() since this information, which is 
	   moved into the header in v3, is part of the body in v2.  What's
	   left for the v2 hello is the remainder of the payload, however we
	   need to know the minor version in order to know whether we can use
	   SSL or TLS, so the header-read code inserts this information at the
	   start of the SSLv2 data:

			SSLv2						SSLv3/TLS
		[ byte		minorVersion ]	byte		ID = 1
		uint16		suiteLen		uint24		len
		uint16		sessIDlen		byte[2]		version = { 0x03, 0x0n }
		uint16		nonceLen		uint32		time		| Client nonce
		uint24[]	suites			byte[28]	nonce		|
		byte[]		sessID			byte		sessIDlen	| May receive nonzero len +
		byte[]		nonce			byte[]		sessID		|	<len> bytes data
									uint16		suiteLen
									uint16[]	suites
									byte		coprLen = 1
									byte		copr = 0 */
	bufPtr = sessionInfoPtr->receiveBuffer;
	if( *bufPtr == SSL_HAND_CLIENT_HELLO )
		{
		/* SSLv3/TLS hello */
		length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
									SSL_HAND_CLIENT_HELLO, 
									VERSIONINFO_SIZE + SSL_NONCE_SIZE + 1 + \
										( UINT16_SIZE * 2 ) + 1 + 1, 
									SSL_MAJOR_VERSION );
		if( cryptStatusError( length ) )
			return( length );
		handshakeInfo->clientOfferedVersion = *bufPtr++;
		status = processVersionInfo( sessionInfoPtr, 
									 handshakeInfo->clientOfferedVersion );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( handshakeInfo->clientNonce, bufPtr, SSL_NONCE_SIZE );
		bufPtr += SSL_NONCE_SIZE;
		sessionIDlength = *bufPtr++;
		sessionIDptr = bufPtr;
		if( sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid session ID length %d", sessionIDlength );
		bufPtr += sessionIDlength;
		suiteLength = mgetWord( bufPtr );
		if( suiteLength < 2 || ( suiteLength % 2 ) != 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid handshake cipher suite length %d", 
					suiteLength );
		length -= VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
				  1 + sessionIDlength + UINT16_SIZE + suiteLength + 1 + 1;
		if( length < 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid header data length %d", length );
		suitePtr = bufPtr;
		bufPtr += suiteLength;
		if( *bufPtr++ != 1 || *bufPtr++ )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid compression suite info 0x%02X", 
					bufPtr[ -1 ] );
		if( length > 0 )
			{
			int extListLen;

			/* There's extra data present in the request which (according to
			   RFC 3546's rather optimistic assumptions) should be TLS 
			   extension data.  Make sure that it's valid:

				uint16		extListLen		| RFC 3546
					byte	extType
					uint16	extLen
					byte[]	extData ] */
			if( length < UINT16_SIZE + 1 + UINT16_SIZE )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Client hello contains %d bytes extraneous data",
						length );
			extListLen = mgetWord( bufPtr );
			if( length != UINT16_SIZE + extListLen )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid TLS extension length %d, extension list "
						"length %d", length, extListLen );
			isExtendedHello = TRUE;
			status = processExtensions( sessionInfoPtr, bufPtr, extListLen );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	else
		{
		int nonceLength;

		/* SSLv2 hello with SSLv3/TLS contents */
		assert( *bufPtr & 0x80 );

		/* Extract the minor version information that was inserted by the
		   header-read code.  We also need to reset the high bit, which was
		   set to ensure that the version doesn't get confused with a 
		   standard SSL packet type */
		handshakeInfo->clientOfferedVersion = *bufPtr++ & 0x7F;
		status = processVersionInfo( sessionInfoPtr, 
									 handshakeInfo->clientOfferedVersion );
		if( cryptStatusError( status ) )
			return( status );

		/* SSLv2 hello from Netscape */
		isV2handshake = TRUE;
		suiteLength = mgetWord( bufPtr );
		sessionIDlength = mgetWord( bufPtr );
		nonceLength = mgetWord( bufPtr );
		if( suiteLength < 3 || ( suiteLength % 3 ) != 0 || \
			sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE || \
			nonceLength < 16 || nonceLength > SSL_NONCE_SIZE || \
			( 3 * UINT16_SIZE ) + suiteLength + sessionIDlength + \
				nonceLength > sessionInfoPtr->receiveBufEnd )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid SSLv2 handshake info, suite length %d, session "
					"ID length %d, nonce length %d", suiteLength, 
					sessionIDlength, nonceLength );
		suitePtr = bufPtr;
		bufPtr += suiteLength;
		sessionIDptr = bufPtr;
		bufPtr += sessionIDlength;
		memcpy( handshakeInfo->clientNonce + SSL_NONCE_SIZE - nonceLength, 
				bufPtr, nonceLength );
		}
	if( sessionIDlength == SESSIONID_SIZE )
		{
		/* There's a resumed session ID present and it's of the right size to
		   have come from a cryptlib server, remember it for later */
		memcpy( handshakeInfo->sessionID, sessionIDptr, sessionIDlength );
		handshakeInfo->sessionIDlength = sessionIDlength;

		/* Check whether this session is cached */
		resumedSessionID = findSessionCacheEntry( handshakeInfo->sessionID, 
											handshakeInfo->sessionIDlength,
											handshakeInfo->premasterSecret );
		}
	if( resumedSessionID )
		{
		/* It's a resumed session, if it's a fixed entry that was added 
		   manually store the session ID as the user name */
		if( resumedSessionID < 0 )
			{
			length = handshakeInfo->sessionIDlength;

			memcpy( sessionInfoPtr->userName, handshakeInfo->sessionID, 
					handshakeInfo->sessionIDlength );
			while( length > 0 && !sessionInfoPtr->userName[ length - 1 ] )
				length--;	/* Strip zero-padding */
			sessionInfoPtr->userNameLength = length;
			resumedSessionID = -resumedSessionID;	/* Fix ID polarity */
			}
		}
	else
		{
		/* It's a new session or the session data has expired from the cache,
		   generate a new session ID */
		setMessageData( &msgData, handshakeInfo->sessionID, SESSIONID_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->sessionIDlength = SESSIONID_SIZE;
		}
	handshakeInfo->cipherSuite = chooseCipherSuite( suitePtr, 
									suiteLength / ( isV2handshake ? 3 : 2 ), 
									isV2handshake );
	if( handshakeInfo->cipherSuite == SSL_NULL_WITH_NULL )
		retExt( sessionInfoPtr, CRYPT_ERROR_NOTAVAIL,
				"No crypto algorithm compatible with the remote system "
				"could be found" );
	status = initCiphersuiteInfo( sessionInfoPtr, handshakeInfo, 
								  handshakeInfo->cipherSuite );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the server hello, cert, optional cert request, and done packets:

		byte		ID = 2
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Server nonce
		byte[28]	nonce			|
		byte		sessIDlen
		byte[]		sessID
		uint16		suite
		byte		copr = 0
		... */
	setMessageData( &msgData, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr = sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs;
	*bufPtr++ = SSL_HAND_SERVER_HELLO;
	*bufPtr++ = 0;
	lengthPtr = bufPtr;		/* Low 16 bits of length */
	bufPtr += LENGTH_SIZE - 1;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = sessionInfoPtr->version;
	memcpy( bufPtr, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	bufPtr += SSL_NONCE_SIZE;
	*bufPtr++ = handshakeInfo->sessionIDlength;
	memcpy( bufPtr, handshakeInfo->sessionID, 
			handshakeInfo->sessionIDlength );
	bufPtr += handshakeInfo->sessionIDlength;
	mputWord( bufPtr, handshakeInfo->cipherSuite ); 
	*bufPtr++ = 0;			/* No compression */
	if( isExtendedHello )
		{
#if 0	/* TLS extension code.  Since no known clients/servers (except maybe 
		   some obscure bits of code embedded in cellphones) do this, we'll 
		   have to wait for something that implements it to come along so we 
		   can send back the appropriate response.  The RFC makes the rather 
		   optimistic assumption that implementations can handle the presence 
		   of unexpected data at the end of the hello packet, since  this is 
		   rarely the case we leave the following disabled by default so as 
		   not to confuse clients that leave some garbage at the end of their
		   client hello and suddenly get back an extension response from the
		   server */
		mputWord( bufPtr, ID_SIZE + UINT16_SIZE + 1 );
		*bufPtr++ = TLS_EXT_MAX_FRAGMENT_LENTH;
		mputWord( bufPtr, 1 );
		*bufPtr++ = 3;
#endif /* 0 */
		}
	length = bufPtr - \
			 ( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs );
	mputWord( lengthPtr, length - ( ID_SIZE + LENGTH_SIZE ) );

	/* If it's not a resumed session, write the server and optional client 
	   cert information and server hello done */
	if( !resumedSessionID )
		{
		/*	...
			(server cert chain)
			... */
		status = writeSSLCertChain( sessionInfoPtr, bufPtr );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += status;

		/*	...			( optional client cert request)
			byte		ID = 0x0D
			uint24		len = 7
			byte		certTypeLen = 2
			byte[2]		certType = { 0x01, 0x02 }
			uint16		caNameListLen = 4
			uint16		caNameLen = 2
			byte[]		caName = { 0x30, 0x00 }
			... */
		if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
			{
			memcpy( bufPtr, serverCertRequestTemplate, 
					SERVERCERTREQUEST_TEMPLATE_SIZE );
			bufPtr += SERVERCERTREQUEST_TEMPLATE_SIZE;
			}

		/*	...
			byte		ID = 0x0E
			uint24		len = 0 */
		memcpy( bufPtr, serverHelloDoneTemplate, 
				SERVERHELLODONE_TEMPLATE_SIZE );
		bufPtr += SERVERHELLODONE_TEMPLATE_SIZE;
		}

	/* Send the combined server packets to the client.  We perform the dual 
	   MAC'ing of the client hello in between the network ops where it's 
	   effectively free */
	length = bufPtr - \
			 ( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs );
	wrapHandshakePacket( sessionInfoPtr->sendBuffer, length, 
						 sessionInfoPtr->version );
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					 sessionInfoPtr->sendBufStartOfs + length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, 
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	dualMacData( handshakeInfo, sessionInfoPtr->sendBuffer + \
								sessionInfoPtr->sendBufStartOfs, length );

	return( resumedSessionID ? OK_SPECIAL : CRYPT_OK );
	}

/* Exchange keys with the client */

int exchangeServerKeys( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE *bufPtr;
	int length, status;

	/* Read the response from the client and, if we're expecting a client 
	   cert, make sure that it's present */
	status = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr = sessionInfoPtr->receiveBuffer;
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		RESOURCE_DATA msgData;
		BYTE certID[ KEYID_SIZE ];
		int chainLength;

		/* Make sure that the client has sent us a cert chain */
		length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
									SSL_HAND_CERTIFICATE, 64, 0 );
		if( cryptStatusError( length ) )
			return( length );
		if( length == 0 || length == 3 )
			{
			/* SSLv3 sent an SSL_ALERT_NO_CERTIFICATE alert to indicate that 
			   the client doesn't have a cert, which is handled by the 
			   readPacketSSL() call.  TLS changed this to send an empty cert 
			   packet instead, supposedly because it lead to implementation
			   problems (presumably it's necessary to create a state machine-
			   based implementation to reproduce these problems, whatever 
			   they are).  The spec is ambiguous as to what constitutes an 
			   empty packet, it could be either a packet with a length of 
			   zero or a packet containing a zero-length cert list so we 
			   check for both.  We also fake the error indicators for 
			   consistency with the status obtained from an SSLv3 no-cert 
			   alert */
			sessionInfoPtr->errorCode = SSL_ALERT_NO_CERTIFICATE;
			retExt( sessionInfoPtr, CRYPT_ERROR_PERMISSION,
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
						"Received SSL alert message: No certificate" : \
						"Received TLS alert message: No certificate" );
			}
		chainLength = mgetWord( bufPtr );
		if( chainLength < 64 || LENGTH_SIZE + chainLength != length )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid client cert chain length %d", chainLength );

		/* Import the cert chain.  This isn't a true cert chain (in the sense 
		   of being degenerate PKCS #7 SignedData) but a special-case SSL-
		   encoded cert chain */
		setMessageCreateObjectIndirectInfo( &createInfo, bufPtr, chainLength,
											CRYPT_ICERTTYPE_SSL_CERTCHAIN );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += chainLength;
		sessionInfoPtr->iKeyexAuthContext = createInfo.cryptHandle;

		/* Make sure that the cert is valid for signing data, which the 
		   client will need to do when it authenticates itself */
		status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
								  IMESSAGE_CHECK, NULL, 
								  MESSAGE_CHECK_PKC_SIGCHECK );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_INVALID,
					"Client supplied a certificate that can't be used for "
					"client authentication" );

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
			retExt( sessionInfoPtr, CRYPT_ERROR_INVALID,
					"Client certificate is not trusted for client "
					"authentication" );

		/* Read the next packet(s) if necessary */
		if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
			{
			status = readPacketSSL( sessionInfoPtr, handshakeInfo, 
									SSL_MSG_HANDSHAKE );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr = sessionInfoPtr->receiveBuffer;
			}		
		}

	/* Process the client key exchange packet:

		byte		ID = 0x10
		uint24		len
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random )
	   DH:
		uint16		yLen
		byte[]		y */
	length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
								SSL_HAND_CLIENT_KEYEXCHANGE, 64, 
								CRYPT_UNUSED );
	if( cryptStatusError( length ) )
		return( length );
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
		{
		int innerLength;

		/* The original Netscape SSL implementation didn't provide a length
		   for the encrypted key and everyone copied that so it became the
		   de facto standard way to do it (Sic faciunt omnes.  The spec 
		   itself is ambiguous on the topic).  This was fixed in TLS 
		   (although the spec is still ambigous) so the encoding differs 
		   slightly between SSL and TLS */
		innerLength = mgetWord( bufPtr );
		if( UINT16_SIZE + innerLength != length )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid encrypted key length %d vs.inner length %d",
					length, innerLength );
		length = innerLength;
		}
	if( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
		length > CRYPT_MAX_PKCSIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid encrypted key length %d", length );

	/* Decrypt the encrypted premaster secret and make sure that it looks OK.  
	   Note that the version that we check for at this point is the version 
	   originally offered by the client in its hello message, not the version 
	   eventually negotiated for the connection.  This is designed to prevent 
	   rollback attacks.  In theory we could explicitly defend against 
	   Bleichenbacher-type attacks at this point by setting the premaster 
	   secret to a pseudorandom value if we get a bad data or incorrect 
	   version error and continuing as normal, however the attack depends on 
	   the server returning information required to pinpoint the cause of 
	   the failure and cryptlib just returns a generic "failed" response for 
	   any handshake failure, so this explicit defence isn't really 
	   necessary */
	setMechanismWrapInfo( &mechanismInfo, bufPtr, length, 
						  handshakeInfo->premasterSecret, SSL_SECRET_SIZE, 
						  CRYPT_UNUSED, sessionInfoPtr->privateKey, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT, 
							  &mechanismInfo, MECHANISM_PKCS1_RAW );
	if( cryptStatusOK( status ) && \
		mechanismInfo.keyDataLength != SSL_SECRET_SIZE )
		status = CRYPT_ERROR_BADDATA;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( handshakeInfo->premasterSecret[ 0 ] != SSL_MAJOR_VERSION || \
		handshakeInfo->premasterSecret[ 1 ] != handshakeInfo->clientOfferedVersion )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid premaster secret version data 0x%02X 0x%02X, "
				"expected 0x03 0x%02X",
				handshakeInfo->premasterSecret[ 0 ], 
				handshakeInfo->premasterSecret[ 1 ],
				handshakeInfo->clientOfferedVersion );
	bufPtr += length;

	/* If we're expecting a client cert, process the client cert verify */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		/* Read the next packet if necessary */
		if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
			{
			status = readPacketSSL( sessionInfoPtr, handshakeInfo, 
									SSL_MSG_HANDSHAKE );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr = sessionInfoPtr->receiveBuffer;
			}		

		/* Process the client cert verify packet:

			byte		ID = 0x0F
			uint24		len
			byte[]		signature */
		length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
									SSL_HAND_CLIENT_CERTVERIFY, 64, 
									CRYPT_UNUSED );
		if( cryptStatusError( length ) )
			return( length );
		status = processCertVerify( sessionInfoPtr, handshakeInfo, bufPtr,
									length, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

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
