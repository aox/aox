/****************************************************************************
*																			*
*					cryptlib HTTP Certstore Session Management				*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTSTORE

/* Processing flags for query data */

#define CERTSTORE_FLAG_NONE		0x00		/* No special processing */
#define CERTSTORE_FLAG_BASE64	0x01		/* Data must be base64 */

/* Table mapping a query submitted as an HTTP GET to a cryptlib-internal 
   keyset query.  Note that the first letter must be lowercase for the
   case-insensitive quick match */

typedef struct {
	const char *attrName;					/* Attribute name from HTTP GET */
	const int attrNameLen;					/* Attribute name length */
	const CRYPT_ATTRIBUTE_TYPE attribute;	/* cryptlib attribute ID */
	const int flags;						/* Processing flags */
	} CERTSTORE_READ_INFO;

static const CERTSTORE_READ_INFO certstoreReadInfo[] = {
	{ "certHash", 8, CRYPT_IKEYID_CERTID, CERTSTORE_FLAG_BASE64 },
	{ "name", 4, CRYPT_KEYID_NAME, CERTSTORE_FLAG_NONE },
	{ "uri", 3, CRYPT_KEYID_URI, CERTSTORE_FLAG_NONE },
	{ "email", 5, CRYPT_KEYID_URI, CERTSTORE_FLAG_NONE },
	{ "sHash", 5, CRYPT_IKEYID_ISSUERID, CERTSTORE_FLAG_BASE64 },
	{ "iHash", 5, CRYPT_IKEYID_ISSUERID, CERTSTORE_FLAG_BASE64 },
	{ "iAndSHash", 9, CRYPT_IKEYID_ISSUERANDSERIALNUMBER, CERTSTORE_FLAG_BASE64 },
	{ "sKIDHash", 8, CRYPT_IKEYID_KEYID, CERTSTORE_FLAG_BASE64 },
	{ NULL, CRYPT_KEYID_NONE, CERTSTORE_FLAG_NONE },
	{ NULL, CRYPT_KEYID_NONE, CERTSTORE_FLAG_NONE }
	};

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Send an error response to the client.  This is mapped at the HTTP layer to
   an appropriate HTTP response.  We don't return a status from this since 
   the caller already has an error status available */

static void sendErrorResponse( SESSION_INFO *sessionInfoPtr,	
							   const int errorStatus )
	{
	STREAM stream;
	int length;

	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 8 );
	writeUint16( &stream, errorStatus );
	length = stell( &stream );
	sMemDisconnect( &stream );
	swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, length );
	}

/* Exchange data with an HTTP client */

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	const CERTSTORE_READ_INFO *certstoreInfoPtr = NULL;
	HTTP_URI_INFO queryInfo;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	STREAM stream;
	BYTE buffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	char sanitisedQueryValue[ CRYPT_MAX_TEXTSIZE + 8 ];
	char *valuePtr, firstChar;
	int valueLen, length, i, status;

	/* Read the request data from the client.  We do a direct read rather 
	   than using readPkiDatagram() since we're reading an idempotent HTTP 
	   GET request and not a PKI datagram submitted via an HTTP POST */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_IDEMPOTENT, NULL, TRUE );
	length = sread( &sessionInfoPtr->stream, &queryInfo, 
					sizeof( HTTP_URI_INFO ) );
	if( cryptStatusError( length ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( length );
		}

	/* Save a copy of the query value for use in reporting errors */
	length = min( queryInfo.valueLen, CRYPT_MAX_TEXTSIZE );
	memcpy( sanitisedQueryValue, queryInfo.value, length );
	buffer[ length ] = '\0';
	sanitiseString( sanitisedQueryValue, length );

	/* Convert the search attribute type into a cryptlib key ID */
	firstChar = toLower( queryInfo.attribute[ 0 ] );
	for( i = 0; 
		 certstoreReadInfo[ i ].attrName != NULL && \
			i < FAILSAFE_ARRAYSIZE( certstoreReadInfo, CERTSTORE_READ_INFO ); 
		 i++ )
		{
		if( queryInfo.attributeLen == certstoreReadInfo[ i ].attrNameLen && \
			certstoreReadInfo[ i ].attrName[ 0 ] == firstChar && \
			!strCompare( queryInfo.attribute, \
						 certstoreReadInfo[ i ].attrName, \
						 certstoreReadInfo[ i ].attrNameLen ) )
			{
			certstoreInfoPtr = &certstoreReadInfo[ i ];
			break;
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( certstoreReadInfo, CERTSTORE_READ_INFO ) )
		retIntError();
	if( certstoreInfoPtr == NULL )
		{
		sendErrorResponse( sessionInfoPtr, CRYPT_ERROR_BADDATA );
		length = min( queryInfo.attributeLen, CRYPT_MAX_TEXTSIZE );
		memcpy( buffer, queryInfo.attribute, length );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, 
				"Invalid certificate store query attribute '%s'", 
				sanitiseString( buffer, length ) );
		}

	/* If the value was base64-encoded in transit, decode it to get the 
	   actual query data */
	if( certstoreInfoPtr->flags & CERTSTORE_FLAG_BASE64 )
		{
		length = base64decode( buffer, CRYPT_MAX_TEXTSIZE, queryInfo.value, 
							   queryInfo.valueLen, CRYPT_CERTFORMAT_NONE );
		if( cryptStatusError( length ) )
			{
			sendErrorResponse( sessionInfoPtr, CRYPT_ERROR_BADDATA );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, 
					"Invalid base64-encoded query value '%s'", 
					sanitisedQueryValue );
			}
		valuePtr = buffer;
		valueLen = length;
		}
	else
		{
		/* The value is used as is */
		valuePtr = queryInfo.value;
		valueLen = queryInfo.valueLen;
		}

	/* Try and fetch the requested cert.  Note that this is somewhat 
	   suboptimal since we have to instantiate the cert only to destroy it
	   again immediately afterwards as soon as we've exported the cert data,
	   for a proper high-performance implementation the server would query
	   the cert database directly and send the stored encoded value to the
	   client */
	setMessageKeymgmtInfo( &getkeyInfo, certstoreInfoPtr->attribute, 
						   valuePtr, valueLen, NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		/* Not finding a cert in response to a request isn't a real error so
		   all we do is return a warning to the caller */
		sendErrorResponse( sessionInfoPtr, status );
		retExt( sessionInfoPtr, CRYPT_OK, 
				"Warning: Couldn't find certificate for '%s'", 
				sanitisedQueryValue );
		}

	/* Write the cert to the session buffer, preceded by the status code for
	   the operation.  Since it's a response to an idempotent read, it'll be 
	   mapped by the HTTP layer into the appropriate HTTP response type */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );
	writeUint16( &stream, CRYPT_OK );	/* Returned status value */
	status = exportCertToStream( &stream, getkeyInfo.cryptHandle,
								 CRYPT_CERTFORMAT_CERTIFICATE );
	length = stell( &stream );
	sMemDisconnect( &stream );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DESTROY );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, status );
		retExt( sessionInfoPtr, status, 
				"Couldn't export requested certificate for '%s'", 
				sanitisedQueryValue );
		}

	/* Send the result to the client */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					 length );
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
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodCertstore( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		0,							/* Client flags */
		SESSION_NEEDS_KEYSET,		/* Server flags */
		1, 1, 1,					/* Version 1 */
		"application/pkix-cert",	/* Client content-type */
		"application/pkix-cert",	/* Server content-type */
	
		/* Protocol-specific information */
		};

	/* Set the access method pointers.  The client-side implementation is 
	  just a standard HTTP fetch so there's no explicit certstore client
	  implementation */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( isServer( sessionInfoPtr ) )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		return( CRYPT_ERROR_NOTAVAIL );

	return( CRYPT_OK );
	}
#endif /* USE_CERTSTORE */
