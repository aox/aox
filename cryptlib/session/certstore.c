/****************************************************************************
*																			*
*					cryptlib HTTP Certstore Session Management				*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/misc_rw.h"
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
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;

	mputWord( bufPtr, errorStatus );
	swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 2 );
	}

/* Read a value from the HTTP GET */

static int readValue( STREAM *stream, char **valuePtrPtr, int *valueLen )
	{
	int status;

	/* Clear return values */
	if( valuePtrPtr != NULL )
		{
		*valuePtrPtr = NULL;
		*valueLen = 0;
		}

	/* Read the { length, data } information */
	status = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( status <= 0 )
		/* If we're not interested in the data then a length of zero (item
		   not present) is OK, otherwise it's an error */
		return( ( valuePtrPtr == NULL ) ? \
				CRYPT_OK : CRYPT_ERROR_UNDERFLOW );
	if( status > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ERROR_OVERFLOW );
	if( valuePtrPtr != NULL )
		{
		char *valuePtr = sMemBufPtr( stream );

		valuePtr[ status ] = '\0';
		*valuePtrPtr = valuePtr;
		*valueLen = status;
		}
	return( sSkip( stream, status ) );
	}

/* Exchange data with an HTTP client */

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	const CERTSTORE_READ_INFO *certstoreInfoPtr;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE buffer[ 128 ];
	char *attrPtr, *valuePtr, valueBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	char firstChar;
	int attrLen, valueLen, length, i, status;

	/* Read the request data from the client.  Note that we do a direct read 
	   rather than using readPkiDatagram() since we're reading an idempotent
	   HTTP GET request and not a PKI datagram submitted via an HTTP POST */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_IDEMPOTENT, NULL, TRUE );
	length = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					sessionInfoPtr->receiveBufSize );
	if( cryptStatusError( length ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( length );
		}

	/* Read the { attribute, value } pair from the HTTP GET:

		word	uriLen
		byte[]	uri
		word	attrLen
		byte[]	attr
		word	valueLen
		byte[]	value */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = readValue( &stream, NULL, NULL );
	if( cryptStatusOK( status ) )
		status = readValue( &stream, &attrPtr, &attrLen );
	if( cryptStatusOK( status ) )
		status = readValue( &stream, &valuePtr, &valueLen );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		/* This shouldn't ever occur since it would mean that the HTTP layer 
		   has sent us invalid data */
		assert( NOTREACHED );
		retExt( sessionInfoPtr, status, "Invalid cert store query data" );
		}
	strcpy( valueBuffer, valuePtr );

	/* Convert the search attribute type into a cryptlib key ID */
	firstChar = toLower( *attrPtr );
	for( i = 0; 
		 certstoreReadInfo[ i ].attrName != NULL && \
		 ( attrLen != certstoreReadInfo[ i ].attrNameLen || \
		   certstoreReadInfo[ i ].attrName[ 0 ] != firstChar || \
		   strCompare( attrPtr, certstoreReadInfo[ i ].attrName, \
					   certstoreReadInfo[ i ].attrNameLen ) ); 
		 i++ );
	certstoreInfoPtr = &certstoreReadInfo[ i ];
	if( certstoreInfoPtr->attrName == NULL )
		{
		sendErrorResponse( sessionInfoPtr, CRYPT_ERROR_BADDATA );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, 
				"Invalid cert store query attribute '%s'", attrPtr );
		}

	/* If the value was base64-encoded in transit, decode it to get the 
	   actual query data */
	if( certstoreInfoPtr->flags & CERTSTORE_FLAG_BASE64 )
		{
		status = base64decode( buffer, 64, valuePtr, valueLen, 
							   CRYPT_CERTFORMAT_NONE );
		if( cryptStatusError( status ) )
			{
			sendErrorResponse( sessionInfoPtr, CRYPT_ERROR_BADDATA );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA, 
					"Invalid base64-encoded query value '%s'", valueBuffer );
			}
		valuePtr = buffer;
		valueLen = status;
		}

	/* Try and fetch the requested cert */
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
				"Warning: Couldn't find certificate for '%s'", valueBuffer );
		}
	memset( sessionInfoPtr->receiveBuffer, 0, 2 );	/* Returned status value */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer + 2,
					sessionInfoPtr->receiveBufSize - 2 );
	status = krnlSendMessage( getkeyInfo.cryptHandle, IMESSAGE_CRT_EXPORT, 
							  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DESTROY );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, status );
		retExt( sessionInfoPtr, status, 
				"Couldn't export requested certificate for '%s'", 
				valueBuffer );
		}

	/* Send the result to the client */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					 msgData.length + 2 );
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
		SESSION_NEEDS_KEYSET |		/* Server flags */
			SESSION_NEEDS_CERTSOURCE,
		1, 1, 1,					/* Version 1 */
		"application/pkix-cert",	/* Client content-type */
		"application/pkix-cert",	/* Server content-type */
	
		/* Protocol-specific information */
		};

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( sessionInfoPtr->flags & SESSION_ISSERVER )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		return( CRYPT_ERROR_NOTAVAIL );

	return( CRYPT_OK );
	}
#endif /* USE_CERTSTORE */
